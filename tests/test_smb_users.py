#!/usr/bin/env python3
"""smb-server's named users: exactly the ones the instance lists.

Audit L19 item 4d (2026-10-17): the `agentic` handoff share was guest and
writable from the whole LAN. The smb-server bundle was guest-only, so a
share for two named users (one writes, one reads) needed users the
instance could name, with passwords from secrets.

`smb-users` runs here against stand-ins for getent, useradd, pdbedit and
smbpasswd that keep their state in files; the real tools ran in the
image on the proving host.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import REPO_ROOT

BUNDLE = REPO_ROOT / "workloads" / "smb-server"
SCRIPT = BUNDLE / "smb-users"
MARK = "smb-server user"

STUBS = {
    "getent": r'''#!/bin/bash
grep "^$2:" "$STUB/passwd" || exit 2
''',
    "useradd": r'''#!/bin/bash
echo "useradd $*" >> "$STUB/log"
comment=""; shell=""
while [ $# -gt 1 ]; do
    case "$1" in
        --comment) comment=$2; shift 2 ;;
        --shell) shell=$2; shift 2 ;;
        *) shift ;;
    esac
done
echo "$1:x:990:990:$comment:/:$shell" >> "$STUB/passwd"
''',
    "pdbedit": r'''#!/bin/bash
echo "pdbedit $*" >> "$STUB/log"
if [ "$1" = -L ]; then
    sed 's/$/:990:/' "$STUB/passdb"
elif [ "$1" = -x ]; then
    sed -i "/^$3\$/d" "$STUB/passdb"
fi
''',
    "smbpasswd": r'''#!/bin/bash
echo "smbpasswd $*" >> "$STUB/log"
user=${!#}
cat > "$STUB/stdin-$user"
grep -qx "$user" "$STUB/passdb" || echo "$user" >> "$STUB/passdb"
''',
}


class TestSmbUsers(unittest.TestCase):

    def setUp(self):
        self.stub = Path(self.enterContext(tempfile.TemporaryDirectory()))
        bin_dir = self.stub / "bin"
        bin_dir.mkdir()
        for name, body in STUBS.items():
            path = bin_dir / name
            path.write_text(body)
            path.chmod(0o755)
        (self.stub / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n")
        (self.stub / "passdb").write_text("")
        (self.stub / "log").write_text("")

    def _run(self, users=None, **passwords):
        env = {"PATH": f"{self.stub / 'bin'}:/usr/bin:/bin",
               "STUB": str(self.stub)}
        if users is not None:
            env["SMB_USERS"] = users
        env.update(passwords)
        return subprocess.run([str(SCRIPT)], env=env, capture_output=True,
                              text=True, timeout=30)

    def _passwd(self):
        rows = (self.stub / "passwd").read_text().splitlines()
        return {row.split(":")[0]: row.split(":") for row in rows}

    def _passdb(self):
        return (self.stub / "passdb").read_text().split()

    def _log(self):
        return (self.stub / "log").read_text()

    def test_no_users_changes_nothing(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("useradd", self._log())
        self.assertNotIn("smbpasswd", self._log())

    def test_each_listed_user_gets_an_account_and_a_password(self):
        result = self._run("agentic-aj agentic-review",
                           SMB_PASSWORD_AGENTIC_AJ="pw-aj",
                           SMB_PASSWORD_AGENTIC_REVIEW="pw-review")
        self.assertEqual(result.returncode, 0, result.stderr)
        passwd = self._passwd()
        for user, pw in (("agentic-aj", "pw-aj"),
                         ("agentic-review", "pw-review")):
            with self.subTest(user=user):
                self.assertEqual(passwd[user][4], MARK)
                self.assertEqual(passwd[user][6], "/sbin/nologin")
                self.assertEqual(
                    (self.stub / f"stdin-{user}").read_text(),
                    f"{pw}\n{pw}\n")
                self.assertIn(f"smbpasswd -s -a {user}", self._log())
        self.assertNotIn("pw-", self._log())
        self.assertEqual(self._passdb(), ["agentic-aj", "agentic-review"])

    def test_a_restart_sets_the_password_again_without_a_second_account(self):
        self._run("writer", SMB_PASSWORD_WRITER="one")
        result = self._run("writer", SMB_PASSWORD_WRITER="two")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._log().count("useradd"), 1)
        self.assertEqual((self.stub / "stdin-writer").read_text(),
                         "two\ntwo\n")

    def test_a_user_taken_off_the_list_loses_its_password(self):
        self._run("writer reader", SMB_PASSWORD_WRITER="w",
                  SMB_PASSWORD_READER="r")
        result = self._run("writer", SMB_PASSWORD_WRITER="w")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._passdb(), ["writer"])
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._passdb(), [])

    def test_a_missing_password_is_refused_before_any_change(self):
        self._run("writer stale", SMB_PASSWORD_WRITER="w",
                  SMB_PASSWORD_STALE="s")
        before = self._log()
        result = self._run("writer reader", SMB_PASSWORD_WRITER="w")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SMB_PASSWORD_READER", result.stderr)
        self.assertEqual(self._log(), before)
        self.assertEqual(self._passdb(), ["writer", "stale"])

    def test_names_that_are_not_user_names_are_refused(self):
        for name in ("../x", "Writer", "a;b", "-x", "a" * 33):
            with self.subTest(name=name):
                result = self._run(name)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not a valid user name", result.stderr)
                self.assertNotIn("useradd", self._log())

    def test_the_images_own_accounts_are_refused(self):
        result = self._run("root", SMB_PASSWORD_ROOT="p")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image's own", result.stderr)
        self.assertNotIn("smbpasswd", self._log())


class TestSmbUsersWiring(unittest.TestCase):
    """What starts smb-users, and what it leaves for smbd."""

    def test_the_image_installs_it_with_useradd(self):
        text = (BUNDLE / "Containerfile").read_text()
        self.assertIn("COPY --link --chmod=0755 smb-users "
                      "/usr/local/bin/smb-users", text)
        self.assertIn("shadow-utils", text)

    def test_the_entrypoint_runs_it_and_starts_smbd_without_passwords(self):
        text = (BUNDLE / "entrypoint.sh").read_text()
        run = text.index("\n/usr/local/bin/smb-users\n")
        unset = text.index('unset SMB_USERS "${!SMB_PASSWORD_@}"')
        smbd = text.index("exec smbd")
        self.assertLess(run, unset)
        self.assertLess(unset, smbd)

    def test_the_toml_names_the_variables_the_script_reads(self):
        text = (BUNDLE / "workload.toml").read_text()
        self.assertIn('# SMB_USERS = "writer reader"', text)
        self.assertIn('# SMB_PASSWORD_WRITER = "${SECRET:smb-writer}"', text)


if __name__ == "__main__":
    unittest.main()
