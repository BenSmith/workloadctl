#!/usr/bin/env python3
"""The host drop-ins the RPM ships against what a workload reaches outside
its tree.

The 2026-10-11 security audit found both gaps live. F17: a container line
starting `<0>` was stored as emerg and journald walled it, escape sequences
raw, to a logged-in terminal; the generator now sets SyslogLevelPrefix=no
(tests.test_generator), and journald walls nothing, which also covers the
journal socket some bundles mount. F9: a key a `_wl-` user wrote in its
own home was accepted by the host's sshd (UsePAM skips the locked-password
check) with TCP forwarding; nologin refused only the shell.

Each file is only as good as the spec line that puts it where its daemon
reads it, so the install path and the %files entry are held here too.
"""

import configparser
import fnmatch
import re
import unittest
from pathlib import Path

from tests.test_rpm_files import INSTALL_RE

import workload_lib  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "rpm" / "workloadctl.spec"
JOURNALD = ROOT / "systemd" / "60-workloadctl-journald.conf"
SSHD = ROOT / "security" / "40-workloadctl-sshd.conf"

JOURNALD_DEST = "%{_prefix}/lib/systemd/journald.conf.d/60-workloadctl.conf"
SSHD_DEST = "%{_sysconfdir}/ssh/sshd_config.d/40-workloadctl.conf"


def _spec_parts():
    spec = SPEC.read_text()
    files_start = spec.index("\n%files")
    installs = dict(INSTALL_RE.findall(spec[:files_start]))
    files = spec[files_start:].splitlines()
    return installs, files


class TestJournaldWallsNothing(unittest.TestCase):

    def test_forward_to_wall_is_off(self):
        conf = configparser.ConfigParser()
        conf.read_string(JOURNALD.read_text())
        self.assertEqual(conf.get("Journal", "ForwardToWall"), "no")

    def test_it_lands_where_journald_reads_drop_ins(self):
        installs, files = _spec_parts()
        self.assertEqual(
            installs.get("systemd/60-workloadctl-journald.conf"),
            JOURNALD_DEST)
        self.assertIn(JOURNALD_DEST, files)


class TestSshdRefusesWorkloadUsers(unittest.TestCase):

    def _deny_patterns(self):
        patterns = []
        for line in SSHD.read_text().splitlines():
            m = re.match(r"\s*DenyUsers\s+(.+?)\s*$", line, re.IGNORECASE)
            if m:
                patterns.extend(m.group(1).split())
        return patterns

    def _denied(self, user):
        return any(fnmatch.fnmatchcase(user, p) for p in self._deny_patterns())

    def test_every_workload_user_is_denied(self):
        for name in ("web", "audit-plain", "a", "dns-vpn"):
            user = workload_lib.workload_username(name)
            self.assertTrue(self._denied(user), f"{user} may log in")

    def test_people_and_root_are_not(self):
        for user in ("root", "ben", "admin", "wl-downloads", "wl_web"):
            self.assertFalse(self._denied(user), f"{user} is refused")

    def test_no_key_is_read_from_a_workload_users_home(self):
        # A Match block holds to the end of the drop-in, so it must be the
        # file's last: anything after it would apply to workload users only.
        # Proven on the proving host (2026-10-13): with DenyUsers removed, a
        # key planted in a workload user's home was refused with the block
        # and accepted without it; sshd -T for other users was unchanged.
        lines = [line.strip() for line in SSHD.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        matches = [i for i, line in enumerate(lines)
                   if line.lower().startswith("match ")]
        self.assertEqual(len(matches), 1, lines)
        self.assertEqual(lines[matches[0]].split()[1:], ["User", "_wl-*"])
        block = dict(line.split(None, 1)
                     for line in lines[matches[0] + 1:])
        self.assertEqual(block, {
            "AuthorizedKeysFile": "none",
            "AuthorizedPrincipalsFile": "none",
            "AuthorizedKeysCommand": "none",
        })

    def test_it_lands_where_sshd_includes_drop_ins(self):
        installs, files = _spec_parts()
        self.assertEqual(
            installs.get("security/40-workloadctl-sshd.conf"), SSHD_DEST)
        self.assertIn(f"%config(noreplace) {SSHD_DEST}", files)


if __name__ == "__main__":
    unittest.main()
