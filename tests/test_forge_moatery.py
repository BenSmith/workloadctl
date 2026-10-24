"""The Forgejo workflows test against main's moatery, signature checked.

The homelab's images ship main's moatery beside main's workloadctl, from
the forge's RPM registry, so the Forgejo unit suite and dev runtime rung
fetch it from there with forge-moatery-rpm. These run the script against
stand-ins for dnf, rpmkeys and rpm, and read the steps that call it.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import REPO_ROOT

SCRIPT = REPO_ROOT / ".forgejo" / "scripts" / "forge-moatery-rpm"
REPO = "REPO: ${{ github.server_url }}/api/packages/${{ github.repository_owner }}/rpm"

DNF = """#!/bin/bash
for a; do case "$a" in --destdir=*) d=${a#--destdir=} ;; esac; done
mkdir -p "$d"
[ -n "$STUB_EMPTY" ] || echo built > "$d/moatery-1.0-1.noarch.rpm"
"""
RPMKEYS = """#!/bin/bash
for a; do [ "$a" != -K ] || exit "${STUB_REFUSE:-0}"; done
"""


class ForgeMoatery(unittest.TestCase):

    def setUp(self):
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.work)])
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        for name, text in (("dnf", DNF), ("rpmkeys", RPMKEYS),
                           ("rpm", "#!/bin/bash\n")):
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        self.path = f"{bin_dir}:{os.environ['PATH']}"

    def fetch(self, **extra):
        dest = self.work / "moatery.rpm"
        done = subprocess.run(
            [str(SCRIPT), "https://forge.example/rpm", str(dest)],
            env={**os.environ, "PATH": self.path, **extra},
            capture_output=True, text=True)
        return done, dest

    def test_a_signed_rpm_is_installed_at_dest(self):
        done, dest = self.fetch()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(dest.read_text(), "built\n")

    def test_one_the_registry_key_did_not_sign_is_refused(self):
        """`rpmkeys -K` passes an unsigned package on its digests unless
        _pkgverify_level says otherwise."""
        self.assertIn("--define '_pkgverify_level signature' -K",
                      SCRIPT.read_text())
        done, dest = self.fetch(STUB_REFUSE="1")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(dest.exists())

    def test_a_registry_without_moatery_is_refused(self):
        done, dest = self.fetch(STUB_EMPTY="1")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(dest.exists())
        self.assertIn("--setopt=forge.skip_if_unavailable=0", SCRIPT.read_text())

    def test_the_forgejo_unit_suite_and_dev_rung_fetch_it(self):
        for workflow, call in (
                ("test.yml", 'forge-moatery-rpm "$REPO" "$rpm"'),
                ("runtime-dev.yml",
                 'forge-moatery-rpm "$REPO" "$WLRT_MOATERY_RPM"')):
            with self.subTest(workflow=workflow):
                text = (REPO_ROOT / ".forgejo" / "workflows" / workflow).read_text()
                self.assertIn(call, text)
                self.assertIn(REPO, text)
                self.assertNotIn("just moatery-rpm", text)


if __name__ == "__main__":
    unittest.main()
