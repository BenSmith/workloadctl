#!/usr/bin/env python3
"""The shipped [host].setup hooks run as root on a data/ tree the workload
user owns, so none of them may write through a link planted there.

Found by the 2026-10-11 security audit (F29): with `data/pki` linked to a
root-owned directory, caddy's `setup.sh enable` wrote its snippet into it,
and sunshine-streaming's wrote its leaf through `data/tls`. Each hook also
ends in a `chmod 0644` that follows a link, which is the sharper half: a
planted `pki/homelab-ca.caddyfile -> /etc/shadow` would have opened the
shadow file to every user.

Each case plants one link at a path the hook writes and checks that what
it points at is left alone; the control runs the same hook on a clean tree
and sees it write.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import REPO_ROOT

CADDY = REPO_ROOT / "workloads" / "caddy" / "setup.sh"


class _Hook(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.data = self.tmp / "data"
        self.data.mkdir()
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.victim = self.outside / "victim"
        self.victim.write_text("root's own file")
        self.victim.chmod(0o600)

    def _victim_untouched(self):
        self.assertEqual(self.victim.read_text(), "root's own file")
        self.assertEqual(stat.S_IMODE(self.victim.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()),
                         ["victim"])


class TestCaddyHook(_Hook):

    def _enable(self):
        instance = self.tmp / "instance"
        instance.mkdir(exist_ok=True)
        shutil.copy(CADDY.parent / "workload.toml", instance)
        env = {
            "PATH": "/usr/bin:/bin",
            "WORKLOAD_NAME": "zzinstance",
            "WORKLOAD_DATA_DIR": str(self.data),
            "WORKLOAD_INSTANCE_DIR": str(instance),
        }
        return subprocess.run([str(CADDY), "enable"], env=env,
                              capture_output=True, text=True, timeout=30)

    def test_control_a_clean_tree_gets_its_snippet(self):
        result = self._enable()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.data / "pki" / "homelab-ca.caddyfile").is_file())

    def test_a_linked_pki_dir_is_refused(self):
        (self.data / "pki").symlink_to(self.outside)
        result = self._enable()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self._victim_untouched()

    def test_a_linked_snippet_is_neither_written_nor_chmodded(self):
        (self.data / "pki").mkdir()
        (self.data / "pki" / "homelab-ca.caddyfile").symlink_to(self.victim)
        result = self._enable()
        self.assertNotEqual(result.returncode, 0)
        self._victim_untouched()

    def test_a_dangling_key_link_is_not_created_through(self):
        (self.data / "homelab-root.key").symlink_to(self.outside / "made")
        result = self._enable()
        self.assertNotEqual(result.returncode, 0)
        self._victim_untouched()

    def test_a_linked_intermediate_certificate_is_refused(self):
        (self.data / "pki").mkdir()
        (self.data / "pki" / "homelab-intermediate.crt").symlink_to(
            self.victim)
        result = self._enable()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self._victim_untouched()


if __name__ == "__main__":
    unittest.main()
