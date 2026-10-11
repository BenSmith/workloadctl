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
SUNSHINE = REPO_ROOT / "workloads" / "sunshine-streaming" / "setup.sh"


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
        env = {
            "PATH": "/usr/bin:/bin",
            "WORKLOAD_NAME": "zzinstance",
            "WORKLOAD_DATA_DIR": str(self.data),
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
        """The keyless branch makes an empty placeholder at the key's path;
        `: >` on a dangling link creates the file it names."""
        (self.data / "homelab-root.key").symlink_to(self.outside / "made")
        result = self._enable()
        self.assertNotEqual(result.returncode, 0)
        self._victim_untouched()


@unittest.skipUnless(shutil.which("openssl") and shutil.which("hostname"),
                     "openssl and hostname are needed to mint a leaf")
class TestSunshineHook(_Hook):

    def setUp(self):
        super().setUp()
        self.ca = self.tmp / "ca"
        self.ca.mkdir()
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self.ca / "ca.key"), "-out",
             str(self.ca / "ca.crt"), "-subj", "/CN=test-ca", "-days", "1"],
            check=True, capture_output=True, timeout=60)
        self.instance = self.tmp / "instance"
        self.instance.mkdir()
        shutil.copy(SUNSHINE.parent / "workload.toml",
                    self.instance / "workload.toml")

    def _mint(self):
        """mint_tls_cert alone: enable also installs a host unit and runs
        systemctl, which a test cannot. The functions are sourced without
        the dispatch at the bottom of the script."""
        env = {
            "PATH": "/usr/bin:/bin",
            "WORKLOAD_NAME": "zzinstance",
            "WORKLOAD_USER": "_wl-zzinstance",
            "WORKLOAD_INSTANCE_DIR": str(self.instance),
            "WORKLOAD_BUNDLE_DIR": str(SUNSHINE.parent),
            "WORKLOAD_DATA_DIR": str(self.data),
            "HOMELAB_CA_CERT": str(self.ca / "ca.crt"),
            "HOMELAB_CA_KEY": str(self.ca / "ca.key"),
        }
        body = SUNSHINE.read_text()
        body = body[:body.rindex('\ncase "${1:-}" in')]
        return subprocess.run(
            ["bash", "-c", body + "\nmint_tls_cert\n"], env=env,
            capture_output=True, text=True, timeout=60)

    def test_control_a_clean_tree_gets_its_leaf(self):
        result = self._mint()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.data / "tls" / "cert.pem").is_file())
        self.assertTrue((self.data / "tls" / "pkey.pem").is_file())

    def test_a_linked_tls_dir_is_refused(self):
        (self.data / "tls").symlink_to(self.outside)
        result = self._mint()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self._victim_untouched()

    def test_linked_outputs_are_neither_written_nor_chmodded(self):
        for name in ("pkey.pem", "cert.pem", "ca.srl"):
            with self.subTest(output=name):
                tls = self.data / "tls"
                shutil.rmtree(tls, ignore_errors=True)
                tls.mkdir()
                (tls / name).symlink_to(self.victim)
                result = self._mint()
                self.assertNotEqual(result.returncode, 0)
                self._victim_untouched()


if __name__ == "__main__":
    unittest.main()
