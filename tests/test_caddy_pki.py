#!/usr/bin/env python3
"""caddy issues from a homelab intermediate and never holds the root's key.

The 2026-10-17 audit (F40) found the homelab root CA's private key mounted
into caddy: whoever ran code as caddy could issue a certificate every
homelab device trusts, for any name. caddy 2.10.2 was then proven on the
proving host to issue from a supplied intermediate with the root's
certificate only, and a nameConstraints intermediate (.local, .internal)
made a leaf for any other name fail at the client. It also showed caddy
never renews a supplied intermediate and serves past its expiry with no
error, which is why setup.sh declares the certificate for doctor.

These run the shipped setup.sh against the shipped workload.toml, so the
key path the toml mounts and the path the snippet names are held together.
"""

import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from tests import REPO_ROOT

BUNDLE = REPO_ROOT / "workloads" / "caddy"
SETUP = BUNDLE / "setup.sh"
KEY_PATH = "/etc/caddy/homelab-intermediate.key"


def _uncomment_secrets(toml: str) -> str:
    """The shipped toml with its commented [secrets] block switched on."""
    start = toml.index("# [secrets]\n")
    end = toml.index("# ]\n", start) + len("# ]\n")
    block = re.sub(r"^# ?", "", toml[start:end], flags=re.M)
    return toml[:start] + block + toml[end:]


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class TestCaddyIntermediate(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.data = self.tmp / "data"
        (self.data / "pki").mkdir(parents=True)
        self.instance = self.tmp / "instance"
        self.instance.mkdir()
        self.shipped = (BUNDLE / "workload.toml").read_text()
        self._toml(self.shipped)

    def _toml(self, text):
        (self.instance / "workload.toml").write_text(text)

    def _cert(self, *days_args):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", str(self.tmp / "ica.key"), "-subj", "/CN=ica",
             "-out", str(self.data / "pki" / "homelab-intermediate.crt"),
             *(days_args or ("-days", "365"))],
            check=True, capture_output=True)

    def _run(self, action="enable"):
        env = {
            "PATH": "/usr/bin:/bin",
            "WORKLOAD_NAME": "zzinstance",
            "WORKLOAD_DATA_DIR": str(self.data),
            "WORKLOAD_INSTANCE_DIR": str(self.instance),
        }
        return subprocess.run([str(SETUP), action], env=env,
                              capture_output=True, text=True, timeout=30)

    def _snippet(self):
        return (self.data / "pki" / "homelab-ca.caddyfile").read_text()

    def test_the_shipped_toml_mounts_no_ca_key(self):
        doc = tomllib.loads(self.shipped)
        volumes = doc["storage"]["volumes"]
        self.assertFalse([v for v in volumes if ".key" in v])
        self.assertIn("./pki:/etc/caddy/pki:ro", volumes)
        self.assertNotIn("secrets", doc)

    def test_the_commented_secret_mounts_the_key_the_snippet_names(self):
        doc = tomllib.loads(_uncomment_secrets(self.shipped))
        self.assertEqual(doc["secrets"]["files"],
                         [{"credential": "homelab-intermediate-key",
                           "path": KEY_PATH}])

    def test_neither_falls_back_to_caddys_own_ca(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("pki {", self._snippet())

    def test_both_issue_from_the_intermediate_with_no_root_key(self):
        self._cert()
        self._toml(_uncomment_secrets(self.shipped))
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        snippet = self._snippet()
        self.assertIn("cert /etc/caddy/pki/homelab-intermediate.crt", snippet)
        self.assertIn(f"key  {KEY_PATH}", snippet)
        self.assertIn("cert /etc/caddy/homelab-root.crt", snippet)
        self.assertNotIn("homelab-root.key", snippet)
        self.assertEqual(len(re.findall(r"^\s*key\s", snippet, re.M)), 1)
        self.assertNotIn("WARNING", result.stderr)

    def test_an_intermediate_near_expiry_warns(self):
        self._cert("-days", "10")
        self._toml(_uncomment_secrets(self.shipped))
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("expires within 30 days", result.stderr)

    def test_half_an_intermediate_is_refused(self):
        # Each half starts from a full pair's snippet, as a re-enable after
        # the certificate or the [secrets] entry went missing would.
        with self.subTest(half="certificate only"):
            self._cert()
            self._toml(_uncomment_secrets(self.shipped))
            self.assertEqual(self._run().returncode, 0)
            self._toml(self.shipped)
            result = self._run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("half a homelab intermediate", result.stderr)
        with self.subTest(half="key only"):
            self._toml(_uncomment_secrets(self.shipped))
            self.assertEqual(self._run().returncode, 0)
            (self.data / "pki" / "homelab-intermediate.crt").unlink()
            result = self._run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("half a homelab intermediate", result.stderr)

    def test_the_root_key_in_the_data_dir_is_refused(self):
        self._cert()
        self._toml(_uncomment_secrets(self.shipped))
        (self.data / "homelab-root.key").write_text("a key\n")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root's private key", result.stderr)

    def test_an_empty_root_key_placeholder_is_not_a_key(self):
        (self.data / "homelab-root.key").write_text("")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_doctor_is_told_of_the_intermediate_only_when_present(self):
        result = self._run("artifacts")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("cert ", result.stdout)
        self._cert()
        result = self._run("artifacts")
        self.assertIn(
            f"cert {self.data / 'pki' / 'homelab-intermediate.crt'}",
            result.stdout)



class TestOnlyCaddyNamesTheRoot(unittest.TestCase):
    """sunshine-streaming's setup.sh signed its web UI's leaf with the root's
    key from caddy's data dir; the leaf went (2026-10-17) so the key could
    leave the host. A bundle naming that path would need it back."""

    def test_no_other_bundle_names_the_roots_key(self):
        for path in sorted(BUNDLE.parent.rglob("*")):
            if not path.is_file() or path.is_relative_to(BUNDLE):
                continue
            with self.subTest(path=str(path.relative_to(BUNDLE.parent))):
                self.assertNotIn(b"homelab-root.key", path.read_bytes())

if __name__ == "__main__":
    unittest.main()
