"""wayvnc listens on loopback only, reached over ssh.

wayvnc on 0.0.0.0 offers security type None to the LAN unless VNC_PASSWORD
is set, and enable_auth with no RSA-AES key or TLS certificate is refused by
wayvnc 0.9. Loopback and ssh avoid both.
"""
import re
import unittest
from pathlib import Path

WORKLOADS = Path(__file__).resolve().parent.parent / "workloads"

# `wayvnc ADDRESS PORT`; the package name in a dnf line has no address.
INVOCATION = re.compile(r"\bwayvnc\s+([0-9a-fA-F.:]*[.:][0-9a-fA-F.:]*)\s")

# Bundles that start wayvnc, so the scan below cannot pass on finding none.
KNOWN = {"vncdesktop-labwc", "vncdesktop-sway", "vncdesktop-wayfire",
         "sunshine-streaming"}


def invocations():
    found = {}
    for containerfile in WORKLOADS.glob("*/Containerfile*"):
        for address in INVOCATION.findall(containerfile.read_text()):
            found.setdefault(containerfile.parent.name, []).append(address)
    return found


class TestWayvncListensOnLoopback(unittest.TestCase):

    def test_every_wayvnc_listens_on_loopback(self):
        found = invocations()
        self.assertLessEqual(KNOWN, set(found))
        for bundle, addresses in found.items():
            for address in addresses:
                with self.subTest(bundle=bundle):
                    self.assertEqual(address, "127.0.0.1")

    def test_no_bundle_offers_a_password_path(self):
        for path in WORKLOADS.glob("*/*"):
            if path.is_file() and path.suffix in ("", ".toml", ".sh"):
                with self.subTest(path=path.relative_to(WORKLOADS)):
                    self.assertNotIn("VNC_PASSWORD", path.read_text())


if __name__ == "__main__":
    unittest.main()
