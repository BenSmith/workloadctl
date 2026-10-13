#!/usr/bin/env python3
"""kmscon is the image's console.

Enabling kmsconvt@ makes it autovt@'s alias, so logind starts it in place
of getty on every VT it spawns, and on tty1. A Containerfile that stopped
enabling it would build green with getty consoles.

Skipped in a standalone workloadctl checkout, where the image half is absent.
"""
import unittest

from tests import REPO_ROOT

CONTAINERFILE = REPO_ROOT.parent / "hypervisor.Containerfile"


@unittest.skipUnless(CONTAINERFILE.exists(), "image half absent")
class Console(unittest.TestCase):

    def test_kmsconvt_is_enabled(self):
        self.assertRegex(CONTAINERFILE.read_text(),
                         r"\nRUN systemctl enable kmsconvt@\.service\n")


if __name__ == "__main__":
    unittest.main()
