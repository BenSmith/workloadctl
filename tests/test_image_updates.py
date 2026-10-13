#!/usr/bin/env python3
"""The image stages OS updates on bootc's timer and never reboots by itself.

The stock bootc-fetch-apply-updates.service runs `bootc upgrade --apply`,
which reboots the host as soon as an image is staged. The image enables the
timer and replaces ExecStart without --apply; a drop-in that kept the stock
line, or a timer left disabled, would still build green.

Skipped in a standalone workloadctl checkout, where the image half is absent.
"""
import re
import unittest

from tests import REPO_ROOT

GIT_ROOT = REPO_ROOT.parent
CONTAINERFILE = GIT_ROOT / "hypervisor.Containerfile"
DROP_IN = GIT_ROOT / "systemd" / "bootc-stage-only.conf"
TARGET = ("/usr/lib/systemd/system/bootc-fetch-apply-updates.service.d/"
          "50-stage-only.conf")


@unittest.skipUnless(CONTAINERFILE.exists(), "image half absent")
class StageOnly(unittest.TestCase):

    def setUp(self):
        self.containerfile = CONTAINERFILE.read_text().replace("\\\n", " ")
        self.drop_in = DROP_IN.read_text()

    def test_the_drop_in_is_installed_over_the_service(self):
        self.assertRegex(self.containerfile,
                         r"COPY systemd/bootc-stage-only\.conf\s+"
                         + re.escape(TARGET))

    def test_the_timer_is_enabled(self):
        self.assertRegex(self.containerfile,
                         r"systemctl enable bootc-fetch-apply-updates\.timer")

    def test_execstart_is_reset_then_upgrades_without_apply(self):
        lines = [ln.strip() for ln in self.drop_in.splitlines()
                 if ln.strip().startswith("ExecStart=")]
        self.assertEqual(lines[0], "ExecStart=")
        self.assertEqual(len(lines), 2)
        self.assertIn("bootc upgrade", lines[1])
        self.assertNotIn("--apply", lines[1])
        self.assertNotIn("reboot", lines[1])


if __name__ == "__main__":
    unittest.main()
