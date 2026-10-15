#!/usr/bin/env python3
"""A streaming workload opens the input devices uinput makes, not the host's.

The image gives /dev/uinput and the nodes under /devices/virtual/input to a
`uinput` group; the physical keyboards and mice stay `input`'s. A bundle that
grants /dev/uinput joins `uinput`. One that joined `input` again would read
every key typed at the host (audit F16), and nothing would fail.

The image's half -- the udev rules and the group -- is held by the image's
own suite.
"""
import tomllib
import unittest

from tests import REPO_ROOT

WORKLOADS = REPO_ROOT / "workloads"


def _uinput_bundles():
    for path in sorted(WORKLOADS.glob("*/workload.toml")):
        config = tomllib.loads(path.read_text())
        if "/dev/uinput" in config.get("devices", {}).get("devices", []):
            yield path.parent.name, config


class Bundles(unittest.TestCase):

    def test_there_are_streaming_bundles_to_hold(self):
        self.assertGreaterEqual(len(list(_uinput_bundles())), 2)

    def test_a_uinput_bundle_is_in_uinput_and_not_input(self):
        for name, config in _uinput_bundles():
            groups = config.get("security", {}).get("extra_groups", [])
            with self.subTest(bundle=name):
                self.assertIn("uinput", groups)
                self.assertNotIn("input", groups)


if __name__ == "__main__":
    unittest.main()
