#!/usr/bin/env python3
"""A streaming workload opens the input devices uinput makes, not the host's.

The image gives /dev/uinput and the nodes under /devices/virtual/input to a
`uinput` group; the physical keyboards and mice stay `input`'s. A bundle that
grants /dev/uinput joins `uinput`. One that joined `input` again would read
every key typed at the host (audit F16), and nothing would fail.

The image half is skipped in a standalone workloadctl checkout.
"""
import re
import tomllib
import unittest

from tests import REPO_ROOT

CONTAINERFILE = REPO_ROOT.parent / "hypervisor.Containerfile"
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


@unittest.skipUnless(CONTAINERFILE.exists(), "image half absent")
class Image(unittest.TestCase):

    def setUp(self):
        self.text = CONTAINERFILE.read_text()

    def _rules(self):
        return re.findall(
            r"printf '([^']*)\\n' \\\s*>>? /usr/lib/udev/rules\.d/"
            r"72-uinput-input\.rules", self.text)

    def test_uinput_and_its_nodes_go_to_the_uinput_group(self):
        rules = self._rules()
        self.assertIn('KERNEL=="uinput", GROUP="uinput", MODE="0660"', rules)
        virtual = [r for r in rules if "/devices/virtual/input/" in r]
        self.assertEqual(len(virtual), 1, rules)
        self.assertIn('SUBSYSTEM=="input"', virtual[0])
        self.assertIn('GROUP="uinput"', virtual[0])

    def test_no_rule_hands_a_node_to_input(self):
        rules = self._rules()
        self.assertTrue(rules)
        self.assertFalse([r for r in rules if 'GROUP="input"' in r])

    def test_the_group_exists(self):
        self.assertRegex(self.text,
                         r"printf 'g uinput - -\\n' > /usr/lib/sysusers\.d/")


if __name__ == "__main__":
    unittest.main()
