"""rt-devices is sunshine-streaming's device configuration.

The runtime rung's test_runtime_devices proves on a live host what
sunshine-streaming's devices, groups, seccomp, rlimits and policy add up to,
through rt-devices, a bundle on a plain image that the gate can pull. It
proves nothing about sunshine once the two differ, so these hold them equal.
"""
import tomllib
import unittest

from tests import REPO_ROOT

SUNSHINE = REPO_ROOT / "workloads" / "sunshine-streaming" / "workload.toml"
RT = REPO_ROOT / "tests" / "cli_surface" / "workloads" / "rt-devices.toml"
RUNTIME = REPO_ROOT / "tests" / "cli_surface" / "test_runtime_devices.py"
DEVICE_VOLUMES = ("/run/udev:", "/dev/input:")
SCHEDULING = ("LimitNICE", "LimitRTPRIO")


def load(path):
    return tomllib.loads(path.read_text())


class RtDevicesIsSunshines(unittest.TestCase):

    def setUp(self):
        self.sunshine, self.rt = load(SUNSHINE), load(RT)

    def test_the_devices_and_security_are_sunshines(self):
        self.assertEqual(self.rt["devices"]["devices"],
                         self.sunshine["devices"]["devices"])
        self.assertEqual(self.rt["security"], self.sunshine["security"])

    def test_the_device_volumes_are_sunshines(self):
        def devices(config):
            return sorted(v for v in config["storage"]["volumes"]
                          if v.startswith(DEVICE_VOLUMES))
        self.assertEqual(devices(self.rt), devices(self.sunshine))
        self.assertEqual(len(devices(self.rt)), len(DEVICE_VOLUMES))

    def test_the_scheduling_limits_are_sunshines(self):
        def limits(config):
            directives = config["resources"]["custom_directives"]
            return {k: directives[k] for k in SCHEDULING}
        self.assertEqual(limits(self.rt), limits(self.sunshine))

    def test_the_runtime_test_installs_sunshines_policy(self):
        text = RUNTIME.read_text()
        self.assertIn('"workloads" / "sunshine-streaming" / "policy.cil"', text)
        self.assertIn('policy.cil")', text)

    def test_the_payload_is_the_probe(self):
        self.assertEqual(self.rt["container"]["command"],
                         ["python3", "-c", "PROBE"])
        self.assertIn('rt-devices-probe.py', RUNTIME.read_text())


if __name__ == "__main__":
    unittest.main()
