"""[security] kernel_modules: the modules the host loads for a container
workload, since its containers may not make the kernel load one.

On the proving host (2026-10-16) the wireguard-vpn bundle's wg-quick, under
workload-vm.cil's module_request deny, was refused the wireguard module
until the workload named it.
"""
import subprocess
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import kernel_modules
import validation


def _container(**security):
    return {"workload": {"name": "wg"},
            "container": {"image": "example.test/wg"},
            "security": security}


class TestValidation(unittest.TestCase):

    def test_a_list_of_module_names_is_accepted(self):
        self.assertEqual(kernel_modules.validate_kernel_modules(
            _container(kernel_modules=["wireguard", "nft_compat",
                                       "xt-mark"]), "container"), [])

    def test_a_name_modprobe_could_read_as_an_option_is_refused(self):
        for bad in (["--all"], ["_x"], ["wire guard"], ["a/b"], [""],
                    "wireguard", [1]):
            with self.subTest(bad=bad):
                self.assertTrue(kernel_modules.validate_kernel_modules(
                    _container(kernel_modules=bad), "container"))

    def test_a_vm_is_refused(self):
        errors = kernel_modules.validate_kernel_modules(
            {"security": {"kernel_modules": ["wireguard"]}}, "vm")
        self.assertIn("guest", errors[0])

    def test_a_container_of_a_pod_names_them_in_the_top_level(self):
        config = {"containers": [{"name": "vpn",
                                  "security": {"kernel_modules": ["x"]}}]}
        errors = kernel_modules.validate_kernel_modules(config, "container")
        self.assertIn("containers[vpn].security.kernel_modules", errors[0])

    def test_validate_reports_it(self):
        """The wiring: validation runs the check for containers and VMs."""
        errors = validation.validate_workload_config(
            _container(kernel_modules=["wire guard"]))
        self.assertTrue(any("kernel_modules" in e for e in errors))
        vm = {"workload": {"name": "v"},
              "vm": {"cloud_image_url": "https://example.invalid/f.qcow2",
                     "cloud_image_checksum": "sha256:" + "0" * 64,
                     "network": {"egress": "open"}},
              "security": {"kernel_modules": ["wireguard"]}}
        errors = validation.validate_workload_config(vm)
        self.assertTrue(any("kernel_modules" in e for e in errors))


class TestLoading(unittest.TestCase):

    def test_each_module_is_modprobed_in_order(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        kernel_modules.load_kernel_modules(
            _container(kernel_modules=["wireguard", "xt_mark"]), run=run)
        self.assertEqual([c.args[0] for c in run.call_args_list],
                         [["modprobe", "--", "wireguard"],
                          ["modprobe", "--", "xt_mark"]])

    def test_a_failure_names_the_module_and_what_modprobe_said(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 1, "", "modprobe: ERROR: could not insert 'sctp'\n"))
        with self.assertRaises(RuntimeError) as ctx:
            kernel_modules.load_kernel_modules(
                _container(kernel_modules=["sctp", "wireguard"]), run=run)
        self.assertIn("modprobe sctp failed", str(ctx.exception))
        self.assertIn("could not insert", str(ctx.exception))
        self.assertEqual(run.call_count, 1)

    def test_none_named_runs_nothing(self):
        run = mock.Mock()
        kernel_modules.load_kernel_modules(_container(), run=run)
        run.assert_not_called()


class TestTheWireGuardBundles(unittest.TestCase):

    def test_a_bundle_running_wg_quick_names_the_wireguard_module(self):
        """seccomp_netlink = ["generic"] marks a bundle running wg-quick,
        whose `ip link add ... type wireguard` needs the module."""
        workloads = Path(__file__).resolve().parent.parent / "workloads"
        found = 0
        for toml in sorted(workloads.glob("*/workload.toml")):
            security = tomllib.loads(toml.read_text()).get("security", {})
            if "generic" not in security.get("seccomp_netlink", []):
                continue
            found += 1
            with self.subTest(bundle=toml.parent.name):
                self.assertIn("wireguard",
                              security.get("kernel_modules", []))
        self.assertGreaterEqual(found, 5)


if __name__ == "__main__":
    unittest.main()
