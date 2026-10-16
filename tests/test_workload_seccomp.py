#!/usr/bin/env python3
"""[security] seccomp_allow, seccomp_netlink and seccomp_32bit: what
validate accepts, and the profile every container of a pod runs under.

The derived profile itself is held to the baseline's checks in
test_seccomp_baseline; the generator's writing of it is in test_generator.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.test_generator import run_generator, write_config
from tests.test_seccomp_baseline import ALLOW, decide
from validation import validate_workload_config
from workload_seccomp import (
    AF_NETLINK, ARCH_X86_64, NETLINK_PROTOCOLS, SUBARCHES_32BIT,
    derived_profile, needs_derived_profile, seccomp_32bit, seccomp_allow,
    seccomp_netlink,
)

SINGLE = {"workload": {"name": "app"}, "container": {"image": "myapp"}}

POD = {
    "workload": {"name": "stack", "mode": "pod"},
    "containers": [
        {"name": "web", "container": {"image": "web"}},
        {"name": "db", "container": {"image": "db"}},
    ],
}

VM = {"workload": {"name": "forge"},
      "vm": {"image": "/var/lib/images/forge.qcow2"}}


def _with(base, **security):
    return dict(base, security=security)


def _seccomp_errors(config):
    return [e for e in validate_workload_config(config)
            if "seccomp_allow" in e]


def _32bit_errors(config):
    return [e for e in validate_workload_config(config)
            if "seccomp_32bit" in e]


def _netlink_errors(config):
    return [e for e in validate_workload_config(config)
            if "seccomp_netlink" in e]


class TestValidate(unittest.TestCase):
    def test_a_list_of_syscall_names_is_accepted(self):
        self.assertEqual(_seccomp_errors(_with(
            SINGLE, seccomp_allow=["ptrace", "process_vm_readv"])), [])
        self.assertEqual(_seccomp_errors(_with(
            POD, seccomp_allow=["ptrace"])), [])

    def test_anything_but_a_list_of_syscall_names_is_refused(self):
        for bad in ("ptrace", ["Ptrace"], ["ptrace;"], [""], [1],
                    ["process vm"]):
            with self.subTest(bad=bad):
                self.assertTrue(_seccomp_errors(_with(
                    SINGLE, seccomp_allow=bad)))

    def test_beside_a_seccomp_profile_of_its_own_it_is_refused(self):
        """The names are added to the baseline, which seccomp= replaces."""
        self.assertTrue(_seccomp_errors(_with(
            SINGLE, seccomp_allow=["ptrace"],
            security_opt=["seccomp=/etc/containers/mine.json"])))
        pod = dict(POD, containers=[
            dict(POD["containers"][0],
                 security={"security_opt": ["seccomp=unconfined"]}),
            POD["containers"][1]])
        self.assertTrue(_seccomp_errors(_with(pod, seccomp_allow=["ptrace"])))

    def test_with_privileged_it_is_refused(self):
        self.assertTrue(_seccomp_errors(_with(
            SINGLE, seccomp_allow=["ptrace"], privileged=True)))

    def test_in_a_containers_own_security_it_is_refused(self):
        """One profile serves the workload; a per-container list would be
        silently ignored."""
        pod = dict(POD, containers=[
            dict(POD["containers"][0],
                 security={"seccomp_allow": ["ptrace"]}),
            POD["containers"][1]])
        self.assertTrue(_seccomp_errors(pod))

    def test_on_a_vm_it_is_refused(self):
        self.assertTrue(_seccomp_errors(_with(VM, seccomp_allow=["ptrace"])))

    def test_the_names_are_sorted_once_each(self):
        self.assertEqual(seccomp_allow(_with(
            SINGLE, seccomp_allow=["ptrace", "keyctl", "ptrace"])),
            ["keyctl", "ptrace"])
        self.assertEqual(seccomp_allow(SINGLE), [])


class TestValidate32bit(unittest.TestCase):
    def test_a_boolean_is_accepted(self):
        self.assertEqual(_32bit_errors(_with(SINGLE, seccomp_32bit=True)), [])
        self.assertEqual(_32bit_errors(_with(SINGLE, seccomp_32bit=False)), [])
        self.assertEqual(_32bit_errors(_with(POD, seccomp_32bit=True)), [])

    def test_anything_but_a_boolean_is_refused(self):
        for bad in ("true", 1, ["x86"], {}):
            with self.subTest(bad=bad):
                self.assertTrue(_32bit_errors(
                    _with(SINGLE, seccomp_32bit=bad)))

    def test_beside_a_seccomp_profile_of_its_own_it_is_refused(self):
        """It adjusts the baseline, which seccomp= replaces."""
        self.assertTrue(_32bit_errors(_with(
            SINGLE, seccomp_32bit=True,
            security_opt=["seccomp=/etc/containers/mine.json"])))

    def test_with_privileged_it_is_refused(self):
        self.assertTrue(_32bit_errors(_with(
            SINGLE, seccomp_32bit=True, privileged=True)))

    def test_in_a_containers_own_security_it_is_refused(self):
        pod = dict(POD, containers=[
            dict(POD["containers"][0],
                 security={"seccomp_32bit": True}),
            POD["containers"][1]])
        self.assertTrue(_32bit_errors(pod))

    def test_on_a_vm_it_is_refused(self):
        self.assertTrue(_32bit_errors(_with(VM, seccomp_32bit=True)))

    def test_a_refusal_names_only_the_key_that_is_set(self):
        for refused in ({"privileged": True},
                        {"security_opt": ["seccomp=unconfined"]}):
            with self.subTest(refused=refused):
                config = _with(SINGLE, seccomp_32bit=True, **refused)
                self.assertTrue(_32bit_errors(config))
                self.assertEqual(_seccomp_errors(config), [])

    def test_the_reader_is_a_bool(self):
        self.assertIs(seccomp_32bit(_with(SINGLE, seccomp_32bit=True)), True)
        self.assertIs(seccomp_32bit(SINGLE), False)


class TestValidateNetlink(unittest.TestCase):
    def test_a_list_of_known_protocols_is_accepted(self):
        self.assertEqual(_netlink_errors(_with(
            SINGLE, seccomp_netlink=["generic"])), [])
        self.assertEqual(_netlink_errors(_with(
            POD, seccomp_netlink=["generic", "sock_diag"])), [])

    def test_anything_but_a_list_of_known_protocols_is_refused(self):
        """route and the rest are the baseline's already; xfrm and the
        other refused protocols are not offered."""
        for bad in ("generic", ["Generic"], ["route"], ["xfrm"], [16],
                    [["generic"]], {}):
            with self.subTest(bad=bad):
                self.assertTrue(_netlink_errors(
                    _with(SINGLE, seccomp_netlink=bad)))

    def test_where_the_baseline_does_not_apply_it_is_refused(self):
        for refused in ({"privileged": True},
                        {"security_opt": ["seccomp=unconfined"]}):
            with self.subTest(refused=refused):
                config = _with(SINGLE, seccomp_netlink=["generic"], **refused)
                self.assertTrue(_netlink_errors(config))
                self.assertEqual(_seccomp_errors(config), [])
                self.assertEqual(_32bit_errors(config), [])
        self.assertTrue(_netlink_errors(
            _with(VM, seccomp_netlink=["generic"])))

    def test_in_a_containers_own_security_it_is_refused(self):
        pod = dict(POD, containers=[
            dict(POD["containers"][0],
                 security={"seccomp_netlink": ["generic"]}),
            POD["containers"][1]])
        self.assertTrue(_netlink_errors(pod))

    def test_the_protocols_are_sorted_once_each(self):
        self.assertEqual(seccomp_netlink(_with(
            SINGLE, seccomp_netlink=["sock_diag", "generic", "generic"])),
            ["generic", "sock_diag"])
        self.assertEqual(seccomp_netlink(SINGLE), [])


class TestNeedsADerivedProfile(unittest.TestCase):
    """The one predicate the generator and the run args both read, so the
    written file and the --security-opt that names it cannot drift apart."""

    def test_neither_opt_uses_the_baseline_directly(self):
        self.assertFalse(needs_derived_profile(SINGLE))

    def test_either_opt_derives_a_profile(self):
        self.assertTrue(needs_derived_profile(
            _with(SINGLE, seccomp_allow=["ptrace"])))
        self.assertTrue(needs_derived_profile(
            _with(SINGLE, seccomp_32bit=True)))
        self.assertTrue(needs_derived_profile(
            _with(SINGLE, seccomp_netlink=["generic"])))


class TestDerive32bit(unittest.TestCase):
    BASE = {"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 38,
            "archMap": [{"architecture": ARCH_X86_64,
                         "subArchitectures": []},
                        {"architecture": "SCMP_ARCH_AARCH64",
                         "subArchitectures": ["SCMP_ARCH_ARM"]}],
            "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}

    def _x86_64(self, profile):
        return next(e for e in profile["archMap"]
                    if e["architecture"] == ARCH_X86_64)["subArchitectures"]

    def test_off_by_default_the_subarches_stay_dropped(self):
        self.assertEqual(self._x86_64(derived_profile(self.BASE, [])), [])

    def test_on_it_restores_only_the_x86_64_subarches(self):
        profile = derived_profile(self.BASE, [], allow_32bit=True)
        self.assertEqual(self._x86_64(profile), SUBARCHES_32BIT)
        aarch64 = next(e for e in profile["archMap"]
                       if e["architecture"] == "SCMP_ARCH_AARCH64")
        self.assertEqual(aarch64["subArchitectures"], ["SCMP_ARCH_ARM"])

    def test_it_does_not_mutate_the_baseline(self):
        derived_profile(self.BASE, [], allow_32bit=True)
        self.assertEqual(self._x86_64(self.BASE), [])


class TestAPod(unittest.TestCase):
    def setUp(self):
        self.dirs = [tempfile.mkdtemp() for _ in range(3)]
        for d in self.dirs:
            self.addCleanup(shutil.rmtree, d)

    def test_every_container_runs_under_the_derived_profile(self):
        config_dir, services_dir, sysusers_dir = self.dirs
        write_config(config_dir, "stack", """\
            [workload]
            name = "stack"
            mode = "pod"

            [security]
            seccomp_allow = ["ptrace"]

            [[containers]]
            name = "web"
            [containers.container]
            image = "web"

            [[containers]]
            name = "db"
            [containers.container]
            image = "db"
        """)
        result = run_generator(config_dir, services_dir, sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        for c in ("web", "db"):
            unit = (Path(services_dir)
                    / f"workload-stack-{c}.service").read_text()
            self.assertIn("--security-opt=seccomp=/run/systemd/system/"
                          "workload-stack.seccomp.json", unit)
        self.assertTrue((Path(services_dir)
                         / "workload-stack.seccomp.json").exists())

    def test_seccomp_32bit_alone_derives_and_names_the_profile(self):
        """No seccomp_allow, only seccomp_32bit: the generator still writes
        the derived profile and the unit names it, not the baseline — the
        seam both call sites read through. The profile carries the 32-bit
        sub-arches back."""
        import json
        config_dir, services_dir, sysusers_dir = self.dirs
        write_config(config_dir, "game", """\
            [workload]
            name = "game"

            [security]
            seccomp_32bit = true

            [container]
            image = "game"
        """)
        result = run_generator(config_dir, services_dir, sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        unit = (Path(services_dir) / "workload-game.service").read_text()
        self.assertIn("--security-opt=seccomp=/run/systemd/system/"
                      "workload-game.seccomp.json", unit)
        profile = json.loads((Path(services_dir)
                              / "workload-game.seccomp.json").read_text())
        x86_64 = next(e for e in profile["archMap"]
                      if e["architecture"] == "SCMP_ARCH_X86_64")
        self.assertEqual(x86_64["subArchitectures"],
                         ["SCMP_ARCH_X86", "SCMP_ARCH_X32"])

    def test_seccomp_netlink_alone_derives_and_names_the_profile(self):
        """No seccomp_allow, only seccomp_netlink: the generator writes the
        derived profile, the unit names it, and the profile carries the
        protocol's socket() allow."""
        import json
        config_dir, services_dir, sysusers_dir = self.dirs
        write_config(config_dir, "vpn", """\
            [workload]
            name = "vpn"

            [security]
            seccomp_netlink = ["generic"]

            [container]
            image = "vpn"
        """)
        result = run_generator(config_dir, services_dir, sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        unit = (Path(services_dir) / "workload-vpn.service").read_text()
        self.assertIn("--security-opt=seccomp=/run/systemd/system/"
                      "workload-vpn.seccomp.json", unit)
        profile = json.loads((Path(services_dir)
                              / "workload-vpn.seccomp.json").read_text())
        self.assertEqual(decide(profile, "socket", AF_NETLINK, 3,
                                NETLINK_PROTOCOLS["generic"]), ALLOW)

    def test_the_profile_is_readable_whatever_the_umask(self):
        """The workload user's podman reads the profile. Written under the
        enabling root's umask 077 (on the proving host, 2026-10-16) it was
        0600 root, and podman exited 125 with "opening seccomp profile
        failed: permission denied" on every start."""
        import os
        config_dir, services_dir, sysusers_dir = self.dirs
        write_config(config_dir, "vpn", """\
            [workload]
            name = "vpn"

            [security]
            seccomp_netlink = ["generic"]

            [container]
            image = "vpn"
        """)
        old = os.umask(0o077)
        try:
            result = run_generator(config_dir, services_dir, sysusers_dir)
        finally:
            os.umask(old)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        mode = (Path(services_dir) / "workload-vpn.seccomp.json").stat().st_mode
        self.assertEqual(mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
