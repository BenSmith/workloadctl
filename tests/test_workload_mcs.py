#!/usr/bin/env python3
"""Each workload runs at an MCS level of its own, and its files carry it.

Before this, every workload's data and state were s0, which every
container's label dominates, so only file modes kept one workload out of
another's files, and VMs had no categories at all (audit F3). The level is
derived from the uid; the containers, the pod, QEMU and virtiofsd run at
it; per-workload fcontext rules put it on the contents of data/ and state/,
leaving the two directories and the PKI subtree at s0 for the host's
confined daemons. Any one of those pieces missing still builds and starts.
"""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cmd_disable
import cmd_enable
import cmd_lifecycle
import workload_selinux
from container_run_args import label_level_args
from gen_vm import generate_virtiofs_service
from tests import REPO_ROOT
from tests.test_generator import run_generator, write_config
from workload_addr import UID_MAX, UID_MIN
from workload_mcs import WORKLOAD_CATEGORIES, mcs_categories, mcs_level
from workloadctl_core import WorkloadUserNotFound


class Level(unittest.TestCase):

    def test_every_workload_uid_has_its_own_pair(self):
        pairs = {mcs_categories(u) for u in range(UID_MIN, UID_MAX + 1)}
        self.assertEqual(len(pairs), UID_MAX - UID_MIN + 1)
        for low, high in pairs:
            self.assertTrue(0 <= low < high < WORKLOAD_CATEGORIES)

    def test_the_level_names_both_lower_first(self):
        self.assertRegex(mcs_level(UID_MIN + 5000), r"^s0:c(\d+),c(\d+)$")
        low, high = map(int, re.findall(r"\d+", mcs_level(UID_MIN + 5000))[1:])
        self.assertLess(low, high)

    def test_a_uid_outside_the_range_has_none(self):
        for uid in (0, 1000, UID_MIN - 1, UID_MAX + 1):
            with self.assertRaises(ValueError):
                mcs_level(uid)


class Containers(unittest.TestCase):

    def test_the_level_goes_on_unless_the_container_is_unlabelled(self):
        self.assertEqual(label_level_args(10042),
                         [f"--security-opt=label=level:{mcs_level(10042)}"])
        self.assertEqual(label_level_args(10042, privileged=True), [])
        self.assertEqual(label_level_args(10042, ["label=disable"]), [])
        self.assertEqual(label_level_args(10042, ["label=level:s0:c1,c2"]), [])

    def _generate(self, toml, name):
        conf, svc, users = (tempfile.mkdtemp() for _ in range(3))
        write_config(conf, name, toml)
        result = run_generator(conf, svc, users)
        self.assertEqual(result.returncode, 0, result.stderr)
        sysusers = (Path(users) / f"workload-{name}.conf").read_text()
        uid = int(re.search(rf"^u _wl-{name} (\d+)", sysusers, re.M)[1])
        return Path(svc), uid

    def test_a_single_container_runs_at_its_level(self):
        svc, uid = self._generate("""\
            [workload]
            name = "lvl"

            [container]
            image = "example.test/img"
            """, "lvl")
        unit = (svc / "workload-lvl.service").read_text()
        self.assertIn(f"--security-opt=label=level:{mcs_level(uid)}", unit)

    def test_a_pod_carries_it_and_its_members_share_it(self):
        svc, uid = self._generate("""\
            [workload]
            name = "plvl"
            mode = "pod"

            [[containers]]
            name = "a"
            [containers.container]
            image = "example.test/a"
            """, "plvl")
        pod = (svc / "workload-plvl-pod.service").read_text()
        self.assertIn(f"--security-opt=label=level:{mcs_level(uid)}", pod)
        members = [p for p in svc.glob("workload-plvl*.service")
                   if p.name != "workload-plvl-pod.service"]
        for member in members:
            self.assertNotIn("label=level:", member.read_text(), member.name)


class Vms(unittest.TestCase):

    def test_virtiofsd_runs_at_the_vms_level(self):
        unit = generate_virtiofs_service("vm1", "data", "/srv/x", "_wl-vm1",
                                         10042)
        self.assertIn("SELinuxContext=system_u:system_r:wlvfsd_t:"
                      f"{mcs_level(10042)}", unit)


class Rules(unittest.TestCase):
    """apply_level_fcontext, with semanage's answers stubbed."""

    def setUp(self):
        self.calls = []
        self.listing = ""
        self.enterContext(mock.patch.object(
            workload_selinux.shutil, "which", return_value="/usr/sbin/x"))

        def run(argv, **kw):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, self.listing, "")
        self.enterContext(mock.patch.object(
            workload_selinux.subprocess, "run", side_effect=run))

    def _config(self, is_vm=False, uid=10042):
        config = mock.Mock(is_vm=is_vm)
        config.name = "w"
        if isinstance(uid, Exception):
            type(config).uid = mock.PropertyMock(side_effect=uid)
        else:
            config.uid = uid
        return config

    def _semanage(self, verb):
        return [c for c in self.calls if c[:3] == ["semanage", "fcontext", verb]]

    def test_a_containers_contents_get_container_file_t_at_its_level(self):
        workload_selinux.apply_level_fcontext(self._config(), "enable")
        added = self._semanage("-a")
        self.assertEqual(len(added), 2)
        for argv in added:
            self.assertEqual(argv[3:7],
                             ["-t", "container_file_t", "-r", mcs_level(10042)])
        self.assertEqual(sorted(a[-1] for a in added), sorted(
            workload_selinux.level_fcontext_patterns("w")))
        self.assertEqual(self.calls[-1][:2], ["restorecon", "-RF"])

    def test_a_vms_get_svirt_image_t(self):
        workload_selinux.apply_level_fcontext(self._config(is_vm=True),
                                              "enable")
        for argv in self._semanage("-a"):
            self.assertEqual(argv[4], workload_selinux.IMAGE_SELINUX_TYPE)

    def test_registered_rules_are_kept_and_others_modified(self):
        pattern = workload_selinux.level_fcontext_patterns("w")
        self.listing = (
            f"{pattern[0]}  all files  system_u:object_r:container_file_t:"
            f"{mcs_level(10042)}\n"
            f"{pattern[1]}  all files  system_u:object_r:container_file_t:"
            f"s0:c1,c2\n")
        workload_selinux.apply_level_fcontext(self._config(), "enable")
        self.assertEqual(self._semanage("-a"), [])
        self.assertEqual([c[-1] for c in self._semanage("-m")], [pattern[1]])

    def test_no_user_registers_nothing(self):
        workload_selinux.apply_level_fcontext(
            self._config(uid=WorkloadUserNotFound("w")), "enable")
        self.assertEqual(self._semanage("-a"), [])

    def test_disable_removes_both(self):
        workload_selinux.apply_level_fcontext(self._config(), "disable")
        self.assertEqual(sorted(c[-1] for c in self._semanage("-d")), sorted(
            workload_selinux.level_fcontext_patterns("w")))

    def test_state_and_the_pki_subtree_stay_off_it(self):
        """The stem before the first metacharacter decides which rule wins:
        each PKI rule's is longer, and the state rule covers only what is
        below state/, which the inspector traverses."""
        def stem(pattern):
            return re.split(r"[\\\\.()?*+\\[]", pattern, maxsplit=1)[0]
        levels = workload_selinux.level_fcontext_patterns("w")
        state_rule = next(p for p in levels if "/state/" in p)
        self.assertTrue(state_rule.endswith("/state/.+"), state_rule)
        for pki, _ in workload_selinux.pki_fcontext_patterns("w"):
            self.assertGreater(len(stem(pki)), len(stem(state_rule)), pki)


class Wiring(unittest.TestCase):
    """What calls apply_level_fcontext: enable after the user exists,
    recreate, and disable."""

    def _source(self, module):
        return Path(module.__file__).read_text()

    def test_enable_registers_after_provisioning_before_starting(self):
        text = self._source(cmd_enable)
        provision = text.index("    provision_user(config)\n")
        register = text.index('apply_level_fcontext(config, "enable")')
        start = text.index("    start_service(config)\n")
        self.assertLess(provision, register)
        self.assertLess(register, start)

    def test_recreate_and_disable_call_it(self):
        self.assertIn('apply_level_fcontext(config, "enable")',
                      self._source(cmd_lifecycle))
        self.assertIn('apply_level_fcontext(config, "disable")',
                      self._source(cmd_disable))

    def test_qemu_starts_at_its_uids_level(self):
        text = (REPO_ROOT / "lib" / "vm_notify.py").read_text()
        self.assertIn("qemu_launch_argv(qemu_cmd, uid)", text)
        self.assertIn("uid = os.getuid()", text)


if __name__ == "__main__":
    unittest.main()
