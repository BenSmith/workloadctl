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

import workload_selinux
from container_run_args import label_level_args
from gen_vm import generate_virtiofs_service
from tests import REPO_ROOT
from tests.test_generator import run_generator, write_config
from workload_addr import UID_MAX, UID_MIN
from workload_mcs import WORKLOAD_CATEGORIES, mcs_categories, mcs_level


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
    """apply_vm_fcontext, with semanage's answers stubbed: a VM's one rule
    in file_contexts.local, a container's none, and nothing else under the
    workload's root. The level is no rule (Stamp)."""

    ROOT = "/var/lib/workloads/w"

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

    def _config(self, is_vm):
        config = mock.Mock(is_vm=is_vm)
        config.name = "w"
        return config

    def _semanage(self, verb):
        return [c for c in self.calls if c[:3] == ["semanage", "fcontext", verb]]

    def _listed(self, *patterns):
        self.listing = "".join(
            f"{p}  all files  system_u:object_r:container_file_t:s0\n"
            for p in patterns)

    def test_a_vm_gets_its_whole_tree_as_svirt_image_t(self):
        workload_selinux.apply_vm_fcontext(self._config(True), "enable")
        self.assertEqual(self._semanage("-a"), [
            ["semanage", "fcontext", "-a", "-t", "svirt_image_t",
             f"{self.ROOT}(/.*)?"]])

    def test_every_other_rule_under_the_root_goes(self):
        self._listed(f"{self.ROOT}(/.*)?", f"{self.ROOT}/state/ca(/.*)?",
                     f"{self.ROOT}/state/.+", f"{self.ROOT}/data(/.*)?")
        workload_selinux.apply_vm_fcontext(self._config(True), "enable")
        self.assertEqual(self._semanage("-a"), [])
        self.assertEqual(sorted(c[-1] for c in self._semanage("-d")), sorted([
            f"{self.ROOT}/state/ca(/.*)?", f"{self.ROOT}/state/.+",
            f"{self.ROOT}/data(/.*)?"]))

    def test_a_container_keeps_none(self):
        self._listed(f"{self.ROOT}(/.*)?", f"{self.ROOT}/data(/.*)?")
        workload_selinux.apply_vm_fcontext(self._config(False), "enable")
        self.assertEqual(self._semanage("-a"), [])
        self.assertEqual(len(self._semanage("-d")), 2)

    def test_disable_removes_the_vms_rule(self):
        self._listed(f"{self.ROOT}(/.*)?")
        workload_selinux.apply_vm_fcontext(self._config(True), "disable")
        self.assertEqual([c[-1] for c in self._semanage("-d")],
                         [f"{self.ROOT}(/.*)?"])
        self.assertEqual(self._semanage("-a"), [])

    def test_another_workload_sharing_the_prefix_is_left_alone(self):
        self._listed("/var/lib/workloads/w-2(/.*)?", "/var/lib/workloads(/.*)?")
        workload_selinux.apply_vm_fcontext(self._config(False), "enable")
        self.assertEqual(self._semanage("-d"), [])

    def test_nothing_is_relabelled_here(self):
        """The setup unit stamps the tree's type with its level; a
        restorecon here would reset the level to s0."""
        workload_selinux.apply_vm_fcontext(self._config(True), "enable")
        self.assertFalse([c for c in self.calls if c[0] == "restorecon"])


class Wiring(unittest.TestCase):
    """The setup unit's step stamps the level for both substrates."""

    def test_both_branches_of_the_setup_step_stamp(self):
        text = (REPO_ROOT / "lib" / "ensure_user.py").read_text()
        self.assertIn("stamp_selinux_labels(name, pw.pw_uid, is_vm=True)",
                      text)
        self.assertIn("stamp_selinux_labels(name, pw.pw_uid, is_vm=False)",
                      text)

    def test_qemu_starts_at_its_uids_level(self):
        text = (REPO_ROOT / "lib" / "vm_notify.py").read_text()
        self.assertIn("qemu_launch_argv(qemu_cmd, uid)", text)
        self.assertIn("uid = os.getuid()", text)


if __name__ == "__main__":
    unittest.main()
