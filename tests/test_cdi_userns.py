#!/usr/bin/env python3
"""A workload whose gpu resolves to nvidia runs in the default namespace.

podman idmaps every CDI-injected mount when the container has a user
namespace of its own, which rootless podman cannot do, so every container of
such a workload runs with --userns=host --user=0:0, delegates no group, and
refuses to start when another subid line would renumber that namespace.
"""

import io
import re
import shutil
import tempfile
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

import diagnose_subid
import ensure_container
import gpu_select
import workload_uid
from validation import validate_workload_config
from tests import load_script
from tests.test_generator import run_generator, write_config

GUARD = "/usr/libexec/workloadctl/workload-cdi-subids"


class _Generated(unittest.TestCase):
    def setUp(self):
        self.dirs = [tempfile.mkdtemp() for _ in range(3)]
        self.config_dir, self.services_dir, self.sysusers_dir = self.dirs

    def tearDown(self):
        for d in self.dirs:
            shutil.rmtree(d)

    def _units(self, toml):
        write_config(self.config_dir, "gpu", toml)
        r = run_generator(self.config_dir, self.services_dir,
                          self.sysusers_dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        return {p.name: p.read_text()
                for p in Path(self.services_dir).glob("workload-gpu*.service")}

    @staticmethod
    def _run_line(unit):
        lines = [l for l in unit.splitlines()
                 if l.startswith(("ExecStart=", "ExecStartPre=-"))
                 and ("podman run" in l or "podman pod create" in l)]
        assert len(lines) == 1, unit
        return lines[0]

    @staticmethod
    def _pre(unit):
        return [l.partition("=")[2] for l in unit.splitlines()
                if l.startswith("ExecStartPre=")]


SINGLE = """\
[workload]
name = "gpu"

[container]
image = "img"

[devices]
gpu = "{gpu}"

[security]
extra_groups = ["video", "render"]
{security}
"""


class SingleModeTest(_Generated):
    def test_nvidia_runs_in_the_default_namespace_as_root(self):
        unit = self._units(SINGLE.format(gpu="nvidia", security=""))[
            "workload-gpu.service"]
        run = self._run_line(unit)
        self.assertIn("--userns=host", run)
        self.assertEqual(re.findall(r"--user=(\S+)", run), ["0:0"])
        self.assertNotRegex(run, r"--(uid|gid)map")
        self.assertIn("--group-add=keep-groups", run)

    def test_default_keep_id_drops_roots_capabilities(self):
        """keep-id would have run it as the workload's own id, which holds
        no capability podman gives root."""
        run = self._run_line(self._units(SINGLE.format(
            gpu="nvidia", security='capabilities = ["CHOWN"]'))[
            "workload-gpu.service"])
        self.assertIn("--cap-drop=all", run)
        self.assertIn("--cap-add=CHOWN", run)

    def test_keep_id_root_keeps_roots_capabilities(self):
        run = self._run_line(self._units(SINGLE.format(
            gpu="nvidia", security='userns = "keep-id:uid=0,gid=0"'))[
            "workload-gpu.service"])
        self.assertNotIn("--cap-drop", run)
        self.assertEqual(re.findall(r"--user=(\S+)", run), ["0:0"])

    def test_guard_runs_before_migrate(self):
        unit = self._units(SINGLE.format(gpu="nvidia", security=""))[
            "workload-gpu.service"]
        pre = self._pre(unit)
        guard = [i for i, p in enumerate(pre) if p.startswith(GUARD)]
        migrate = [i for i, p in enumerate(pre) if "system migrate" in p]
        self.assertEqual(len(guard), 1, pre)
        self.assertLess(guard[0], migrate[0])
        self.assertRegex(pre[guard[0]], rf"^{GUARD} _wl-gpu \d+$")

    def test_ordered_after_the_toolkits_refresh(self):
        unit = self._units(SINGLE.format(gpu="nvidia", security=""))[
            "workload-gpu.service"]
        self.assertIn("After=nvidia-cdi-refresh.service", unit)
        self.assertNotIn("nvidia-cdi-generator", unit)
        self.assertNotRegex(unit, r"(Requires|Wants)=.*nvidia-cdi-refresh")

    def test_amd_keeps_the_fixed_slot_maps(self):
        unit = self._units(SINGLE.format(gpu="amd", security=""))[
            "workload-gpu.service"]
        run = self._run_line(unit)
        self.assertNotIn("--userns=", run)
        self.assertRegex(run, r"--gidmap \+\d+:@\d+:1")
        self.assertNotIn("--cap-drop", run)
        self.assertNotIn(GUARD, unit)


MULTI = """\
[workload]
name = "gpu"
mode = "{mode}"

[security]
extra_groups = ["video"]

[[containers]]
name = "a"
[containers.container]
image = "img-a"
[containers.devices]
gpu = "nvidia"

[[containers]]
name = "b"
[containers.container]
image = "img-b"
"""


class MultiModeTest(_Generated):
    def test_pod_one_nvidia_member_puts_the_pod_in_the_default_namespace(self):
        units = self._units(MULTI.format(mode="pod"))
        pod = units["workload-gpu-pod.service"]
        self.assertIn("--userns=host", self._run_line(pod))
        self.assertNotRegex(self._run_line(pod), r"--(uid|gid)map")
        self.assertEqual(len([p for p in self._pre(pod)
                              if p.startswith(GUARD)]), 1)
        for c in ("a", "b"):
            member = units[f"workload-gpu-{c}.service"]
            self.assertEqual(re.findall(r"--user=(\S+)",
                                        self._run_line(member)), ["0:0"])
            self.assertNotIn(GUARD, member)

    def test_bridge_one_nvidia_container_moves_every_container(self):
        units = self._units(MULTI.format(mode="bridge"))
        self.assertEqual(len([p for p in self._pre(units["workload-gpu-net.service"])
                              if p.startswith(GUARD)]), 1)
        for c in ("a", "b"):
            run = self._run_line(units[f"workload-gpu-{c}.service"])
            self.assertIn("--userns=host", run)
            self.assertNotRegex(run, r"--(uid|gid)map")


class DelegationsTest(unittest.TestCase):
    def test_nvidia_delegates_no_group(self):
        cfg = {"devices": {"gpu": "nvidia:0"},
               "security": {"extra_groups": ["video"]}}
        with mock.patch.object(ensure_container.grp, "getgrnam",
                               lambda n: types.SimpleNamespace(gr_gid=39)):
            self.assertEqual(ensure_container.delegated_gids(cfg), [])
            cfg["devices"]["gpu"] = "amd"
            self.assertEqual(ensure_container.delegated_gids(cfg), [39])

    def test_auto_resolving_to_nvidia_is_cdi(self):
        cfg = {"containers": [{"name": "a"},
                              {"name": "b", "devices": {"gpu": "auto"}}]}
        with mock.patch.object(gpu_select, "resolve_auto_gpu",
                               return_value="nvidia"):
            self.assertTrue(gpu_select.uses_cdi(cfg))
        with mock.patch.object(gpu_select, "resolve_auto_gpu",
                               return_value="nouveau"):
            self.assertFalse(gpu_select.uses_cdi(cfg))


def _config(security=None, **top):
    cfg = {"workload": {"name": "gpu"}, "container": {"image": "img"},
           "devices": {"gpu": "nvidia"}, "security": dict(security or {})}
    cfg.update(top)
    return cfg


class ValidateTest(unittest.TestCase):
    def _cdi_errors(self, cfg):
        return [e for e in validate_workload_config(cfg) if "CDI" in e]

    def test_refusals(self):
        for name, cfg in (
            ("shares", _config(shares=[{"name": "media", "target": "/m",
                                        "access": "read"}])),
            ("extra_gidmaps", _config({"extra_gidmaps": ["+44:@39:1"]})),
            ("extra_uidmaps", _config({"extra_uidmaps": ["+1:@{UID}:1"]})),
            ("userns", _config({"userns": "keep-id:uid=1000,gid=1000"})),
        ):
            with self.subTest(name):
                errors = self._cdi_errors(cfg)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn(name, errors[0])

    def test_the_three_default_namespace_forms_pass(self):
        for userns in (None, "keep-id", "keep-id:uid=0,gid=0", "host"):
            with self.subTest(userns=userns):
                security = {"unsafe_host_userns": True}
                if userns:
                    security["userns"] = userns
                self.assertEqual(validate_workload_config(_config(security)),
                                 [])

    def test_not_refused_without_nvidia(self):
        cfg = _config({"extra_gidmaps": ["+44:@39:1"]})
        cfg["devices"]["gpu"] = "amd"
        self.assertEqual(self._cdi_errors(cfg), [])


class SubidRefusalTest(unittest.TestCase):
    MAIN = "_wl-gpu:600231072:65536\n"

    def test_one_line_each_passes(self):
        self.assertIsNone(diagnose_subid.cdi_subid_refusal(
            self.MAIN, self.MAIN, "_wl-gpu", 10002))

    def test_a_pin_is_refused_and_named(self):
        msg = diagnose_subid.cdi_subid_refusal(
            self.MAIN, "_wl-gpu:39:1\n" + self.MAIN, "_wl-gpu", 10002)
        self.assertIn("/etc/subgid has 2 lines", msg)
        self.assertIn("_wl-gpu:39:1", msg)
        self.assertNotIn("/etc/subuid has", msg)

    def test_a_line_by_uid_counts(self):
        msg = diagnose_subid.cdi_subid_refusal(
            self.MAIN + "10002:105:1\n", self.MAIN, "_wl-gpu", 10002)
        self.assertIn("10002:105:1", msg)

    def test_other_users_lines_do_not_count(self):
        self.assertIsNone(diagnose_subid.cdi_subid_refusal(
            self.MAIN + "_wl-other:39:1\n", self.MAIN, "_wl-gpu", 10002))

    def test_no_line_is_refused(self):
        self.assertIn("0 lines", diagnose_subid.cdi_subid_refusal(
            "", self.MAIN, "_wl-gpu", 10002))


class GuardShimTest(unittest.TestCase):
    """The program the unit names reads the files and exits non-zero."""

    def setUp(self):
        self.shim = load_script("libexec/workload-cdi-subids")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.subuid, self.subgid = self.tmp / "subuid", self.tmp / "subgid"
        self.subuid.write_text("_wl-gpu:600231072:65536\n")
        self.enterContext(mock.patch.object(workload_uid, "SUBUID_FILE",
                                            self.subuid))
        self.enterContext(mock.patch.object(workload_uid, "SUBGID_FILE",
                                            self.subgid))

    def _run(self):
        err = io.StringIO()
        with redirect_stderr(err):
            rc = self.shim.main(["workload-cdi-subids", "_wl-gpu", "10002"])
        return rc, err.getvalue()

    def test_clean_files_start(self):
        self.subgid.write_text("_wl-gpu:600231072:65536\n")
        self.assertEqual(self._run(), (0, ""))

    def test_a_pin_stops_the_start(self):
        self.subgid.write_text("_wl-gpu:39:1\n_wl-gpu:600231072:65536\n")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("_wl-gpu:39:1", err)


if __name__ == "__main__":
    unittest.main()
