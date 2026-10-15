"""The `rro` volume option, from the bundle to the running container.

The 2026-10-11 security audit (F8): alloy's `/:/host:ro` was read-only at the
top only, so `/host/proc`, `/host/sys`, the homes and `/run/user` stayed `rw`
inside it, and only DAC and alloy's label stood between it and a write there.
podman 5.8.7 (and 6.1.4) refuses `rro`; crun applies it. Proven on the
proving host 2026-10-13: the hook turned those mounts `ro` and a write under
`/host/tmp` got EROFS where the plain `ro` bind let it through (SELinux off,
so only the mount flag decided). Under rslave a mount the host made after the
start arrived `rw`; under rprivate it did not arrive.

Every link here is one that, broken, leaves the bind at plain `ro` with no
error anywhere: the generator's flags, the hook file's path and annotation
rule, the spec's install line, the hook's rewrite, and the check that reads
the running container's mountinfo.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import diagnose_battery
from recursive_readonly import (
    RRO_ANNOTATION,
    RRO_HOOKS_DIR,
    RroHookError,
    rro_rewrite,
    rro_volume_errors,
    rro_writable_mounts,
)
from validation import validate_workload_config

from tests import REPO_ROOT, script_env
from tests.test_shipped_bundles import generate_all

HOOK_JSON = REPO_ROOT / "oci-hooks" / "workloadctl-rro.json"
HOOK_PROGRAM = REPO_ROOT / "libexec" / "workload-oci-rro"
SPEC = REPO_ROOT / "rpm" / "workloadctl.spec"


def _oci(destinations, mounts):
    return {"annotations": {RRO_ANNOTATION: ",".join(destinations)},
            "mounts": mounts}


def _bind(destination, *options):
    return {"destination": destination, "type": "bind", "source": "/",
            "options": ["rbind", *options]}


class TestTheHookRewrites(unittest.TestCase):

    def test_the_annotated_bind_becomes_rro(self):
        config = rro_rewrite(_oci(["/host"], [
            _bind("/host", "ro", "rprivate"), _bind("/etc/x", "ro")]))
        self.assertEqual(config["mounts"][0]["options"],
                         ["rbind", "rro", "rprivate"])
        self.assertEqual(config["mounts"][1]["options"], ["rbind", "ro"])

    def test_a_destination_without_a_read_only_bind_refuses(self):
        for mounts in ([], [_bind("/host", "rw")], [_bind("/hostx", "ro")]):
            with self.subTest(mounts=mounts), \
                    self.assertRaises(RroHookError):
                rro_rewrite(_oci(["/host"], mounts))

    def test_an_empty_annotation_refuses(self):
        with self.assertRaises(RroHookError):
            rro_rewrite(_oci([], [_bind("/host", "ro")]))

    def test_the_program_rewrites_and_fails_closed(self):
        """podman creates the container from stdout and refuses it on a
        non-zero exit; both halves through the installed entrypoint."""
        def run(config):
            return subprocess.run(
                [sys.executable, str(HOOK_PROGRAM)], input=json.dumps(config),
                capture_output=True, text=True, env=script_env(), timeout=30,
                check=False)
        good = run(_oci(["/host"], [_bind("/host", "ro")]))
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertIn("rro", json.loads(good.stdout)["mounts"][0]["options"])
        bad = run(_oci(["/host"], [_bind("/elsewhere", "ro")]))
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, "")


class TestTheHookIsSelected(unittest.TestCase):
    """podman runs the hook only when the unit names its directory, the file
    there names the installed program, and its rule matches the annotation the
    generator writes."""

    @classmethod
    def setUpClass(cls):
        cls.hook = json.loads(HOOK_JSON.read_text())

    def test_the_rule_matches_the_generators_annotation(self):
        rules = self.hook["when"]["annotations"]
        self.assertEqual(len(rules), 1)
        (key, value), = rules.items()
        self.assertRegex(RRO_ANNOTATION, key)
        self.assertRegex("/host", value)
        self.assertEqual(self.hook["stages"], ["precreate"])

    def test_the_path_is_the_installed_program(self):
        self.assertEqual(self.hook["hook"]["path"],
                         f"/usr/libexec/workloadctl/{HOOK_PROGRAM.name}")

    def test_the_spec_installs_the_file_in_the_hooks_dir(self):
        self.assertEqual(RRO_HOOKS_DIR, "/usr/share/workloadctl/oci-hooks.d")
        self.assertRegex(
            SPEC.read_text(),
            r" oci-hooks/workloadctl-rro\.json \\\n\s+"
            r"%\{buildroot\}%\{_datadir\}/workloadctl/oci-hooks\.d/"
            r"workloadctl-rro\.json")


class TestTheShippedAlloyUnit(unittest.TestCase):
    """The rendered unit, where the flags have to arrive to mean anything."""

    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp:
            svc = Path(tmp) / "svc"
            svc.mkdir()
            generate_all(svc)
            cls.unit = (svc / "workload-alloy.service").read_text()

    def test_host_is_bound_ro_with_the_hook_selected(self):
        self.assertIn('--volume "/":"/host":"ro" ', self.unit)
        self.assertIn(f'--hooks-dir "{RRO_HOOKS_DIR}"', self.unit)
        self.assertIn(f'--annotation "{RRO_ANNOTATION}=/host"', self.unit)

    def test_podman_never_sees_rro_or_slave_propagation(self):
        self.assertNotRegex(self.unit, r"\brro\b")
        self.assertNotIn("slave", self.unit)


class TestValidation(unittest.TestCase):

    def test_propagating_and_doubled_options_are_refused(self):
        for opts in ("rro,rslave", "rro,shared", "rro,ro", "rw,rro"):
            with self.subTest(opts=opts):
                self.assertTrue(rro_volume_errors([f"/:/host:{opts}"], "v"))

    def test_rro_alone_or_private_passes(self):
        self.assertEqual(
            rro_volume_errors(["/:/host:rro", "/:/h:rro,rprivate", "/a:/b"],
                              "v"), [])

    def test_validate_config_reports_it_for_both_shapes(self):
        single = {"container": {"image": "x"},
                  "storage": {"volumes": ["/:/host:rro,rslave"]}}
        multi = {"workload": {"mode": "pod"}, "containers": [
            {"name": "a", "container": {"image": "x"},
             "storage": {"volumes": ["/:/host:rro,rslave"]}}]}
        for config in (single, multi):
            with self.subTest(shape=list(config)):
                self.assertTrue(any("rslave" in e for e in
                                    validate_workload_config(config)))


class TestTheRunningContainerIsChecked(unittest.TestCase):

    MOUNTINFO = (
        "1 0 0:1 / / rw - x x rw\n"
        "2 1 0:2 / /host ro,relatime - x x rw\n"
        "3 2 0:3 / /host/proc rw,nosuid - proc proc rw\n"
        "4 1 0:4 / /hostile rw - x x rw\n")

    def test_writable_mounts_under_the_destination_are_named(self):
        self.assertEqual(rro_writable_mounts(self.MOUNTINFO, "/host"),
                         ["/host/proc"])

    def _run_check(self, destination):
        config = SimpleNamespace(
            config={"workload": {"name": "w"}, "container": {"image": "x"},
                    "storage": {"volumes": [f"/:{destination}:rro"]}},
            home_dir=Path("/nonexistent"), is_multi=False, name="w",
            container_name="workload-w")
        podman = SimpleNamespace(
            container_inspect=lambda name: {"State": {"Pid": os.getpid()}})
        manager = SimpleNamespace(podman=lambda config: podman)
        checks = []
        diagnose_battery._recursive_readonly_checks(
            config, manager,
            lambda name, passed, message, fix=None:
                checks.append((name, passed, message)),
            lambda fn, *args: (True, fn(*args)))
        return checks

    def test_this_processs_own_rw_mounts_fail_the_check(self):
        """The check reads /proc/PID/mountinfo of the container's pid; this
        test process's own `/` has rw mounts, so naming it must fail."""
        (name, passed, message), = self._run_check("/")
        self.assertEqual(name, "recursive_readonly")
        self.assertFalse(passed, message)

    def test_a_destination_with_nothing_writable_passes(self):
        (_, passed, message), = self._run_check("/nonexistent-dest")
        self.assertTrue(passed, message)

    def test_the_battery_runs_the_check(self):
        source = Path(diagnose_battery.__file__).read_text()
        body = source[source.index("def collect_diagnose_checks"):]
        self.assertRegex(body, re.compile(
            r"_recursive_readonly_checks\(config, manager, _check, "
            r"podman_read\)"))


if __name__ == "__main__":
    unittest.main()
