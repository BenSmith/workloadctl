#!/usr/bin/env python3
"""diagnose lists local bundle files that shadow a shipped file.

A file in /etc/workloadctl/bundles/<bundle>/ with the same relative path as one
in the shipped bundle wins over it and stops following package updates. The
check is a warning naming those files: it passes, carries `"warning": True` and
a fix, and is absent when there are none.
"""
import io
import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import cmd_diagnose
import diagnose_battery
import diagnose_egress
import diagnose_inspect
import workload_lib
from workloadctl_core import WorkloadConfig

TOML = """\
[workload]
name = "app"

[container]
image = "localhost/app:latest"
"""

CHECK = "bundle_shadowing"


class Wiring(unittest.TestCase):
    """Through collect_diagnose_checks, which is where the check is called."""

    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.etc, self.usr, self.local = (
            root / "etc", root / "usr", root / "local")
        for d in (self.etc, self.usr, self.local):
            d.mkdir()
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_BUNDLES_DIR", self.usr))
        self.enterContext(mock.patch.object(
            workload_lib, "WORKLOAD_LOCAL_BUNDLES_DIR", self.local))
        (self.etc / "app").mkdir()
        (self.etc / "app" / "workload.toml").write_text(TOML)
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.manager.get_image_id.return_value = "sha256:0123456789ab"
        self.manager.podman.return_value.image_info.return_value = {}
        self.manager.podman.return_value.container_status.return_value = "Up"
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=10099))
        self.enterContext(mock.patch.object(
            diagnose_battery.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))
        for module in (diagnose_battery, diagnose_inspect, diagnose_egress):
            self.enterContext(mock.patch.object(
                module, "service_active", return_value=(False, "inactive")))

    def _write(self, layer, relpath):
        path = layer / "app" / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relpath)

    def _checks(self):
        checks, _ = diagnose_battery.collect_diagnose_checks(
            WorkloadConfig("app"), self.manager)
        return checks

    def _entry(self):
        return next((c for c in self._checks() if c["check"] == CHECK), None)

    def test_a_shadowing_file_is_a_warning(self):
        self._write(self.usr, "build.sh")
        self._write(self.local, "build.sh")
        entry = self._entry()
        self.assertTrue(entry["passed"])
        self.assertIs(entry["warning"], True)
        self.assertEqual(
            set(entry), {"check", "passed", "message", "fix", "warning"})
        self.assertIn("build.sh", entry["message"])
        self.assertIn("do not follow package updates", entry["message"])
        self.assertIn(str(self.local / "app"), entry["message"])

    def test_the_fix_compares_the_two_trees_and_says_how_to_follow_again(self):
        self._write(self.usr, "build.sh")
        self._write(self.local, "build.sh")
        fix = self._entry()["fix"]
        self.assertIn(f"diff -ru {self.usr / 'app'} {self.local / 'app'}", fix)
        self.assertIn("deleting a local file makes it follow the package again",
                      fix)

    def test_only_a_warning_carries_the_key(self):
        self._write(self.usr, "build.sh")
        self._write(self.local, "build.sh")
        others = [c for c in self._checks() if c["check"] != CHECK]
        self.assertTrue(others)
        for c in others:
            self.assertNotIn("warning", c, c["check"])

    def _diagnose(self, json_mode):
        out = io.StringIO()
        with mock.patch.object(cmd_diagnose, "require_root", lambda: None), \
                redirect_stdout(out), self.assertRaises(SystemExit):
            cmd_diagnose.cmd_diagnose(
                Namespace(workload="app", json=json_mode), self.manager)
        return out.getvalue()

    def test_the_diagnose_command_shows_and_counts_it(self):
        """The seam: the real battery's entry, through the real renderer."""
        self._write(self.usr, "build.sh")
        self._write(self.local, "build.sh")
        data = json.loads(self._diagnose(json_mode=True))
        self.assertEqual(data["checks_warned"], 1)
        text = self._diagnose(json_mode=False)
        self.assertIn("! Local bundle files shadow the shipped bundle", text)
        self.assertIn("Warnings:\n  1. Local bundle files shadow", text)

    def test_a_warning_survives_the_disabled_fold(self):
        """This workload has no enable marker, so the battery folds its
        absences; the on-disk shadowing is not one of them."""
        self._write(self.usr, "build.sh")
        self._write(self.local, "build.sh")
        checks = self._checks()
        self.assertIn("workload_disabled", [c["check"] for c in checks])
        entry = next(c for c in checks if c["check"] == CHECK)
        self.assertIs(entry["warning"], True)

    def test_an_enabled_workload_warns_too(self):
        self._write(self.usr, "build.sh")
        self._write(self.local, "build.sh")
        (self.etc / "app" / ".enabled").touch()
        checks = self._checks()
        self.assertNotIn("workload_disabled", [c["check"] for c in checks])
        entry = next(c for c in checks if c["check"] == CHECK)
        self.assertIs(entry["warning"], True)

    def test_a_nested_path_is_listed(self):
        self._write(self.usr, "scripts/inner/helper.sh")
        self._write(self.local, "scripts/inner/helper.sh")
        self.assertIn("scripts/inner/helper.sh", self._entry()["message"])

    def test_a_local_only_file_is_not_listed(self):
        self._write(self.usr, "build.sh")
        self._write(self.local, "build.sh")
        self._write(self.local, "extra.sh")
        self._write(self.local, "scripts/mine.sh")
        message = self._entry()["message"]
        self.assertIn("build.sh", message)
        self.assertNotIn("extra.sh", message)
        self.assertNotIn("mine.sh", message)

    def test_only_local_only_files_report_nothing(self):
        self._write(self.usr, "build.sh")
        self._write(self.local, "extra.sh")
        self.assertIsNone(self._entry())

    def test_no_local_dir_reports_nothing(self):
        self._write(self.usr, "build.sh")
        self.assertIsNone(self._entry())

    def test_a_local_only_bundle_reports_nothing(self):
        self._write(self.local, "build.sh")
        self.assertIsNone(self._entry())


class Malformed(unittest.TestCase):
    def test_a_malformed_bundle_name_is_left_out_not_raised(self):
        config = mock.Mock()
        type(config).local_bundle_dir = mock.PropertyMock(
            side_effect=ValueError("Invalid [workload] bundle"))
        checks = []
        diagnose_battery._bundle_shadowing_check(
            config, lambda *args, **kwargs: checks.append(args))
        self.assertEqual(checks, [])


if __name__ == "__main__":
    unittest.main()
