#!/usr/bin/env python3
"""`diagnose` renders a warning: a check that passed and that the operator
should see.

A warning is `passed=True` plus `"warning": True` on the entry. It never fails
anything, so `passed`, the exit status and `checks_passed` are what they would
be without it; it is only rendered differently — `!`, its `Fix:` line, a
`Warnings:` list, a count in the summary and the closing line, and
`checks_warned` in the JSON. The collector side is pinned in
test_diagnose_bundle_shadowing and test_gpu_selinux, the doctor side in
test_cmd_doctor.
"""
import io
import json
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

import cmd_diagnose

PASS = {"check": "user_exists", "passed": True, "message": "User exists"}
WARN = {"check": "bundle_shadowing", "passed": True,
        "message": "Local bundle files shadow the shipped bundle: build.sh",
        "fix": "diff -ru /usr/shipped /etc/local", "warning": True}
WARN2 = {"check": "gpu_selinux", "passed": True,
         "message": "NVIDIA device access allowed via the legacy blanket "
                    "container_use_devices",
         "fix": "sudo setsebool -P container_use_xserver_devices on", "warning": True}
FAIL = {"check": "home_dir", "passed": False,
        "message": "Home directory missing", "fix": "sudo mkdir /home/x"}


class DiagnoseWarningTest(unittest.TestCase):
    def setUp(self):
        self.enabled = True
        self.enterContext(
            mock.patch.object(cmd_diagnose, "require_root", lambda: None))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "load_config_or_exit",
            lambda name, json_mode=False: SimpleNamespace(
                name="app", enabled=self.enabled)))

    def _run(self, checks, json_mode=False):
        passed = all(c["passed"] for c in checks)
        out = io.StringIO()
        code = None
        with mock.patch.object(cmd_diagnose, "collect_diagnose_checks",
                               lambda config, manager: (checks, passed)), \
                redirect_stdout(out):
            try:
                cmd_diagnose.cmd_diagnose(
                    Namespace(workload="app", json=json_mode), mock.Mock())
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()

    def test_a_warning_is_marked_with_its_fix_and_leaves_the_exit_zero(self):
        code, out = self._run([PASS, WARN])
        self.assertEqual(code, 0)
        self.assertIn("✓ User exists\n"
                      "! Local bundle files shadow the shipped bundle: "
                      "build.sh\n"
                      "  Fix: diff -ru /usr/shipped /etc/local\n", out)
        self.assertNotIn("✗", out)
        self.assertNotIn("Issues found", out)

    def test_the_summary_and_the_closing_line_count_it(self):
        _, out = self._run([PASS, WARN])
        self.assertIn("Checks: 2/2 passed, 1 warning\n", out)
        self.assertTrue(out.endswith(
            "✓ All checks passed (1 warning) - workload is healthy\n"), out)

    def test_the_warnings_list_numbers_message_and_fix(self):
        _, out = self._run([PASS, WARN, WARN2])
        self.assertIn("Checks: 3/3 passed, 2 warnings\n", out)
        self.assertIn(
            "Warnings:\n"
            "  1. Local bundle files shadow the shipped bundle: build.sh\n"
            "     diff -ru /usr/shipped /etc/local\n"
            "  2. NVIDIA device access allowed via the legacy blanket "
            "container_use_devices\n"
            "     sudo setsebool -P container_use_xserver_devices on\n", out)
        self.assertIn("✓ All checks passed (2 warnings) - ", out)

    def test_no_warning_changes_nothing_in_the_output(self):
        code, out = self._run([PASS])
        self.assertEqual(code, 0)
        self.assertIn("Checks: 1/1 passed\n", out)
        self.assertTrue(
            out.endswith("✓ All checks passed - workload is healthy\n"), out)
        self.assertNotIn("!", out)
        self.assertNotIn("Warnings", out)
        self.assertNotIn("warning", out)

    def test_a_disabled_workload_keeps_its_state_note(self):
        self.enabled = False
        _, out = self._run([PASS, WARN])
        self.assertTrue(out.endswith(
            "✓ All checks passed (1 warning) - workload is healthy "
            "(disabled — nothing is running)\n"), out)

    def test_a_failure_beside_a_warning_lists_both_and_exits_one(self):
        code, out = self._run([PASS, WARN, FAIL])
        self.assertEqual(code, 1)
        self.assertIn("✗ Home directory missing\n  Fix: sudo mkdir /home/x\n",
                      out)
        self.assertIn("! Local bundle files shadow", out)
        self.assertIn("Checks: 2/3 passed, 1 warning\n", out)
        self.assertLess(out.index("Issues found:"), out.index("Warnings:"))
        issues, warnings = out.split("Warnings:")
        self.assertNotIn("Local bundle files", issues.split("Issues found:")[1])
        self.assertNotIn("Home directory missing", warnings)
        self.assertNotIn("All checks passed", out)

    def test_json_counts_warnings_and_keeps_the_entry_key(self):
        code, out = self._run([PASS, WARN], json_mode=True)
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertTrue(data["passed"])
        self.assertEqual(data["checks_warned"], 1)
        self.assertEqual(data["checks_passed"], 2)
        self.assertEqual(data["checks_total"], 2)
        self.assertEqual(data["checks"][1], WARN)
        self.assertNotIn("warning", data["checks"][0])

    def test_json_counts_zero_when_nothing_warns(self):
        _, out = self._run([PASS, FAIL], json_mode=True)
        data = json.loads(out)
        self.assertEqual(data["checks_warned"], 0)
        self.assertFalse(any("warning" in c for c in data["checks"]))

    def test_json_exit_follows_passed_not_warnings(self):
        code, out = self._run([WARN, FAIL], json_mode=True)
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertFalse(data["passed"])
        self.assertEqual(data["checks_warned"], 1)


if __name__ == "__main__":
    unittest.main()
