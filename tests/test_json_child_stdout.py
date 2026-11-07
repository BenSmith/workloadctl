#!/usr/bin/env python3
"""Under --json a child's stdout goes to stderr.

On the proving host (2026-11-07) `enable --json` printed four lines of
workload-ensure-user progress ("Ensuring user setup for workload: …" to
"User setup complete …") ahead of the result object, so `| jq` failed.
The helper and a bundle's setup script write to the inherited fd 1, which
cli_log's suppression never sees.
"""

import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import cli_log
import provisioning

LIB = Path(__file__).resolve().parent.parent / "lib"

# A child process, so the setup script writes to a real fd 1.
SETUP_UNDER_JSON = """
import sys, types
from pathlib import Path
from unittest import mock
import cli_log, host_setup
cli_log.configure(json_mode=sys.argv[2] == "json", command="enable")
script = Path(sys.argv[1])
config = types.SimpleNamespace(
    config={"host": {"setup": str(script)}},
    resolve_control_file=lambda s: script)
with mock.patch.object(host_setup, "host_setup_env", return_value={}), \\
        mock.patch.object(cli_log.oplog, "record"):
    host_setup.run_host_setup(config, "enable")
    cli_log.emit_result([{"workload": "web", "result": "enabled"}])
"""


class ASetupScriptUnderJson(unittest.TestCase):

    def run_child(self, mode):
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "setup.sh"
            script.write_text("#!/bin/sh\necho setting up the host\n")
            script.chmod(0o755)
            return subprocess.run(
                [sys.executable, "-c", SETUP_UNDER_JSON, str(script), mode],
                capture_output=True, text=True, timeout=30,
                env={**os.environ, "PYTHONPATH": str(LIB)})

    def test_stdout_is_the_result_alone(self):
        p = self.run_child("json")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["workloads"][0]["result"],
                         "enabled")
        self.assertIn("setting up the host", p.stderr)

    def test_without_json_the_script_speaks_on_stdout(self):
        p = self.run_child("text")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("setting up the host", p.stdout)


class TheUserHelpersUnderJson(unittest.TestCase):

    def stdouts(self, json_mode):
        cli_log.configure(json_mode=json_mode)
        self.addCleanup(cli_log.reset)
        config = types.SimpleNamespace(name="web")
        with mock.patch.object(provisioning.subprocess, "run",
                               return_value=mock.MagicMock(returncode=0)) as run:
            provisioning.provision_user(config)
        return {c.args[0][0]: c.kwargs.get("stdout") for c in run.call_args_list}

    def test_sysusers_and_ensure_user_write_to_stderr(self):
        self.assertEqual(self.stdouts(True), {
            "systemd-sysusers": sys.stderr,
            "/usr/libexec/workloadctl/workload-ensure-user": sys.stderr})

    def test_without_json_they_inherit_stdout(self):
        self.assertEqual(set(self.stdouts(False).values()), {None})


if __name__ == "__main__":
    unittest.main()
