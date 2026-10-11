#!/usr/bin/env python3
"""The inspector's and responder's inputs live in a root-owned directory.

The 2026-10-11 security audit (F20): inspect.json and resolve-static.json
were in /run/workload-vm/<name>/, which is the workload uid's, and as the
VM's uid under QEMU's label a file was created there and inspect.json moved
aside and back. They now live in /run/workload-vm/_policy/<name>/, root's.

workload-ensure-user makes that directory, but in the setup service, which
does not run again when a workload is restarted; on a host whose workloadctl
was upgraded without a reboot the writers reached a directory that was not
there and the inspect socket failed its start (measured on the proving
host). So each writer makes it too, and that is what this holds.
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import egress_policy
from egress_policy import ensure_policy_parent


class TestEnsurePolicyParent(unittest.TestCase):

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "_policy" / "web" / "inspect.json"

    def test_a_missing_dir_is_made_roots_and_closed(self):
        with mock.patch.object(egress_policy.os, "chown") as chown:
            ensure_policy_parent(str(self.path), 10001)
        parent = self.path.parent
        self.assertTrue(parent.is_dir())
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o750)
        chown.assert_called_once_with(str(parent), 0, 10001)

    def test_an_existing_dir_is_left_alone(self):
        self.path.parent.mkdir(parents=True)
        os.chmod(self.path.parent, 0o755)
        with mock.patch.object(egress_policy.os, "chown") as chown:
            ensure_policy_parent(str(self.path), 10001)
        chown.assert_not_called()
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o755)

    def test_the_paths_are_not_in_the_runtime_dir(self):
        for path in (egress_policy.inspect_policy_path("web"),
                     egress_policy.resolve_static_path("web")):
            self.assertTrue(path.startswith(f"{egress_policy.POLICY_DIR}/web/"),
                            path)


class TestTheWritersMakeIt(unittest.TestCase):
    """Wiring: each writer calls it with its own path before writing."""

    def test_both_writers_call_it_before_the_write(self):
        import inspect as pyinspect
        import filter_arm
        import inspect_arm
        for fn, getter in ((inspect_arm.write_policy, "inspect_policy_path"),
                           (filter_arm.write_resolve_static, "resolve_static_path")):
            src = pyinspect.getsource(fn)
            self.assertIn("ensure_policy_parent(path", src, fn.__name__)
            self.assertLess(src.index("ensure_policy_parent(path"),
                            src.index("open(tmp"), fn.__name__)


if __name__ == "__main__":
    unittest.main()
