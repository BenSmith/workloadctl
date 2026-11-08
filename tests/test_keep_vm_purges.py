"""WLRT_KEEP_VM keeps the guest, never a workload.

The flag once made the harness's purge helper return early. A gate run
with it then failed test_health_lifecycle and the linger test (the
purge they assert on never ran), met a stale rt-vm host key in the VM
smoke test, and ran the guest out of memory under every workload left
running. Only the session's power-off may read the flag.
"""
import ast
import unittest
from pathlib import Path

CLI_SURFACE = Path(__file__).parent / "cli_surface"
FLAG = "WLRT_KEEP_VM"


def readers(path):
    """The functions in PATH whose source names the flag."""
    tree = ast.parse(path.read_text())
    return {node.name for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and FLAG in ast.get_source_segment(path.read_text(), node)}


class KeepVmPurges(unittest.TestCase):
    def test_the_purge_helper_does_not_read_the_flag(self):
        self.assertNotIn("_purge_workload",
                         readers(CLI_SURFACE / "fixtures.py"))

    def test_only_the_session_fixture_reads_it(self):
        found = {}
        for path in sorted(CLI_SURFACE.glob("*.py")):
            names = readers(path)
            if names:
                found[path.name] = names
        # `target` chooses poweroff or the notice; the notice prints it.
        self.assertEqual(found,
                         {"conftest.py": {"_keep_vm_notice", "target"}})
        conftest = (CLI_SURFACE / "conftest.py").read_text()
        self.assertIn("request.addfinalizer(t.poweroff)", conftest)


if __name__ == "__main__":
    unittest.main()
