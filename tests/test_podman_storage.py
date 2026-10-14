#!/usr/bin/env python3
"""A container workload's podman store is transient (audit F18).

podman wrote a `${SECRET:}` value, with the rest of the container's
environment, into its database and the container's config.json under the
graphroot (measured 2026-10-11, L10.3). With storage.conf's transient_store
both live under the runroot.
"""
import os
import shutil
import tempfile
import tomllib
import types
import unittest
from pathlib import Path
from unittest import mock

import podman_storage
from podman_storage import transient_storage_conf

FEDORA = """\
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
[storage.options]
additionalimagestores = [
"/usr/lib/containers/storage",
]
[storage.options.pull_options]
[storage.options.overlay]
mountopt = "nodev,metacopy=on"
"""


class TestTheConf(unittest.TestCase):
    """What c/storage gives a rootless user from the system's file, and
    transient_store. Measured on the proving host 2026-10-14: a copy of
    Fedora's whole file stopped the workload starting, as its rootless
    podman could not lock the additional image store."""

    def test_it_is_what_a_rootless_podman_takes_made_transient(self):
        self.assertEqual(
            tomllib.loads(transient_storage_conf(FEDORA)),
            {"storage": {"driver": "overlay", "transient_store": True,
                         "options": {"pull_options": {}}}})

    def test_overlays_chown_errors_and_pull_options_carry_over(self):
        conf = tomllib.loads(transient_storage_conf(
            '[storage]\ndriver = "overlay2"\ntransient_store = false\n'
            '[storage.options]\npull_options = {enable_partial_images = '
            '"true"}\n[storage.options.overlay]\n'
            'ignore_chown_errors = "true"\nmount_program = "/x"\n'))
        self.assertEqual(conf["storage"], {
            "driver": "overlay", "transient_store": True,
            "options": {"pull_options": {"enable_partial_images": "true"},
                        "overlay": {"ignore_chown_errors": "true"}}})

    def test_a_driver_that_does_not_run_rootless_leaves_the_priority(self):
        conf = tomllib.loads(transient_storage_conf(
            '[storage]\ndriver = "zfs"\n'
            'driver_priority = ["overlay", "vfs"]\n'))
        self.assertEqual(conf["storage"], {
            "driver_priority": ["overlay", "vfs"], "transient_store": True})

    def test_with_no_system_file_it_is_transient_alone(self):
        self.assertEqual(tomllib.loads(transient_storage_conf("")),
                         {"storage": {"transient_store": True}})

    def test_a_value_it_cannot_write_is_refused(self):
        with self.assertRaises(ValueError):
            transient_storage_conf(
                "[storage]\ndriver = \"overlay\"\n"
                "[storage.options]\npull_options = {ratio = 1.5}\n")


class TestEnsure(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = self.tmp / "wl"
        self.state = self.root / "state"
        self.state.mkdir(parents=True)
        self.graphroot = self.state / ".local/share/containers/storage"
        self.pw = types.SimpleNamespace(pw_uid=os.getuid(),
                                        pw_gid=os.getgid(), pw_name="_wl-wl")
        for name, value in (("workload_root_dir", self.root),
                            ("workload_state_dir", self.state)):
            patcher = mock.patch.object(podman_storage, name,
                                        return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(podman_storage, "system_storage_conf",
                                    return_value=FEDORA)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, stdout="", returncode=0):
        result = types.SimpleNamespace(stdout=stdout, returncode=returncode)
        with mock.patch.object(podman_storage.subprocess, "run",
                               return_value=result) as run:
            podman_storage.ensure_transient_store(self.pw, "wl")
        return run

    def _old_db(self):
        (self.graphroot / "libpod").mkdir(parents=True)
        for rel in ("db.sql", "db.sql-wal", "libpod/bolt_state.db"):
            (self.graphroot / rel).write_text("canary")

    def test_the_conf_is_in_the_workloads_home(self):
        self._run()
        conf = self.state / ".config/containers/storage.conf"
        self.assertIs(tomllib.loads(conf.read_text())["storage"]
                      ["transient_store"], True)
        self.assertEqual(conf.stat().st_mode & 0o777, 0o644)

    def test_with_no_old_database_podman_is_not_asked(self):
        self._run().assert_not_called()

    def test_the_old_database_goes_once_nothing_is_recorded_in_it(self):
        self._old_db()
        run = self._run()
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["runuser", "-u", "_wl-wl"])
        self.assertEqual(argv[-4:],
                         ["podman", "--transient-store=false", "ps", "-aq"])
        for rel in ("db.sql", "db.sql-wal", "libpod/bolt_state.db"):
            with self.subTest(rel=rel):
                self.assertFalse(os.path.lexists(self.graphroot / rel))

    def test_a_container_recorded_there_keeps_it(self):
        self._old_db()
        self._run(stdout="3f2a\n")
        self.assertTrue((self.graphroot / "db.sql").exists())

    def test_podman_failing_keeps_it(self):
        self._old_db()
        self._run(returncode=125)
        self.assertTrue((self.graphroot / "db.sql").exists())

    def test_a_link_on_the_way_to_the_database_is_not_followed(self):
        outside = self.tmp / "outside"
        (outside / "share/containers/storage").mkdir(parents=True)
        victim = outside / "share/containers/storage/db.sql"
        victim.write_text("root's")
        os.symlink(outside, self.state / ".local")
        self._run().assert_not_called()
        self.assertEqual(victim.read_text(), "root's")

    def test_a_link_at_the_conf_is_replaced_not_written_through(self):
        victim = self.tmp / "victim"
        victim.write_text("root's")
        (self.state / ".config/containers").mkdir(parents=True)
        os.symlink(victim, self.state / ".config/containers/storage.conf")
        self._run()
        self.assertEqual(victim.read_text(), "root's")
        self.assertFalse(
            (self.state / ".config/containers/storage.conf").is_symlink())

    def test_a_link_at_the_config_dir_is_refused(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        os.symlink(outside, self.state / ".config")
        with self.assertRaises(RuntimeError):
            self._run()
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
