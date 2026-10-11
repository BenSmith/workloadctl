#!/usr/bin/env python3
"""[[secrets.files]] are copied where their container can read them.

The 2026-10-11 security audit (F19): a [[secrets.files]] credential was
bind-mounted from systemd's /run/credentials/<unit>/, labelled
init_var_run_t, and the container got EACCES reading it (AVC container_t
read on init_var_run_t). workload-write-env now copies each one, at every
start, into the workload's runtime dir, and the mount relabels the copy with
:Z (tests.test_generator holds the mount).

The copy is written by root into a directory the workload user owns, which
is the class of the audit's F28 and F29: every case below with a planted
link checks that what it points at is left alone.
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path

import secrets_env
from secrets_env import (
    EnvFileError,
    secret_file_specs,
    write_secret_files,
)
from secrets_template import secret_files_dir

UID, GID = os.getuid(), os.getgid()
CTR = "workload-app"


class _Root(unittest.TestCase):

    def setUp(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runtime_root = tmp / "run-user"
        (self.runtime_root / str(UID)).mkdir(parents=True)
        self.creds = tmp / "creds"
        self.creds.mkdir()
        (self.creds / "tls-cert").write_text("CERT")
        (self.creds / "db-pass").write_text("PASS")
        self.outside = tmp / "outside"
        self.outside.mkdir()
        self.victim = self.outside / "victim"
        self.victim.write_text("root's own file")

    def _write(self, specs):
        write_secret_files(UID, GID, CTR, specs, str(self.creds),
                           runtime_root=str(self.runtime_root))

    def _dir(self):
        return secret_files_dir(UID, CTR, str(self.runtime_root))

    def _victim_untouched(self):
        self.assertEqual(self.victim.read_text(), "root's own file")
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()),
                         ["victim"])


class TestTheCopy(_Root):

    def test_each_credential_is_copied_with_its_mode(self):
        self._write([("tls-cert", "ro"), ("db-pass", "rw")])
        d = self._dir()
        self.assertEqual((d / "tls-cert").read_text(), "CERT")
        self.assertEqual((d / "db-pass").read_text(), "PASS")
        self.assertEqual(stat.S_IMODE((d / "tls-cert").stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE((d / "db-pass").stat().st_mode), 0o644)
        for p in (d, d.parent):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700, p)

    def test_each_start_writes_a_fresh_copy(self):
        self._write([("tls-cert", "ro"), ("db-pass", "ro")])
        (self.creds / "tls-cert").write_text("ROTATED")
        self._write([("tls-cert", "ro")])
        self.assertEqual((self._dir() / "tls-cert").read_text(), "ROTATED")
        self.assertFalse((self._dir() / "db-pass").exists(),
                         "a credential no longer declared must not stay")

    def test_no_files_declared_removes_the_copy(self):
        self._write([("tls-cert", "ro")])
        self._write([])
        self.assertFalse(self._dir().exists())

    def test_a_credential_not_loaded_is_refused(self):
        with self.assertRaises(EnvFileError):
            self._write([("absent", "ro")])

    def test_a_credential_name_is_a_name(self):
        for bad in ("../x", "a/b", "", "x y"):
            with self.subTest(credential=bad):
                entry = {"secrets": {"files": [
                    {"credential": bad or "", "path": "/p"}]}}
                if not bad:
                    self.assertEqual(secret_file_specs(entry), [])
                    continue
                with self.assertRaises(EnvFileError):
                    secret_file_specs(entry)


class TestPlantedLinks(_Root):

    def test_a_linked_secrets_dir_is_not_followed(self):
        (self.runtime_root / str(UID) / "workload-secrets").symlink_to(
            self.outside)
        with self.assertRaises(OSError):
            self._write([("tls-cert", "ro")])
        self._victim_untouched()

    def test_a_linked_container_dir_is_unlinked_not_followed(self):
        top = self.runtime_root / str(UID) / "workload-secrets"
        top.mkdir(mode=0o700)
        (top / CTR).symlink_to(self.outside)
        self._write([("tls-cert", "ro")])
        self._victim_untouched()
        self.assertFalse((top / CTR).is_symlink())
        self.assertEqual((top / CTR / "tls-cert").read_text(), "CERT")

    def test_a_linked_container_dir_is_not_emptied_when_none_declared(self):
        top = self.runtime_root / str(UID) / "workload-secrets"
        top.mkdir(mode=0o700)
        (top / CTR).symlink_to(self.outside)
        self._write([])
        self._victim_untouched()


class TestTheEntrypointPath(unittest.TestCase):
    """write_secrets_env takes its root from WORKLOAD_RUNTIME_ROOT, as the
    env file takes its dir from WORKLOAD_ENV_DIR; on a host both default to
    the paths the generator mounts."""

    def test_the_default_root_is_the_one_the_generator_mounts(self):
        self.assertEqual(
            secret_files_dir(10000, CTR),
            Path("/run/user/10000/workload-secrets/workload-app"))
        if "WORKLOAD_RUNTIME_ROOT" not in os.environ:
            self.assertEqual(secrets_env.RUNTIME_ROOT, "/run/user")


if __name__ == "__main__":
    unittest.main()
