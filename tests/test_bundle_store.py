#!/usr/bin/env python3
"""bundle_store: safe unpack and copy, root-run files, the record, drift,
the swap and the staging sweep."""

import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bundle_store
import workload_lib
from bundle_fixtures import bundle_tar
from bundle_store import BundleError


class _Roots(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.local = self.tmp / "etc/workloadctl/bundles"
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_LOCAL_BUNDLES_DIR", self.local))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_BUNDLES_DIR", self.tmp / "usr"))
        self.dest = self.tmp / "dest"
        self.dest.mkdir()

    def tar(self, data: bytes) -> Path:
        p = self.tmp / "b.tar"
        p.write_bytes(data)
        return p


class ExtractTar(_Roots):

    def test_tree_and_modes_kept(self):
        bundle_store.extract_tar(self.tar(bundle_tar(
            {"workload.toml": "x", "cloud-init/user-data": "y", "setup.sh": "z"},
            {"setup.sh": 0o4775})), self.dest)
        self.assertEqual((self.dest / "cloud-init/user-data").read_text(), "y")
        self.assertEqual((self.dest / "setup.sh").stat().st_mode & 0o7777, 0o755)

    def _special(self, kind, **kw):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo(kw.pop("name", "evil"))
            info.type = kind
            for k, v in kw.items():
                setattr(info, k, v)
            tf.addfile(info)
        return self.tar(buf.getvalue())

    def test_symlink_refused_by_name(self):
        with self.assertRaisesRegex(BundleError, "links or special files: evil"):
            bundle_store.extract_tar(self._special(tarfile.SYMTYPE, linkname="/etc/shadow"), self.dest)

    def test_hardlink_refused(self):
        with self.assertRaisesRegex(BundleError, "links or special"):
            bundle_store.extract_tar(self._special(tarfile.LNKTYPE, linkname="x"), self.dest)

    def test_device_refused(self):
        with self.assertRaisesRegex(BundleError, "links or special"):
            bundle_store.extract_tar(self._special(tarfile.CHRTYPE), self.dest)

    def test_traversal_refused(self):
        for name in ("../escape", "/abs/escape"):
            with self.subTest(name), self.assertRaisesRegex(BundleError, "leave the bundle"):
                bundle_store.extract_tar(self.tar(bundle_tar({name: "x"})), self.dest)
        self.assertFalse((self.tmp / "escape").exists())


class CopyDir(_Roots):

    def test_copies_and_masks_modes(self):
        src = self.tmp / "src"
        (src / "sub").mkdir(parents=True)
        (src / "sub/f").write_text("a")
        (src / "setup.sh").write_text("b")
        os.chmod(src / "setup.sh", 0o6777)
        bundle_store.copy_dir(src, self.dest)
        self.assertEqual((self.dest / "sub/f").read_text(), "a")
        self.assertEqual((self.dest / "setup.sh").stat().st_mode & 0o7777, 0o755)

    def test_symlink_refused(self):
        src = self.tmp / "src"
        src.mkdir()
        (src / "link").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(BundleError, "link"):
            bundle_store.copy_dir(src, self.dest)

    def test_symlinked_dir_refused(self):
        src = self.tmp / "src"
        src.mkdir()
        (src / "d").symlink_to(self.tmp)
        with self.assertRaisesRegex(BundleError, "not a regular file or dir: d"):
            bundle_store.copy_dir(src, self.dest)


class RootRun(_Roots):

    def bundle(self, toml: str, **files) -> Path:
        (self.dest / "workload.toml").write_text(toml)
        for rel, content in files.items():
            (self.dest / rel).write_text(content)
        return self.dest

    def test_setup_build_script_and_policy(self):
        b = self.bundle('[host]\nsetup = "setup.sh"\n[build]\nscript = "build.sh"\n',
                        **{"setup.sh": "s", "build.sh": "b", "policy.cil": "p"})
        self.assertEqual(sorted(bundle_store.root_run_files(b)),
                         ["build.sh", "policy.cil", "setup.sh"])

    def test_containerfile_is_not_root_run(self):
        b = self.bundle("[build]\n", Containerfile="FROM x")
        self.assertEqual(bundle_store.root_run_files(b), {})
        self.assertEqual(bundle_store.containerfiles(b), ["Containerfile"])

    def test_instance_refs_count(self):
        # An instance TOML keeps naming setup.sh after the bundle's own
        # workload.toml drops it; the file still runs as root at enable.
        b = self.bundle("", **{"setup.sh": "s"})
        self.assertEqual(list(bundle_store.root_run_files(b, {"setup.sh"})), ["setup.sh"])

    def test_absolute_ref_listed(self):
        b = self.bundle('[host]\nsetup = "/usr/bin/true"\n')
        self.assertEqual(bundle_store.root_run_files(b), {"/usr/bin/true": "absolute"})

    def test_escaping_ref_ignored(self):
        b = self.bundle('[host]\nsetup = "../outside"\n')
        (self.tmp / "outside").write_text("x")
        self.assertEqual(bundle_store.root_run_files(b), {})

    def test_changed_rule(self):
        old = {"setup.sh": "a", "policy.cil": "p"}
        self.assertEqual(bundle_store.changed_root_run(old, old), [])
        self.assertEqual(bundle_store.changed_root_run({"setup.sh": "b", "policy.cil": "p"}, old),
                         ["setup.sh"])
        self.assertEqual(bundle_store.changed_root_run({"build.sh": "c"}, old), ["build.sh"])
        self.assertEqual(bundle_store.changed_root_run({}, old), [])


class RecordAndDrift(_Roots):

    def setUp(self):
        super().setUp()
        self.b = self.local / "app"
        self.b.mkdir(parents=True)
        (self.b / "workload.toml").write_text("a")
        (self.b / "f").write_text("b")

    def test_round_trip(self):
        files = bundle_store.tree_hashes(self.b)
        rec = bundle_store.make_record("dir:/x", bundle_store.dir_digest(files), files, {})
        bundle_store.write_record("app", rec)
        self.assertEqual(bundle_store.read_record("app"), rec)
        self.assertEqual(sorted(p.name for p in self.local.iterdir()), ["app", "app.origin.json"])
        self.assertEqual(workload_lib.loose_local_bundles(), [])

    def test_drift(self):
        rec = {"files": bundle_store.tree_hashes(self.b)}
        self.assertEqual(bundle_store.drift(self.b, rec), [])
        (self.b / "f").write_text("edited")
        (self.b / "new").write_text("n")
        (self.b / "workload.toml").unlink()
        self.assertEqual(bundle_store.drift(self.b, rec), ["f", "new", "workload.toml"])

    def test_dir_digest_follows_content(self):
        d1 = bundle_store.dir_digest(bundle_store.tree_hashes(self.b))
        (self.b / "f").write_text("edited")
        self.assertNotEqual(d1, bundle_store.dir_digest(bundle_store.tree_hashes(self.b)))


class SwapAndSweep(_Roots):

    def test_swap_replaces_and_cleans(self):
        (self.local / "app").mkdir(parents=True)
        (self.local / "app/old").write_text("o")
        staged = bundle_store.new_staging("app")
        (staged / "new").write_text("n")
        bundle_store.swap_in(staged, "app")
        self.assertEqual(os.listdir(self.local / "app"), ["new"])
        self.assertEqual(list(bundle_store.staging_root().iterdir()), [])

    def test_staging_is_outside_the_root(self):
        self.assertNotEqual(bundle_store.staging_root().parent / "bundles", bundle_store.staging_root())
        self.assertFalse(bundle_store.staging_root().is_relative_to(self.local))

    def test_sweep_removes_dead_pids_only(self):
        root = bundle_store.staging_root()
        live = root / f"app.{os.getpid()}"
        dead = root / "app.999999999"
        dead_old = root / "app.999999999.old"
        for d in (live, dead, dead_old):
            d.mkdir(parents=True)
        bundle_store.sweep_staging()
        self.assertEqual(sorted(p.name for p in root.iterdir()), [live.name])

    def test_remove_bundle(self):
        (self.local / "app").mkdir(parents=True)
        bundle_store.write_record("app", {"files": {}})
        bundle_store.remove_bundle("app")
        self.assertEqual(list(self.local.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
