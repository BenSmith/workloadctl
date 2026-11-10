#!/usr/bin/env python3
"""A filtered workload's image fetch (lib/image_fetch.py and its worker).

The decision per pull policy, the transient unit's argv, the order of the
leftover cleanup, the free-space refusal per filesystem, and the files root
reads from the fetch identity's cache. The seam (systemd-run from a unit's
start step, the dynamic uid outside the filter, the load) is proved on a
real host by tests/manual/container_egress_rig.py.
"""
import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import image_fetch
import image_fetch_worker
from image_ref import names_registry, source_reference, split_reference

IMAGE = "registry.example/team/app:1.0"
OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64


class _Config:
    name = "wl"
    username = "_wl-wl"
    uid = 10001

    def __init__(self, home):
        self.home_dir = home


class FetchDecisionTest(unittest.TestCase):
    """fetch_image per policy, with the unit, the load and the store faked."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.tmp / "home").mkdir()
        (self.tmp / "root").mkdir()
        self.config = _Config(str(self.tmp / "home"))
        self.calls = []
        patch = lambda *a, **k: self.enterContext(mock.patch.object(*a, **k))
        patch(image_fetch, "LOCK_DIR", self.tmp / "lock")
        patch(image_fetch, "CACHE_ROOT", self.tmp / "cache")
        patch(image_fetch, "record_path",
              lambda name: self.tmp / "root" / image_fetch.RECORD_NAME)
        patch(image_fetch, "stop_leftover_unit",
              lambda name: self.calls.append("stop"))
        self.pod = mock.Mock()
        patch(image_fetch.Podman, "for_user", return_value=self.pod)
        self.inspect = patch(image_fetch, "inspect",
                             return_value={"digest": NEW, "size": 100})
        self.run_worker = patch(image_fetch, "run_worker")
        self.load = patch(image_fetch, "_load_fetched")
        patch(image_fetch, "check_space")
        self.warn = patch(image_fetch, "warn")
        patch(image_fetch, "info")

    def store(self, *ids):
        self.pod.image_id.side_effect = list(ids)

    def record(self, digest, image_id):
        (self.tmp / "root" / image_fetch.RECORD_NAME).write_text(json.dumps(
            {IMAGE: {"digest": digest, "image_id": image_id}}))

    def fetch(self, policy):
        with mock.patch.object(image_fetch, "replace_file_atomically",
                               self._write):
            return image_fetch.fetch_image(self.config, "wl", IMAGE, policy)

    def _write(self, path, content, **kw):
        Path(path).write_text(content)

    def assert_copied(self):
        self.run_worker.assert_called_once_with(
            "wl", ["copy", f"registry.example/team/app@{NEW}", IMAGE],
            image_fetch.COPY_MAX_SEC)
        self.load.assert_called_once()

    def assert_not_copied(self):
        self.run_worker.assert_not_called()
        self.load.assert_not_called()

    def test_missing_with_the_image_asks_no_registry(self):
        self.store("id-1")
        self.assertEqual(self.fetch("missing"), "unchanged")
        self.inspect.assert_not_called()
        self.assert_not_copied()

    def test_missing_without_the_image_fetches_and_records(self):
        self.store("", "id-new")
        self.assertEqual(self.fetch("missing"), "loaded")
        self.assert_copied()
        self.assertEqual(image_fetch.read_record("wl")[IMAGE],
                         {"digest": NEW, "image_id": "id-new"})

    def test_newer_with_matching_record_and_store_does_nothing(self):
        self.record(NEW, "id-1")
        self.store("id-1")
        self.assertEqual(self.fetch("newer"), "unchanged")
        self.inspect.assert_called_once()
        self.assert_not_copied()

    def test_newer_with_a_new_digest_fetches(self):
        self.record(OLD, "id-1")
        self.store("id-1", "id-2")
        self.assertEqual(self.fetch("newer"), "loaded")
        self.assert_copied()

    def test_newer_with_no_record_fetches_once(self):
        self.store("id-1", "id-2")
        self.assertEqual(self.fetch("newer"), "loaded")
        self.assert_copied()

    def test_newer_when_the_store_lost_the_recorded_image_fetches(self):
        self.record(NEW, "id-1")
        self.store("id-other", "id-1")
        self.assertEqual(self.fetch("newer"), "loaded")
        self.assert_copied()

    def test_always_and_update_skip_a_matching_digest_too(self):
        for policy in ("always", "update"):
            with self.subTest(policy=policy):
                self.record(NEW, "id-1")
                self.store("id-1")
                self.assertEqual(self.fetch(policy), "unchanged")
                self.assert_not_copied()

    def test_newer_with_registry_down_uses_the_local_image(self):
        self.store("id-1")
        self.inspect.side_effect = image_fetch.WorkerFailed("no route")
        self.assertEqual(self.fetch("newer"), "unchanged")
        self.assertIn("outside the workload's filter",
                      self.warn.call_args.args[0])
        self.assert_not_copied()

    def test_registry_down_fails_without_a_local_image_or_for_always(self):
        for policy, local in (("newer", ""), ("missing", ""),
                              ("always", "id-1"), ("update", "id-1")):
            with self.subTest(policy=policy):
                self.store(local)
                self.inspect.side_effect = image_fetch.WorkerFailed("no route")
                with self.assertRaises(image_fetch.ImageFetchError) as cm:
                    self.fetch(policy)
                self.assertIn("outside the workload's filter", str(cm.exception))
                self.assertIn("no route", str(cm.exception))

    def test_a_load_that_leaves_no_name_fails(self):
        self.store("", "")
        with self.assertRaises(image_fetch.ImageFetchError):
            self.fetch("missing")

    def test_never_is_not_a_fetch_policy(self):
        with self.assertRaises(ValueError):
            self.fetch("never")

    def test_leftover_unit_is_stopped_before_the_cache_is_cleared(self):
        cache = self.tmp / "cache" / "wl"
        cache.mkdir(parents=True)
        (cache / "image.tar").write_bytes(b"x")
        real_clear = image_fetch.clear_cache

        def clear(name):
            self.calls.append("clear")
            real_clear(name)

        self.store("id-1")
        with mock.patch.object(image_fetch, "clear_cache", clear):
            self.fetch("missing")
        self.assertEqual(self.calls[:2], ["stop", "clear"])
        self.assertFalse(cache.exists())

    def test_lock_is_released_when_the_fetch_returns(self):
        """update restarts the unit after fetch_image returns, and the unit's
        own fetch step takes the same lock."""
        self.store("id-1")
        self.fetch("missing")
        import fcntl
        fd = os.open(image_fetch.lock_path("wl"), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


class WorkerArgvTest(unittest.TestCase):

    def test_the_transient_unit(self):
        argv = image_fetch.worker_argv("wl", ["inspect", IMAGE], 60)
        self.assertEqual(argv[0], "systemd-run")
        self.assertIn("--wait", argv)
        self.assertNotIn("--pipe", argv)
        self.assertIn("--unit=workload-image-fetch-wl.service", argv)
        props = [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]
        self.assertIn("DynamicUser=yes", props)
        self.assertIn("CacheDirectory=workloadctl-fetch/wl", props)
        self.assertIn("RuntimeMaxSec=60", props)
        self.assertFalse([p for p in props if p.startswith(("User=", "Group="))])
        self.assertEqual(argv[-3:], [image_fetch.WORKER, "inspect", IMAGE])

    def test_skopeo_inspect_takes_no_credentials(self):
        self.assertEqual(image_fetch_worker.inspect_argv(IMAGE),
                         ["/usr/bin/skopeo", "inspect", "--no-creds",
                          "--no-tags", f"docker://{IMAGE}"])

    def test_skopeo_copy(self):
        argv = image_fetch_worker.copy_argv("/c", "r.example/a@" + NEW,
                                            "r.example/a:1")
        self.assertEqual(argv[:3], ["/usr/bin/skopeo", "--tmpdir", "/c"])
        self.assertIn("--src-no-creds", argv)
        self.assertIn("--remove-signatures", argv)
        self.assertEqual(argv[-2:], [f"docker://r.example/a@{NEW}",
                                     "oci-archive:/c/image.tar:r.example/a:1"])


class WorkerTest(unittest.TestCase):

    def test_summary_of_inspect(self):
        out = json.dumps({"Digest": NEW, "LayersData": [{"Size": 10},
                                                        {"Size": 5}]})
        self.assertEqual(image_fetch_worker.summarize(out),
                         {"digest": NEW, "size": 15})

    def test_unknown_layer_size_gives_no_size(self):
        for layers in ([{"Size": -1}], [{}], None):
            out = json.dumps({"Digest": NEW, "LayersData": layers})
            self.assertIsNone(image_fetch_worker.summarize(out)["size"])

    def test_no_digest_is_an_error(self):
        with self.assertRaises(image_fetch_worker.WorkerError):
            image_fetch_worker.summarize(json.dumps({"LayersData": []}))

    def test_failure_writes_the_reason_for_root(self):
        with tempfile.TemporaryDirectory() as cache, \
                mock.patch.dict(os.environ, {"CACHE_DIRECTORY": cache}), \
                mock.patch.object(image_fetch_worker.subprocess, "run",
                                  return_value=mock.Mock(
                                      returncode=1, stdout="",
                                      stderr="manifest unknown")), \
                contextlib.redirect_stdout(None):
            rc = image_fetch_worker.main(["w", "inspect", IMAGE])
            self.assertEqual(rc, 1)
            self.assertEqual(Path(cache, "error").read_text(),
                             "manifest unknown")


class FreeSpaceTest(unittest.TestCase):
    GIB = 2**30

    def test_separate_filesystems(self):
        size = self.GIB
        ok_cache, ok_vol = (1, 2 * size), (2, (1 + image_fetch.UNPACKED_RATIO) * size)
        self.assertEqual(image_fetch.space_shortfalls(size, ok_cache, ok_vol), [])
        short = image_fetch.space_shortfalls(size, (1, size), ok_vol)
        self.assertEqual(len(short), 1)
        self.assertIn("fetch cache", short[0])
        short = image_fetch.space_shortfalls(size, ok_cache, (2, size))
        self.assertEqual(len(short), 1)
        self.assertIn("workload volume", short[0])

    def test_one_filesystem_holds_the_archive_during_the_load(self):
        size = self.GIB
        need = (2 + image_fetch.UNPACKED_RATIO) * size
        self.assertEqual(image_fetch.space_shortfalls(size, (1, need), (1, need)), [])
        self.assertTrue(image_fetch.space_shortfalls(size, (1, need - 1),
                                                     (1, need - 1)))

    def test_refusal_names_the_image(self):
        config = _Config("/")
        with mock.patch.object(image_fetch, "_free", return_value=(1, 0)):
            with self.assertRaises(image_fetch.ImageFetchError) as cm:
                image_fetch.check_space(config, IMAGE, self.GIB)
        self.assertIn(IMAGE, str(cm.exception))


class CacheFileTest(unittest.TestCase):
    """Root opens what the fetch identity wrote, never through a link."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(image_fetch, "CACHE_ROOT", self.tmp))
        (self.tmp / "wl").mkdir()

    def test_regular_file(self):
        (self.tmp / "wl" / "inspect.json").write_text("{}")
        self.assertEqual(image_fetch._read_cache_file("wl", "inspect.json"), "{}")

    def test_link_is_refused(self):
        (self.tmp / "target").write_text("secret")
        (self.tmp / "wl" / "image.tar").symlink_to(self.tmp / "target")
        with self.assertRaises(OSError):
            image_fetch._open_cache_file("wl", "image.tar")

    def test_fifo_is_refused(self):
        os.mkfifo(self.tmp / "wl" / "image.tar")
        with self.assertRaises(OSError):
            image_fetch._open_cache_file("wl", "image.tar")

    def test_linked_cache_directory_is_refused(self):
        (self.tmp / "elsewhere").mkdir()
        (self.tmp / "elsewhere" / "image.tar").write_text("x")
        (self.tmp / "wl").rmdir()
        (self.tmp / "wl").symlink_to(self.tmp / "elsewhere")
        with self.assertRaises(OSError):
            image_fetch._open_cache_file("wl", "image.tar")


class LoadLeftoversTest(unittest.TestCase):

    def test_only_regular_podman_temp_files_go(self):
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as other:
            home, other = Path(home), Path(other)
            (home / "podman123").write_bytes(b"x")
            (home / "podman-keep").write_bytes(b"x")
            (other / "victim").write_bytes(b"x")
            (home / "podman456").symlink_to(other / "victim")
            image_fetch.clear_load_leftovers(home)
            self.assertFalse((home / "podman123").exists())
            self.assertTrue((home / "podman-keep").exists())
            self.assertTrue((home / "podman456").is_symlink())
            self.assertTrue((other / "victim").exists())


class ReferenceTest(unittest.TestCase):

    def test_split(self):
        self.assertEqual(split_reference("r.example:5000/a/b:1"),
                         ("r.example:5000/a/b", "1", ""))
        self.assertEqual(split_reference("r.example:5000/a/b"),
                         ("r.example:5000/a/b", "", ""))
        self.assertEqual(split_reference(f"r.example/a:1@{NEW}"),
                         ("r.example/a", "1", NEW))

    def test_source_is_pinned_to_the_inspected_digest(self):
        self.assertEqual(source_reference("r.example:5000/a:1", NEW),
                         f"r.example:5000/a@{NEW}")

    def test_names_registry(self):
        for image in ("docker.io/library/nginx", "r.example:5000/a",
                      "localhost/a:1"):
            self.assertTrue(names_registry(image), image)
        for image in ("nginx", "library/nginx:1", "team/app"):
            self.assertFalse(names_registry(image), image)


if __name__ == "__main__":
    unittest.main()
