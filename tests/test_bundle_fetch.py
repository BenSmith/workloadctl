#!/usr/bin/env python3
"""bundle_fetch: ref parsing, the skopeo call, and reading the layout back."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bundle_fetch
from bundle_fetch import BundleFetchError, parse_ref, read_layout, ref_name
from bundle_fixtures import bundle_tar, install_stub_skopeo, make_layout, stub_env


class ParseRef(unittest.TestCase):

    def test_qualified_refs_pass(self):
        for ref in ("registry.local/bundles/vm-base:1",
                    "localhost/vm-base:latest",
                    "localhost:5000/vm-base:1",
                    "ghcr.io/o/vm-base@sha256:" + "a" * 64):
            self.assertEqual(parse_ref(ref), ref)

    def test_bare_and_short_names_refused(self):
        for ref in ("forgejo", "forgejo:1", "library/forgejo:1", "ben/vm-base:1"):
            with self.assertRaises(ValueError, msg=ref):
                parse_ref(ref)

    def test_tag_or_digest_required(self):
        for ref in ("registry.local/vm-base", "localhost:5000/vm-base",
                    "registry.local/vm-base@sha256:short"):
            with self.assertRaises(ValueError, msg=ref):
                parse_ref(ref)

    def test_ref_name(self):
        self.assertEqual(ref_name("localhost:5000/b/vm-base:1"), "vm-base")
        self.assertEqual(ref_name("ghcr.io/o/x@sha256:" + "a" * 64), "x")


class ReadLayout(unittest.TestCase):

    def setUp(self):
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.tar = bundle_tar({"workload.toml": "[workload]\n"})

    def test_good_layout(self):
        digest = make_layout(self.dir, self.tar)
        got = read_layout(self.dir)
        self.assertEqual(got.digest, digest)
        self.assertEqual(got.tar.read_bytes(), self.tar)

    def test_wrong_artifact_type(self):
        make_layout(self.dir, self.tar, artifact_type="application/vnd.other")
        with self.assertRaisesRegex(BundleFetchError, "not a workloadctl bundle"):
            read_layout(self.dir)

    def test_missing_artifact_type(self):
        make_layout(self.dir, self.tar, artifact_type=None)
        with self.assertRaisesRegex(BundleFetchError, "not a workloadctl bundle"):
            read_layout(self.dir)

    def test_octet_stream_layer_refused(self):
        make_layout(self.dir, self.tar, layer_types=("application/octet-stream",))
        with self.assertRaisesRegex(BundleFetchError, "exactly one layer"):
            read_layout(self.dir)

    def test_two_layers_refused(self):
        make_layout(self.dir, self.tar, layer_types=(bundle_fetch.LAYER_TYPE,) * 2)
        with self.assertRaisesRegex(BundleFetchError, "exactly one layer"):
            read_layout(self.dir)

    def test_tampered_layer_refused(self):
        make_layout(self.dir, self.tar)
        blob = next(p for p in (self.dir / "blobs/sha256").iterdir()
                    if p.read_bytes() == self.tar)
        blob.write_bytes(self.tar[:-1] + b"x")
        with self.assertRaisesRegex(BundleFetchError, "doesn't match"):
            read_layout(self.dir)

    def _index(self, edit):
        index = json.loads((self.dir / "index.json").read_text())
        edit(index)
        (self.dir / "index.json").write_text(json.dumps(index))

    def test_two_manifests_refused(self):
        make_layout(self.dir, self.tar)
        self._index(lambda i: i["manifests"].append(i["manifests"][0]))
        with self.assertRaisesRegex(BundleFetchError, "expected one manifest, found 2"):
            read_layout(self.dir)

    def test_tampered_manifest_refused(self):
        digest = make_layout(self.dir, self.tar)
        mpath = self.dir / "blobs/sha256" / digest.split(":")[1]
        mpath.write_text(mpath.read_text().replace(bundle_fetch.LAYER_TYPE, "x"))
        with self.assertRaisesRegex(BundleFetchError, f"manifest {digest} doesn't match"):
            read_layout(self.dir)

    def test_malformed_digest_refused(self):
        make_layout(self.dir, self.tar)
        self._index(lambda i: i["manifests"][0].update(digest="sha256:../../index.json"))
        with self.assertRaisesRegex(BundleFetchError, "bad digest in layout"):
            read_layout(self.dir)

    def test_missing_layer_blob_refused(self):
        make_layout(self.dir, self.tar)
        next(p for p in (self.dir / "blobs/sha256").iterdir()
             if p.read_bytes() == self.tar).unlink()
        with self.assertRaisesRegex(BundleFetchError, "bundle layer missing"):
            read_layout(self.dir)

    def test_partial_layout_refused(self):
        # what a refused skopeo copy leaves: an empty blobs/, no index.json
        (self.dir / "blobs").mkdir()
        with self.assertRaisesRegex(BundleFetchError, "unreadable OCI layout"):
            read_layout(self.dir)


class Fetch(unittest.TestCase):
    """Through a stub skopeo on PATH."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.src = self.tmp / "src"
        self.digest = make_layout(self.src, bundle_tar({"workload.toml": ""}))
        install_stub_skopeo(self.tmp / "bin")
        self.argv = self.tmp / "argv"
        self.policy = self.tmp / "bundle-policy.json"
        self.policy.write_text("{}")
        self.work = self.tmp / "work"
        self.work.mkdir()

    def _fetch(self, fail=""):
        env = stub_env(self.tmp / "bin", self.src, self.argv, fail)
        with mock.patch.dict("os.environ", env):
            return bundle_fetch.fetch("localhost:5000/b:1", self.work, self.policy)

    def test_copies_under_the_bundle_policy(self):
        self.assertEqual(self._fetch().digest, self.digest)
        self.assertEqual(self.argv.read_text().split("\n")[:5],
                         ["--policy", str(self.policy), "copy", "--remove-signatures",
                          "docker://localhost:5000/b:1"])

    def test_refusal_carries_stderr(self):
        with self.assertRaisesRegex(BundleFetchError, "no signature exists"):
            self._fetch(fail="A signature was required, but no signature exists")

    def test_skopeo_missing_or_hung(self):
        for exc, match in ((FileNotFoundError(), "skopeo is not installed"),
                           (subprocess.TimeoutExpired("skopeo", 1), "timed out after")):
            with self.subTest(match), \
                    mock.patch.object(bundle_fetch.subprocess, "run", side_effect=exc), \
                    self.assertRaisesRegex(BundleFetchError, match):
                self._fetch()

    def test_missing_policy_refuses_before_skopeo(self):
        self.policy.unlink()
        with self.assertRaisesRegex(BundleFetchError, "no bundle trust policy"):
            self._fetch()
        self.assertFalse(self.argv.exists())


if __name__ == "__main__":
    unittest.main()
