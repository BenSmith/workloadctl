#!/usr/bin/env python3
"""`workloadctl bundle add|update|rm`, through the parser, with a stub skopeo.

The rules under test are the threat model's: the trust policy is the bundle
policy, root-run files need --allow-host-setup from an OCI source (and on
update only when new or changed), shipped names are refused, drift refuses
before anything is fetched, and rm refuses while an instance uses the bundle.
"""

import fcntl
import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import bundle_fetch
import bundle_store
import cmd_bundle
import cmd_catalog
import workload_lib
from bundle_fixtures import bundle_tar, install_stub_skopeo, make_layout, stub_env
from cli_parser import build_parser

REF = "localhost:5000/b/app:1"
TOML = '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
SETUP_TOML = TOML + '\n[host]\nsetup = "setup.sh"\n'


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.local = self.tmp / "etc/workloadctl/bundles"
        self.shipped = self.tmp / "usr"
        self.shipped.mkdir()
        self.conf = self.tmp / "workloads.d"
        self.conf.mkdir()
        self.policy = self.tmp / "bundle-policy.json"
        self.policy.write_text("{}")
        self.layout = self.tmp / "published"
        self.argv = self.tmp / "argv"
        install_stub_skopeo(self.tmp / "bin")
        for target, attr, value in (
                (workload_lib, "WORKLOAD_LOCAL_BUNDLES_DIR", self.local),
                (workload_lib, "WORKLOAD_BUNDLES_DIR", self.shipped),
                (workload_lib, "WORKLOAD_CONFIG_DIR", self.conf),
                (bundle_store, "LOCK_PATH", self.tmp / "lock"),
                (cmd_bundle, "require_root", lambda: None),
                (cmd_bundle, "_FETCH_TMP", str(self.tmp)),
        ):
            self.enterContext(mock.patch.object(target, attr, value))
        # fetch's default policy argument was bound at import
        self.enterContext(mock.patch.object(
            cmd_bundle, "fetch",
            lambda ref, work: bundle_fetch.fetch(ref, work, self.policy)))
        self.enterContext(mock.patch.dict(
            "os.environ", stub_env(self.tmp / "bin", self.layout, self.argv)))

    def publish(self, files: dict, modes=None) -> str:
        import shutil
        shutil.rmtree(self.layout, ignore_errors=True)
        return make_layout(self.layout, bundle_tar(files, modes))

    def run_cli(self, *argv) -> tuple[int, str, str]:
        args = build_parser().parse_args(["bundle", *argv])
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with redirect_stdout(out), redirect_stderr(err):
            try:
                args.func(args, None)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def ok(self, *argv) -> str:
        code, out, err = self.run_cli(*argv)
        self.assertEqual(code, 0, err)
        return out

    def refused(self, *argv, match: str) -> str:
        code, _, err = self.run_cli(*argv)
        self.assertEqual(code, 1)
        self.assertRegex(err, match)
        return err

    def record(self, name="app") -> dict:
        return json.loads((self.local / f"{name}.origin.json").read_text())

    def instance(self, name, bundle="app", extra=""):
        d = self.conf / name
        d.mkdir()
        (d / "workload.toml").write_text(
            f'[workload]\nname = "{name}"\nbundle = "{bundle}"\n{extra}')

    def assert_nothing_left(self):
        self.assertFalse((self.local / "app").exists())
        staging = bundle_store.staging_root()
        self.assertEqual(list(staging.iterdir()) if staging.exists() else [], [])


class Add(_Base):

    def test_oci_add_installs_and_records(self):
        digest = self.publish({"workload.toml": TOML, "cloud-init/user-data": "x"})
        self.ok("add", REF)
        self.assertEqual((self.local / "app/cloud-init/user-data").read_text(), "x")
        rec = self.record()
        self.assertEqual((rec["source"], rec["digest"]), (f"oci:{REF}", digest))
        self.assertIn("--policy", self.argv.read_text().split("\n"))
        self.assertEqual(workload_lib.bundle_names(), ["app"])
        self.assertFalse(bundle_store.staging_root().exists())

    def test_policy_refusal_leaves_nothing(self):
        self.publish({"workload.toml": TOML})
        os.environ["STUB_FAIL"] = "A signature was required, but no signature exists"
        self.refused("add", REF, match="no signature exists")
        self.assert_nothing_left()
        self.assertFalse(bundle_store.staging_root().exists())

    def test_missing_policy_refuses(self):
        self.publish({"workload.toml": TOML})
        self.policy.unlink()
        self.refused("add", REF, match="no bundle trust policy")
        self.assert_nothing_left()

    def test_bare_name_refused_without_network(self):
        self.refused("add", "app", match="not a registry reference")
        self.assertFalse(self.argv.exists())

    def test_shipped_name_refused(self):
        (self.shipped / "app").mkdir()
        (self.shipped / "app/workload.toml").write_text(TOML)
        self.publish({"workload.toml": TOML})
        self.refused("add", REF, match="shipped bundle is named 'app'")
        self.assertFalse(self.argv.exists())

    def test_existing_local_dir_refused(self):
        (self.local / "app").mkdir(parents=True)
        self.refused("add", REF, match="already exists")

    def test_no_workload_toml_refused(self):
        self.publish({"README": "x"})
        self.refused("add", REF, match="no top-level workload.toml")
        self.assert_nothing_left()

    def test_setup_script_needs_the_flag(self):
        self.publish({"workload.toml": SETUP_TOML, "setup.sh": "#!/bin/sh\n"})
        self.refused("add", REF, match="run as host root: setup.sh")
        self.assert_nothing_left()
        self.ok("add", REF, "--allow-host-setup")

    def test_build_script_needs_the_flag(self):
        self.publish({"workload.toml": TOML + '\n[build]\nscript = "build.sh"\n',
                      "build.sh": "#!/bin/sh\n"})
        self.refused("add", REF, match="build.sh")

    def test_policy_cil_needs_the_flag(self):
        self.publish({"workload.toml": TOML, "policy.cil": "()"})
        self.refused("add", REF, match="policy.cil")

    def test_containerfile_listed_not_gated(self):
        self.publish({"workload.toml": TOML, "Containerfile": "FROM x"})
        self.assertIn("rootful container at `workloadctl build`: Containerfile",
                      self.ok("add", REF))

    def test_dir_add_lists_but_does_not_gate(self):
        src = self.tmp / "mybundle"
        src.mkdir()
        (src / "workload.toml").write_text(SETUP_TOML)
        (src / "setup.sh").write_text("#!/bin/sh\n")
        out = self.ok("add", str(src))
        self.assertIn("setup.sh", out)
        rec = self.record("mybundle")
        self.assertEqual(rec["source"], f"dir:{src}")
        self.assertEqual(rec["digest"], bundle_store.dir_digest(rec["files"]))

    def test_file_source_refused(self):
        f = self.tmp / "bundle.tar"
        f.write_text("x")
        self.refused("add", str(f), match="is not a directory")
        self.assertFalse(self.argv.exists())

    def test_name_flag(self):
        self.publish({"workload.toml": TOML})
        self.ok("add", REF, "--name", "other")
        self.assertTrue((self.local / "other/workload.toml").is_file())

    def test_catalog_shows_origin(self):
        digest = self.publish({"workload.toml": TOML})
        self.ok("add", REF)
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_catalog.cmd_catalog(build_parser().parse_args(["catalog", "--json"]), None)
        entry = json.loads(out.getvalue())[0]
        self.assertEqual(entry["origin"], f"oci {REF}@{digest}")


class Update(_Base):

    def setUp(self):
        super().setUp()
        self.d1 = self.publish({"workload.toml": SETUP_TOML, "setup.sh": "v1"})
        self.ok("add", REF, "--allow-host-setup")

    def test_new_digest_installs(self):
        d2 = self.publish({"workload.toml": SETUP_TOML, "setup.sh": "v1", "f": "new"})
        out = self.ok("update", "app")
        self.assertIn(f"{self.d1} → {d2}", out)
        self.assertEqual(self.record()["digest"], d2)

    def test_same_digest_is_current(self):
        self.assertIn("is current", self.ok("update", "app"))

    def test_changed_setup_needs_the_flag_again(self):
        self.publish({"workload.toml": SETUP_TOML, "setup.sh": "v2"})
        self.refused("update", "app", match="new or changed.*setup.sh")
        self.assertEqual((self.local / "app/setup.sh").read_text(), "v1")
        self.ok("update", "app", "--allow-host-setup")

    def test_instance_reference_keeps_setup_gated(self):
        # the bundle drops the line, but an instance's TOML still names setup.sh
        self.instance("app1", extra='[host]\nsetup = "setup.sh"\n')
        self.publish({"workload.toml": TOML, "setup.sh": "v2"})
        self.refused("update", "app", match="setup.sh")

    def test_drift_refused_then_forced(self):
        (self.local / "app/setup.sh").write_text("edited")
        self.publish({"workload.toml": SETUP_TOML, "setup.sh": "v1", "f": "x"})
        self.refused("update", "app", match="edited since.*setup.sh")
        self.ok("update", "app", "--force")
        self.assertEqual((self.local / "app/setup.sh").read_text(), "v1")

    def test_drift_checked_before_the_digest(self):
        (self.local / "app/extra").write_text("x")
        self.refused("update", "app", match="edited since.*extra")
        self.assertIn("Restored", self.ok("update", "app", "--force"))
        self.assertFalse((self.local / "app/extra").exists())

    def test_hand_made_dir_refused(self):
        (self.local / "mine").mkdir()
        self.refused("update", "mine", match="wasn't added with")

    def test_never_added_refused(self):
        self.refused("update", "nothere", match="no bundle 'nothere' was added")

    def test_unparseable_instance_toml_skipped(self):
        # one broken instance TOML can't block updating the bundle
        (self.conf / "broken").mkdir()
        (self.conf / "broken/workload.toml").write_text("[workload\n")
        self.instance("app1")
        self.publish({"workload.toml": SETUP_TOML, "setup.sh": "v1", "f": "x"})
        self.assertIn("Updated", self.ok("update", "app"))

    def test_shipped_name_now_refused(self):
        (self.shipped / "app").mkdir()
        self.refused("update", "app", match="shipped bundle is now named")

    def test_lists_instances(self):
        self.instance("app1")
        self.publish({"workload.toml": SETUP_TOML, "setup.sh": "v1", "f": "x"})
        self.assertIn("Instances using it: app1", self.ok("update", "app"))

    def test_new_source_is_recorded(self):
        ref2 = "localhost:5000/b/app:2"
        self.publish({"workload.toml": SETUP_TOML, "setup.sh": "v1", "f": "x"})
        self.ok("update", "app", ref2)
        self.assertEqual(self.record()["source"], f"oci:{ref2}")


class DirUpdate(_Base):

    def setUp(self):
        super().setUp()
        self.src = self.tmp / "app"
        self.src.mkdir()
        (self.src / "workload.toml").write_text(TOML)
        self.ok("add", str(self.src))

    def test_update_follows_the_dir(self):
        (self.src / "workload.toml").write_text(TOML + "# edited\n")
        self.assertIn("Updated", self.ok("update", "app"))
        self.assertIn("# edited", (self.local / "app/workload.toml").read_text())

    def test_second_dir_becomes_the_source(self):
        src2 = self.tmp / "app2"
        src2.mkdir()
        (src2 / "workload.toml").write_text(TOML + "# two\n")
        self.ok("update", "app", str(src2))
        self.assertEqual(self.record()["source"], f"dir:{src2}")

    def test_gone_dir_refused(self):
        import shutil
        shutil.rmtree(self.src)
        self.refused("update", "app", match=f"{self.src} is gone")


class Rm(_Base):

    def setUp(self):
        super().setUp()
        self.publish({"workload.toml": TOML})
        self.ok("add", REF)

    def test_refused_while_in_use(self):
        self.instance("app1")
        err = self.refused("rm", "app", match="instances use 'app': app1;")
        self.assertIn(str(self.conf), err)
        self.assertTrue((self.local / "app").is_dir())

    def test_removes_dir_and_record(self):
        self.ok("rm", "app")
        self.assertEqual(list(self.local.iterdir()), [])

    def test_hand_made_refused(self):
        (self.local / "mine").mkdir()
        self.refused("rm", "mine", match="wasn't added with")

    def test_waits_for_the_lock(self):
        result = {}
        with open(bundle_store.LOCK_PATH, "a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            t = threading.Thread(target=lambda: result.update(r=self.run_cli("rm", "app")))
            t.start()
            t.join(0.5)
            self.assertTrue(t.is_alive(), "rm ran while another verb held the lock")
            self.assertTrue((self.local / "app").is_dir())
        t.join(10)
        self.assertEqual(result["r"][0], 0, result["r"][2])
        self.assertFalse((self.local / "app").exists())


if __name__ == "__main__":
    unittest.main()
