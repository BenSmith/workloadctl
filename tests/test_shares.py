#!/usr/bin/env python3
"""Named shares (audit F3's second layer, and F14).

A share is a host directory some workloads use: its files carry a
category its members hold, so no other workload reaches them; writers are
in its group and readers have a read ACL and a read-only mount, so a reader
cannot plant a file. Each piece fails silently when missing: a mount
without the category, a writer without the group, a reader with write.
"""
import re
import shutil
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import diagnose_battery
import shares
import shares_setup
import validation
from container_run_args import label_level_args
from tests.test_generator import run_generator, write_config
from workload_mcs import CATEGORIES, WORKLOAD_CATEGORIES, mcs_level

DOWNLOADS = {"shares": {"downloads": {"path": "/var/mnt/downloads"}}}


def parsed(doc=DOWNLOADS):
    found, errors = shares.parse_shares(doc)
    assert not errors, errors
    return found


class Declaring(unittest.TestCase):

    def test_a_share_gets_a_category_above_the_workload_pairs(self):
        share = parsed()["downloads"]
        self.assertEqual(share.path, "/var/mnt/downloads")
        self.assertTrue(WORKLOAD_CATEGORIES <= share.category < CATEGORIES)
        self.assertEqual(share.category, shares.derived_category("downloads"))

    def test_a_category_can_be_given(self):
        doc = {"shares": {"a": {"path": "/a", "category": 700}}}
        self.assertEqual(parsed(doc)["a"].category, 700)

    def test_what_is_refused(self):
        for doc, words in (
                ({"shares": {"a": {"path": "rel"}}}, "absolute"),
                ({"shares": {"a": {"path": "/a", "category": 5}}},
                 "category must be"),
                ({"shares": {"Bad": {"path": "/a"}}}, "share name"),
                ({"shares": {"a" * 30: {"path": "/a"}}}, "share name"),
                ({"shares": {"a": {"path": "/a", "mode": 1}}}, "unknown"),
                ({"shares": {"a": {"path": "/a", "category": 600},
                             "b": {"path": "/b", "category": 600}}},
                 "one category"),
                ({"shares": {"a": {"path": "/m"},
                             "b": {"path": "/m/sub"}}}, "overlap")):
            _, errors = shares.parse_shares(doc)
            self.assertTrue(any(words in e for e in errors), (doc, errors))

    def test_no_file_is_no_shares(self):
        self.assertEqual(shares.load_shares(Path("/nonexistent/s.toml")),
                         ({}, []))


class Joining(unittest.TestCase):

    def config(self, *entries, vm=False):
        doc = {"workload": {"name": "w"}, "shares": list(entries)}
        doc["vm" if vm else "container"] = {"image": "x"}
        return doc

    def test_a_valid_membership_passes(self):
        doc = self.config({"name": "downloads", "target": "/d",
                           "access": "read", "subpath": "complete"})
        self.assertEqual(shares.validate_memberships(doc), [])

    def test_what_is_refused(self):
        for entry, words in (
                ({"name": "d", "target": "rel", "access": "read"}, "target"),
                ({"name": "d", "target": "/d", "access": "rw"}, "access"),
                ({"name": "d", "target": "/d", "access": "read",
                  "subpath": "../x"}, "subpath"),
                ({"target": "/d", "access": "read"}, "name")):
            errors = shares.validate_memberships(self.config(entry))
            self.assertTrue(any(words in e for e in errors), (entry, errors))

    def test_a_vm_is_refused_through_the_workload_validation(self):
        doc = self.config({"name": "d", "target": "/d", "access": "read"},
                          vm=True)
        self.assertTrue(any("container workloads" in e
                            for e in validation.validate_workload_config(doc)))


class Resolving(unittest.TestCase):

    def test_a_reader_mounts_read_only_and_joins_no_group(self):
        doc = {"workload": {"name": "j"}, "container": {"image": "x"},
               "shares": [{"name": "downloads", "target": "/media",
                           "access": "read", "subpath": "media"}]}
        got = shares.resolve(doc, parsed())
        self.assertEqual(got["storage"]["volumes"],
                         ["/var/mnt/downloads/media:/media:ro"])
        self.assertEqual(got["security"]["extra_groups"], [])
        self.assertEqual(got["security"]["share_categories"],
                         [parsed()["downloads"].category])
        self.assertNotIn("storage", doc)

    def test_a_writer_mounts_read_write_in_the_group(self):
        doc = {"workload": {"name": "t"}, "container": {"image": "x"},
               "security": {"extra_groups": ["render"]},
               "shares": [{"name": "downloads", "target": "/dl",
                           "access": "write"}]}
        got = shares.resolve(doc, parsed())
        self.assertEqual(got["storage"]["volumes"],
                         ["/var/mnt/downloads:/dl"])
        self.assertEqual(got["security"]["extra_groups"],
                         ["render", "wl-share-downloads"])

    def test_every_container_of_a_multi_workload_mounts_it(self):
        doc = {"workload": {"name": "p", "mode": "pod"},
               "containers": [{"name": "a", "container": {"image": "x"}},
                              {"name": "b", "container": {"image": "y"},
                               "storage": {"volumes": ["/v:/v"]}}],
               "shares": [{"name": "downloads", "target": "/dl",
                           "access": "read"}]}
        got = shares.resolve(doc, parsed())
        self.assertEqual([c["storage"]["volumes"] for c in got["containers"]],
                         [["/var/mnt/downloads:/dl:ro"],
                          ["/v:/v", "/var/mnt/downloads:/dl:ro"]])

    def test_an_undeclared_share_is_warned_about_and_left_out(self):
        said = []
        doc = {"workload": {"name": "j"}, "container": {"image": "x"},
               "shares": [{"name": "nope", "target": "/n", "access": "read"}]}
        got = shares.resolve(doc, parsed(), warn=said.append)
        self.assertEqual(got["storage"]["volumes"], [])
        self.assertEqual(got["security"]["share_categories"], [])
        self.assertTrue(said)

    def test_the_level_holds_the_pair_and_the_share(self):
        category = parsed()["downloads"].category
        args = label_level_args(10042, share_categories=[category])
        self.assertEqual(args, [f"--security-opt=label=level:"
                                f"{mcs_level(10042, [category])}"])
        self.assertIn(f",c{category}", args[0])


class Generated(unittest.TestCase):
    """shares.toml and two members through the generator."""

    def test_the_units_mount_the_share_at_its_level_with_the_group(self):
        conf, svc, users = (tempfile.mkdtemp() for _ in range(3))
        (Path(conf) / "shares.toml").write_text(
            '[shares.downloads]\npath = "/var/mnt/downloads"\n')
        write_config(conf, "torrent", """\
            [workload]
            name = "torrent"
            [container]
            image = "example.test/t"
            [[shares]]
            name = "downloads"
            target = "/downloads"
            access = "write"
            """)
        write_config(conf, "jelly", """\
            [workload]
            name = "jelly"
            [container]
            image = "example.test/j"
            [[shares]]
            name = "downloads"
            target = "/media"
            access = "read"
            subpath = "media"
            """)
        result = run_generator(conf, svc, users)
        self.assertEqual(result.returncode, 0, result.stderr)
        category = shares.derived_category("downloads")
        for name, volume in (("torrent", '"/var/mnt/downloads":"/downloads"'),
                             ("jelly",
                              '"/var/mnt/downloads/media":"/media":"ro"')):
            unit = (Path(svc) / f"workload-{name}.service").read_text()
            self.assertIn(f"--volume {volume}", unit)
            level = re.search(r"label=level:(\S+)", unit)[1]
            self.assertTrue(level.endswith(f",c{category}"), level)
        writer = (Path(users) / "workload-torrent.conf").read_text()
        reader = (Path(users) / "workload-jelly.conf").read_text()
        self.assertIn("m _wl-torrent wl-share-downloads", writer)
        self.assertNotIn("wl-share-downloads", reader)


class HostSetup(unittest.TestCase):

    def setUp(self):
        self.calls = []

        def run(argv, **kw):
            self.calls.append(argv)
            out = ""
            return subprocess.CompletedProcess(argv, 0, out, "")
        self.run = run
        self.enterContext(mock.patch.object(
            shares_setup.shutil, "which", return_value="/usr/bin/x"))
        # Fedora's: /var/mnt is labelled as /mnt.
        self.enterContext(mock.patch.object(
            shares_setup, "path_substitutions",
            return_value=[("/var/mnt", "/mnt")]))

    def member(self, name, access):
        return {"workload": {"name": name}, "container": {"image": "x"},
                "shares": [{"name": "downloads", "target": "/d",
                            "access": access}]}

    def apply(self, name, access, action, others):
        config = types.SimpleNamespace(name=name,
                                       config=self.member(name, access))
        shares_setup.apply_shares(
            config, action, run=self.run, shares=parsed(),
            configs={n: self.member(n, a) for n, a in others.items()})

    def has(self, *prefix):
        return [c for c in self.calls if c[:len(prefix)] == list(prefix)]

    def test_enable_labels_owns_and_gives_every_reader_its_acl(self):
        self.apply("torrent", "write", "enable",
                   {"jelly": "read", "smb": "read"})
        category = parsed()["downloads"].category
        self.assertEqual(self.has("semanage", "fcontext", "-a")[0],
                         ["semanage", "fcontext", "-a", "-t",
                          "container_file_t", "-r", f"s0:c{category}",
                          "/mnt/downloads(/.*)?"])
        self.assertTrue(self.has("restorecon", "-RF", "/var/mnt/downloads"))
        self.assertTrue(self.has("chgrp", "-R", "wl-share-downloads"))
        self.assertTrue(self.has("chmod", "-R", "g+rwX,o-rwx"))
        acls = {c[3] for c in self.has("setfacl", "-R", "-m")}
        self.assertEqual(acls, {"u:_wl-jelly:rX", "u:_wl-smb:rX"})
        defaults = {c[4] for c in self.has("setfacl", "-R", "-d", "-m")}
        self.assertEqual(defaults, acls)

    def test_a_reader_enabled_first_gets_its_own_acl(self):
        self.apply("jelly", "read", "enable", {})
        self.assertEqual({c[3] for c in self.has("setfacl", "-R", "-m")},
                         {"u:_wl-jelly:rX"})

    def test_a_writer_never_gets_a_read_acl(self):
        self.apply("torrent", "write", "enable", {"other": "write"})
        self.assertEqual(self.has("setfacl", "-R", "-m"), [])

    def test_disabling_a_reader_takes_its_acl_away(self):
        self.apply("jelly", "read", "disable", {"torrent": "write"})
        self.assertTrue(self.has("setfacl", "-R", "-x", "u:_wl-jelly"))
        self.assertEqual(self.has("semanage", "fcontext", "-d"), [])

    def test_the_last_member_out_removes_the_rule(self):
        self.apply("torrent", "write", "disable", {})
        self.assertEqual(self.has("semanage", "fcontext", "-d"),
                         [["semanage", "fcontext", "-d",
                           "/mnt/downloads(/.*)?"]])

    def test_a_refused_rule_is_not_reported_registered(self):
        def run(argv, **kw):
            self.calls.append(argv)
            refused = argv[:3] == ["semanage", "fcontext", "-a"]
            return subprocess.CompletedProcess(argv, 1 if refused else 0, "",
                                               "ValueError: conflicts")
        self.run = run
        with mock.patch.object(shares_setup, "info") as info, \
             mock.patch.object(shares_setup, "warn"):
            self.apply("torrent", "write", "enable", {})
        self.assertFalse(any("Registered" in c.args[0]
                             for c in info.call_args_list))


class Equivalences(unittest.TestCase):
    """semanage refuses a rule under an equivalence's alias: on the proving
    host (2026-10-14) a share at /var/mnt/audit-share got no rule, stayed
    mnt_t, and its writer could not create a file in it."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.files = self.root / "targeted" / "contexts" / "files"
        self.files.mkdir(parents=True)

    def test_a_path_under_an_alias_is_labelled_as_under_its_target(self):
        subs = [("/var/mnt", "/mnt"), ("/var/home", "/home")]
        self.assertEqual(shares_setup.labelled_as("/var/mnt/dl", subs),
                         "/mnt/dl")
        self.assertEqual(shares_setup.labelled_as("/var/mnt", subs), "/mnt")
        self.assertEqual(shares_setup.labelled_as("/var/mntx/dl", subs),
                         "/var/mntx/dl")
        self.assertEqual(shares_setup.labelled_as("/srv/dl", subs), "/srv/dl")

    def test_the_local_file_is_read_before_the_distributions(self):
        (self.files / "file_contexts.subs_dist").write_text(
            "# comment\n/var/mnt /mnt\n/var/home   /home\n")
        (self.files / "file_contexts.subs").write_text("/var/mnt/x /srv/x\n")
        subs = shares_setup.path_substitutions("targeted", root=self.root)
        self.assertEqual(subs, [("/var/mnt/x", "/srv/x"),
                                ("/var/mnt", "/mnt"), ("/var/home", "/home")])
        self.assertEqual(shares_setup.labelled_as("/var/mnt/x/y", subs),
                         "/srv/x/y")

    def test_no_files_no_substitutions(self):
        self.assertEqual(
            shares_setup.path_substitutions("targeted", root=self.root), [])


class Diagnosed(unittest.TestCase):

    def run_checks(self, label):
        checks = []

        def _check(name, passed, message, fix=None):
            checks.append((name, passed))
        config = types.SimpleNamespace(name="jelly", config={
            "shares": [{"name": "downloads", "target": "/m",
                        "access": "read"}]})
        with mock.patch.object(diagnose_battery.Path, "is_dir",
                               return_value=True):
            diagnose_battery._share_checks(
                config, _check, shares=parsed(),
                getxattr=lambda p, k: label.encode() + b"\0")
        return checks

    def test_the_shares_category_passes_and_another_fails(self):
        category = parsed()["downloads"].category
        ok = f"system_u:object_r:container_file_t:s0:c{category}"
        self.assertEqual(self.run_checks(ok), [("share[downloads]", True)])
        self.assertEqual(self.run_checks("system_u:object_r:x:s0"),
                         [("share[downloads]", False)])


class Wiring(unittest.TestCase):

    def test_enable_recreate_and_disable_set_shares_up(self):
        import cmd_disable
        import cmd_enable
        import cmd_lifecycle
        for module, action in ((cmd_enable, "enable"),
                               (cmd_lifecycle, "enable"),
                               (cmd_disable, "disable")):
            self.assertIn(f'apply_shares(config, "{action}")',
                          Path(module.__file__).read_text(), module.__name__)

    def test_diagnose_runs_the_share_check(self):
        text = Path(diagnose_battery.__file__).read_text()
        self.assertIn("_share_checks(config, _check)", text)


if __name__ == "__main__":
    unittest.main()
