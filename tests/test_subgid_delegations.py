#!/usr/bin/env python3
"""Single-gid subgid lines: what a workload requires, and what drifted.

podman numbers a rootless user's namespace by sorting its subgid ranges by
host id, and a workload's `user:G:1` delegations sort before its main range.
Adding or removing one shifts the group ids of the files already in the
workload's images and volumes. `delegated_gids` is the one rule for
"required" (the writer and the checker both use it); `subgid_delegation_check`
reports stale and pending lines; `validate` warns on them.
"""

import io
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import cmd_validate
import diagnose_subid
import ensure_container
import workload_lib
import workload_uid
from shares import Share
from workloadctl_core import WorkloadConfig

GROUPS = {"render": 105, "video": 39, "wl-share-media": 950}


def _getgrnam(name):
    if name not in GROUPS:
        raise KeyError(name)
    return types.SimpleNamespace(gr_gid=GROUPS[name], gr_name=name)


def _getgrgid(gid):
    for name, g in GROUPS.items():
        if g == gid:
            return types.SimpleNamespace(gr_gid=g, gr_name=name)
    raise KeyError(gid)


class DelegatedGidsTest(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(
            ensure_container.grp, "getgrnam", _getgrnam))

    def test_groups_in_order(self):
        cfg = {"security": {"extra_groups": ["video", "render"]}}
        self.assertEqual(ensure_container.delegated_gids(cfg), [39, 105])

    def test_no_security_table_needs_none(self):
        self.assertEqual(ensure_container.delegated_gids({}), [])

    def test_userns_host_needs_none(self):
        cfg = {"security": {"userns": "host", "extra_groups": ["render"]}}
        self.assertEqual(ensure_container.delegated_gids(cfg), [])

    def test_missing_group_is_skipped_and_reported(self):
        warned = []
        cfg = {"security": {"extra_groups": ["render", "nope", "video"]}}
        got = ensure_container.delegated_gids(cfg, warn=warned.append)
        self.assertEqual(got, [105, 39])
        self.assertEqual(
            warned, ["Group 'nope' not found, skipping subgid entry"])

    def test_missing_group_without_a_warn_is_silent(self):
        cfg = {"security": {"extra_groups": ["nope"]}}
        self.assertEqual(ensure_container.delegated_gids(cfg), [])

    def test_share_group_through_resolve_shares(self):
        from shares import resolve
        shares = {"media": Share("media", "/srv/media", 1)}
        cfg = {"security": {"extra_groups": ["render"]},
               "shares": [{"name": "media", "target": "/m",
                           "access": "write"}]}
        resolved = resolve(cfg, shares)
        self.assertEqual(
            ensure_container.delegated_gids(resolved), [105, 950])

    def test_duplicate_groups_once(self):
        cfg = {"security": {"extra_groups": ["render", "render"]}}
        self.assertEqual(ensure_container.delegated_gids(cfg), [105])


class WriterUsesTheRuleTest(unittest.TestCase):
    def test_configure_writes_the_delegated_gids_after_the_main_range(self):
        pw = types.SimpleNamespace(pw_uid=10005, pw_name="_wl-x")
        written = {}

        def fake_append(path, entries):
            written[path.name] = list(entries)

        cfg = {"security": {"extra_groups": ["video", "render"]}}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(ensure_container.grp, "getgrnam",
                                  _getgrnam), \
                mock.patch.object(ensure_container, "subuid_file",
                                  lambda: Path(d) / "subuid"), \
                mock.patch.object(ensure_container, "subgid_file",
                                  lambda: Path(d) / "subgid"), \
                mock.patch.object(ensure_container, "append_subid_entries",
                                  fake_append), \
                mock.patch.object(ensure_container, "subprocess",
                                  mock.MagicMock()), \
                mock.patch.object(ensure_container.ensure_common, "log"):
            ensure_container.configure_subuid_subgid(pw, cfg)
        start, count = workload_uid.derived_subid_range(10005)
        main = f"_wl-x:{start}:{count}"
        self.assertEqual(written["subgid"],
                         [main, "_wl-x:39:1", "_wl-x:105:1"])
        self.assertEqual(written["subuid"], [main])


MAIN = "_wl-x:600100000:65536"


def verdict(text, required=(), mapped=(), names=None):
    return diagnose_subid.subgid_delegation_check(
        text, "_wl-x", list(required), set(mapped), names)


class SubgidDelegationCheckTest(unittest.TestCase):
    def test_clean(self):
        ok, msg, _ = verdict(f"{MAIN}\n_wl-x:105:1\n", required=[105])
        self.assertTrue(ok)

    def test_one_stale(self):
        ok, msg, _ = verdict(f"_wl-x:966:1\n{MAIN}\n", names={966: "old"})
        self.assertFalse(ok)
        self.assertIn("966 (old)", msg)
        self.assertIn("Removing a delegation shifts the group ids", msg)
        self.assertNotIn("Adding", msg)
        self.assertIn('"When a delegated group changes"', msg)

    def test_one_pending(self):
        ok, msg, _ = verdict(MAIN + "\n", required=[105],
                             names={105: "render"})
        self.assertFalse(ok)
        self.assertIn("105 (render)", msg)
        self.assertIn("Adding a delegation shifts the group ids", msg)
        self.assertNotIn("Removing", msg)

    def test_both_together(self):
        ok, msg, _ = verdict(f"{MAIN}\n_wl-x:966:1\n", required=[105])
        self.assertFalse(ok)
        self.assertIn("966", msg)
        self.assertIn("105", msg)
        self.assertIn("Removing", msg)
        self.assertIn("Adding", msg)

    def test_extra_gidmaps_host_id_is_not_stale(self):
        ok, _, _ = verdict(f"{MAIN}\n_wl-x:950:1\n", mapped=[950])
        self.assertTrue(ok)

    def test_main_range_is_never_stale(self):
        ok, _, _ = verdict(MAIN + "\n")
        self.assertTrue(ok)

    def test_not_provisioned_is_clean(self):
        self.assertTrue(verdict("")[0])
        self.assertTrue(verdict("", required=[105])[0])
        # a single-gid line alone is not a main range either
        self.assertTrue(verdict("_wl-x:966:1\n", required=[105])[0])

    def test_only_this_users_lines_count(self):
        text = (f"{MAIN}\n_wl-y:600165536:65536\n_wl-y:966:1\n"
                f"_wl-xy:700:1\n_wl-x:105:1\n")
        self.assertTrue(verdict(text, required=[105])[0])
        # another user's main range does not provision this one
        self.assertTrue(verdict("_wl-y:600165536:65536\n",
                                required=[105])[0])

    def test_extra_gidmap_host_gids_parses_the_map_forms(self):
        got = diagnose_subid.extra_gidmap_host_gids(
            {"extra_gidmaps": ["+950:@950:1", "0:960:2", "{GID}:x:1"]})
        self.assertEqual(got, {950, 960, 961})


class ValidateSubgidTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(
            workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.subgid = self.tmp / "subgid"
        self.enterContext(mock.patch.object(
            workload_uid, "SUBGID_FILE", self.subgid))
        self.enterContext(mock.patch.object(
            ensure_container, "load_shares", lambda: ({}, [])))
        self.enterContext(mock.patch.object(
            ensure_container.grp, "getgrnam", _getgrnam))
        self.enterContext(mock.patch.object(
            ensure_container.grp, "getgrgid", _getgrgid))
        self.manager = mock.Mock()
        self.manager.get_all_configs.return_value = []
        (self.tmp / "app").mkdir()

    def _validate(self, groups, subgid):
        extra = ", ".join(f'"{g}"' for g in groups)
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
            f'\n[security]\nextra_groups = [{extra}]\n')
        self.subgid.write_text(subgid)
        config = WorkloadConfig("app")
        with redirect_stdout(io.StringIO()):
            return cmd_validate.validate_single(
                config, self.manager, json_mode=True)

    def _finding(self, res):
        return next((c for c in res["checks"]
                     if c["check"] == "subgid_delegations"), None)

    def test_pending_group_warns_and_still_passes(self):
        res = self._validate(["render"], "_wl-app:600100000:65536\n")
        c = self._finding(res)
        self.assertEqual(c["severity"], "warning")
        self.assertIs(c["passed"], False)
        self.assertIn("105 (render)", c["message"])
        self.assertEqual(res["errors"], 0)
        self.assertTrue(res["passed"])

    def test_stale_line_warns(self):
        res = self._validate(
            [], "_wl-app:966:1\n_wl-app:600100000:65536\n")
        c = self._finding(res)
        self.assertEqual(c["severity"], "warning")
        self.assertIn("966", c["message"])
        self.assertTrue(res["passed"])

    def test_matching_lines_report_nothing(self):
        res = self._validate(
            ["render"], "_wl-app:600100000:65536\n_wl-app:105:1\n")
        self.assertIsNone(self._finding(res))

    def test_missing_subgid_file_reports_nothing(self):
        res = self._validate(["render"], "")
        self.subgid.unlink()
        with redirect_stdout(io.StringIO()):
            res = cmd_validate.validate_single(
                WorkloadConfig("app"), self.manager, json_mode=True)
        self.assertIsNone(self._finding(res))


if __name__ == "__main__":
    unittest.main()
