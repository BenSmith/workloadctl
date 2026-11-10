"""Shifted images: the verdict over what the layers say, and the walk that
reads them from a fake store (no root: gids come from a table)."""

import json
import os
import tempfile
import unittest
from pathlib import Path

import diagnose_image_shift as dis
from diagnose_subid import image_shift_check

GROUPS = {12: "mail", 22: "utmp", 42: "shadow", 190: "systemd-journal",
          999: "app"}


def verdict(counts, groups=GROUPS, shadow=None, outside=0):
    return image_shift_check("image_shift", "img", counts, groups, shadow,
                             outside)


class ImageShiftCheckTest(unittest.TestCase):
    def test_clean(self):
        res = verdict({12: 1, 999: 1}, shadow=42)
        self.assertTrue(res[1])
        self.assertIsNone(res[3])

    def test_no_groups_is_not_judged(self):
        self.assertIsNone(verdict({14: 1}, groups={}))

    def test_histogram_names_the_offset(self):
        res = verdict({14: 1, 24: 3, 192: 1})
        self.assertFalse(res[1])
        self.assertIn("+2", res[2])
        self.assertNotIn("08-security.md", res[2])
        self.assertTrue(res[3].endswith("When a delegated group changes\"."))

    def test_negative_offset_is_signed(self):
        res = verdict({10: 1, 20: 3, 188: 1})
        self.assertIn("-2", res[2])

    def test_a_few_unknown_gids_are_not_a_finding(self):
        res = verdict({42: 5, 22: 3, 1018: 11}, shadow=42)
        self.assertTrue(res[1])
        res = verdict({22: 3, 1018: 11})
        self.assertTrue(res[1])

    def test_shadow_anchor_beats_a_tied_histogram(self):
        dense = {i: f"g{i}" for i in range(1, 60)}
        dense[42] = "shadow"
        res = verdict({43: 5, 44: 3, 5: 4}, groups=dense, shadow=43)
        self.assertFalse(res[1])
        self.assertIn("+1", res[2])
        self.assertIn("/etc/shadow", res[2])

    def test_shadow_match_is_clean_whatever_the_histogram(self):
        res = verdict({14: 1, 24: 3, 192: 1}, shadow=42)
        self.assertTrue(res[1])

    def test_outside_the_map_is_a_finding(self):
        res = verdict({12: 1}, shadow=42, outside=3)
        self.assertFalse(res[1])
        self.assertIn("3 files", res[2])

    def test_real_outputs_before_the_fix(self):
        pihole = {44: 4, 1002: 1}
        res = verdict(pihole, groups={**GROUPS, 1000: "pihole"}, shadow=44)
        self.assertIn("+2", res[2])
        jelly = {43: 5, 44: 3, 5: 4, 9: 1, 1019: 11}
        groups = {42: "shadow", 43: "utmp", 4: "adm", 8: "mail",
                  44: "video", 5: "tty", 9: "news"}
        res = verdict(jelly, groups=groups, shadow=43)
        self.assertFalse(res[1])
        self.assertIn("+1", res[2])

    def test_real_outputs_after_the_fix_are_clean(self):
        cases = [
            ({12: 1, 999: 1}, {12: "mail", 999: "caddy"}, None),
            ({12: 1, 190: 1, 22: 3}, GROUPS, None),
            ({1000: 1, 42: 4}, {42: "shadow", 1000: "pihole"}, 42),
            ({42: 5, 43: 3, 4: 4, 8: 1, 1018: 11},
             {42: "shadow", 43: "utmp", 4: "adm", 8: "mail"}, 42),
            ({12: 1, 190: 1, 22: 3, 7: 2, 998: 1},
             {12: "mail", 190: "j", 22: "utmp", 7: "lp", 998: "pa"}, None),
        ]
        for counts, groups, shadow in cases:
            with self.subTest(counts=counts):
                self.assertTrue(verdict(counts, groups, shadow)[1])


class FakeStore:
    """A store under a temp dir: layers hold files, `gids` holds the host
    gid of each (layer id, relative path)."""

    def __init__(self, test):
        self.tmp = Path(test.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.tmp / "state"
        self.root = self.state / ".local/share/containers/storage"
        (self.root / "overlay-layers").mkdir(parents=True)
        self.gids = {}
        self.recorded = []
        self.ids = []

    def layer(self, lid, files, gidmap=None, dirgid=None):
        diff = self.root / "overlay" / lid / "diff"
        diff.mkdir(parents=True)
        for rel, gid in files.items():
            path = diff / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
            self.gids[(lid, rel)] = gid
        for d in diff.rglob("*"):
            if d.is_dir():
                self.gids[(lid, str(d.relative_to(diff)))] = dirgid or ROOT
        entry = {"id": lid}
        if gidmap:
            entry["gidmap"] = gidmap
        self.recorded.append(entry)
        (self.root / "overlay-layers" / "layers.json").write_text(
            json.dumps(self.recorded))
        self.ids.append(lid)
        return diff

    def info(self, ids=None):
        dirs = [str(self.root / "overlay" / i / "diff")
                for i in (ids or reversed(self.ids))]
        return {"GraphDriver": {"Data": {
            "UpperDir": dirs[0], "LowerDir": ":".join(dirs[1:])}}}

    def gid_of(self, path):
        return self.lookup(path)

    def lookup(self, path):
        parts = Path(path).relative_to(self.root / "overlay").parts
        return self.gids[(parts[0], "/".join(parts[2:]))]

    def facts(self, gid_map, info=None, **kw):
        return dis.image_shift_facts(
            info or self.info(), str(self.state), gid_map,
            gid_of=self.gid_of, shadow_gid_of=self.shadow_gid_of, **kw)

    def shadow_gid_of(self, dir_fd, path):
        return self.lookup(path)


ROOT = 10000
MAP = [(0, ROOT, 1), (1, 5000, 100)]
GROUP_FILE = "root:x:0:\nmail:x:12:\nshadow:x:42:\napp:x:70:\n"


def host(ns):
    return 5000 + ns - 1


class ImageShiftFactsTest(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore(self)

    def base(self, shift=0, gidmap=None):
        """One layer whose files sit `shift` ns gids above the image's."""
        root = host(3) if gidmap else ROOT
        self.store.layer("l1", {
            "etc/group": root, "etc/shadow": host(42 + shift),
            "usr/bin/x": host(12 + shift), "usr/bin/y": host(70 + shift)},
            gidmap=gidmap, dirgid=root)
        (self.store.root / "overlay/l1/diff/etc/group").write_text(GROUP_FILE)

    def verdict(self):
        return image_shift_check("image_shift", "img",
                                 *self.store.facts(MAP))

    def test_no_shift(self):
        self.base()
        counts, groups, shadow, outside = self.store.facts(MAP)
        self.assertEqual((shadow, outside), (42, 0))
        self.assertEqual(counts, {12: 1, 70: 1, 42: 1})
        self.assertTrue(self.verdict()[1])

    def test_plus_one_shift(self):
        self.base(shift=1)
        res = self.verdict()
        self.assertFalse(res[1])
        self.assertIn("+1", res[2])

    def test_recorded_map_reads_clean(self):
        # Stored in a container's mapping: container gid c sits at ns c+3.
        self.base(shift=3, gidmap=[
            {"container_id": 0, "host_id": 3, "size": 90}])
        self.assertTrue(self.verdict()[1])

    def test_recorded_map_is_what_makes_it_clean(self):
        self.base(shift=3)
        self.assertFalse(self.verdict()[1])

    def test_files_outside_the_map(self):
        self.store.layer("l1", {"etc/group": ROOT, "etc/shadow": 7,
                                "usr/x": 9000})
        (self.store.root / "overlay/l1/diff/etc/group").write_text(GROUP_FILE)
        _, _, _, outside = self.store.facts(MAP)
        self.assertEqual(outside, 2)

    def test_symlinked_etc_is_not_followed(self):
        self.store.layer("l1", {"keep/group": ROOT, "usr/x": 5000})
        diff = self.store.root / "overlay/l1/diff"
        (diff / "keep/group").write_text(GROUP_FILE)
        os.symlink("keep", diff / "etc")
        self.store.gids[("l1", "etc")] = ROOT
        counts, groups, shadow, outside = self.store.facts(MAP)
        self.assertEqual(groups, {})
        self.assertIsNone(shadow)

    def test_layer_outside_the_state_dir_is_refused(self):
        other = Path(self.enterContext(tempfile.TemporaryDirectory()))
        diff = other / "overlay/l1/diff"
        (diff / "etc").mkdir(parents=True)
        (diff / "etc/group").write_text(GROUP_FILE)
        info = {"GraphDriver": {"Data": {"UpperDir": str(diff)}}}
        self.assertIsNone(dis.image_shift_facts(
            info, str(self.store.state), MAP, gid_of=lambda p: 0))

    def test_layer_symlinked_out_of_the_state_dir_is_refused(self):
        other = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (other / "diff").mkdir()
        link = self.store.root / "overlay" / "evil"
        link.mkdir(parents=True)
        os.symlink(other / "diff", link / "diff")
        info = {"GraphDriver": {"Data": {"UpperDir": str(link / "diff")}}}
        self.assertIsNone(dis.image_shift_facts(
            info, str(self.store.state), MAP, gid_of=lambda p: 0))

    def test_shared_layers_are_walked_once(self):
        self.base()
        calls = []
        cache = {}
        orig = self.store.gid_of
        self.store.gid_of = lambda p: (calls.append(p), orig(p))[1]
        self.store.facts(MAP, cache=cache)
        first = len(calls)
        self.store.facts(MAP, cache=cache)
        self.assertEqual(len(calls), first)


if __name__ == "__main__":
    unittest.main()
