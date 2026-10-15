#!/usr/bin/env python3
"""The homelab registry takes pushes only from `ci`.

One of two halves that only work together (F25 in the 2026-10 audit: zot answered
anonymous pushes from anywhere on the LAN, and hosts accept the mirrored public
names unsigned):

  - zot's shipped config: anonymous read everywhere; `ci` may write only CI's
    own repositories; nothing grants a write that reaches a mirrored name. zot
    applies the longest matching pattern, so an entry that forgets
    `anonymousPolicy` would make that repository unreadable to the hosts.
  - every Forgejo step that writes to the registry (`podman push`, a `skopeo
    copy` to a floating or dated tag) passes the sealed login, in a step that
    refuses to run without it. That half is the image repository's, whose
    suite holds it.
"""
import json
import tomllib
import unittest

from tests import REPO_ROOT as ROOT

ZOT = ROOT / "workloads" / "zot-registry"

CI_REPOS = {"workloads/**", "hypervisor-bootc", "hypervisor-amd",
            "hypervisor-nvidia", "fedora-bootc-minimal", "negativo-rpms"}
WRITES = {"create", "update", "delete"}


class ZotConfigTests(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads((ZOT / "config.json").read_text())
        self.http = self.cfg["http"]
        self.repos = self.http["accessControl"]["repositories"]

    def test_it_listens_on_loopback_only(self):
        self.assertEqual(self.http["address"], "127.0.0.1")

    def test_logins_come_from_the_mounted_htpasswd(self):
        path = self.http["auth"]["htpasswd"]["path"]
        toml = tomllib.loads((ZOT / "workload.toml").read_text())
        mounts = [v.split(":")[1] for v in toml["storage"]["volumes"]]
        self.assertIn(path, mounts)
        required = [f["path"] for f in toml["setup"]["required_files"]]
        self.assertIn("./htpasswd", required)

    def test_every_repository_is_anonymously_readable(self):
        for pattern, rule in self.repos.items():
            with self.subTest(pattern=pattern):
                self.assertEqual(rule.get("anonymousPolicy"), ["read"])

    def test_writes_go_to_ci_and_ci_repositories_only(self):
        writable = {}
        for pattern, rule in self.repos.items():
            self.assertNotIn("defaultPolicy", rule, pattern)
            self.assertFalse(WRITES & set(rule["anonymousPolicy"]), pattern)
            for policy in rule.get("policies", []):
                if WRITES & set(policy["actions"]):
                    writable[pattern] = policy["users"]
        self.assertEqual(set(writable), CI_REPOS)
        for pattern, users in writable.items():
            self.assertEqual(users, ["ci"], pattern)
        self.assertNotIn("adminPolicy", self.http["accessControl"])


if __name__ == "__main__":
    unittest.main()
