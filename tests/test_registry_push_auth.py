#!/usr/bin/env python3
"""The homelab registry takes pushes only from `ci`, and CI always logs in.

Two halves that only work together (F25 in the 2026-10 audit: zot answered
anonymous pushes from anywhere on the LAN, and hosts accept the mirrored public
names unsigned):

  - zot's shipped config: anonymous read everywhere; `ci` may write only CI's
    own repositories; nothing grants a write that reaches a mirrored name. zot
    applies the longest matching pattern, so an entry that forgets
    `anonymousPolicy` would make that repository unreadable to the hosts.
  - every Forgejo step that writes to the registry (`podman push`, a `skopeo
    copy` to a floating or dated tag) passes the sealed login, in a step that
    refuses to run without it. A push step added without it would fail at
    push time with a 401; this fails here first.
"""
import json
import re
import tomllib
import unittest

from tests import REPO_ROOT as ROOT

ZOT = ROOT / "workloads" / "zot-registry"
WORKFLOWS = ROOT.parent / ".forgejo" / "workflows"

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


@unittest.skipUnless(WORKFLOWS.is_dir(),
                     "workflows absent (the image build copies workloadctl/ alone)")
class WorkflowLoginTests(unittest.TestCase):
    WRITE = re.compile(r"^\s*(sudo\s+)?(podman push|skopeo copy)\b")

    def steps(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            step, start = [], 0
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if re.match(r"\s*- name:", line):
                    if step:
                        yield path.name, start, step
                    step, start = [], n
                step.append(line)
            if step:
                yield path.name, start, step

    def test_every_registry_write_passes_the_sealed_login(self):
        writes = 0
        for name, start, step in self.steps():
            code = [ln for ln in step if not ln.strip().startswith("#")]
            uses = [ln for ln in code if self.WRITE.search(ln)]
            if not uses:
                continue
            with self.subTest(workflow=name, step_line=start):
                text = "\n".join(code)
                self.assertIn('test -s "${CREDS}/registry-auth"', text)
                self.assertIn(
                    'AUTH_ARGS=(--authfile "${CREDS}/registry-auth")', text)
                for ln in uses:
                    writes += 1
                    self.assertIn('"${AUTH_ARGS[@]}"', ln)
        self.assertGreater(writes, 0)


if __name__ == "__main__":
    unittest.main()
