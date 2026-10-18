#!/usr/bin/env python3
"""`ci-scan.py`: what fails an image build's scan.

    python3 .forgejo/scripts/test_ci_scan.py
"""
import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load():
    spec = importlib.util.spec_from_file_location("ci_scan",
                                                  HERE / "ci-scan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan = _load()


def match(vid, severity="Critical", state="fixed", versions=("1.2",)):
    return {"vulnerability": {"id": vid, "severity": severity,
                              "fix": {"state": state,
                                      "versions": list(versions)}},
            "artifact": {"name": "openssl", "version": "1.0"}}


class Judging(unittest.TestCase):

    def test_a_fixable_critical_fails(self):
        got = scan.failures({"matches": [match("CVE-1")]}, "img", [])
        self.assertEqual(got, [("CVE-1", "openssl", "1.0", "1.2")])

    def test_unfixed_or_lesser_ones_do_not(self):
        doc = {"matches": [match("CVE-1", state="not-fixed"),
                           match("CVE-2", severity="High"),
                           match("CVE-3", state="wont-fix")]}
        self.assertEqual(scan.failures(doc, "img", []), [])

    def test_the_allowlist_accepts_by_id_and_image(self):
        allow = scan.read_allowlist(
            "CVE-1 registry.local/workloads/jelly* upstream ships it\n"
            "# a comment\n\nCVE-2 * accepted everywhere\n")
        doc = {"matches": [match("CVE-1"), match("CVE-2"), match("CVE-3")]}
        got = scan.failures(doc, "registry.local/workloads/jellyfin:latest",
                            allow)
        self.assertEqual([g[0] for g in got], ["CVE-3"])
        got = scan.failures(doc, "registry.local/workloads/caddy:latest",
                            allow)
        self.assertEqual([g[0] for g in got], ["CVE-1", "CVE-3"])

    def test_an_allowlist_line_needs_a_reason(self):
        with self.assertRaises(ValueError):
            scan.read_allowlist("CVE-1 *\n")

    def test_a_scan_that_did_not_run_fails_not_passes(self):
        for doc in ({}, {"matches": None}, [], None, {"descriptor": {}}):
            with self.assertRaises(ValueError):
                scan.failures(doc, "img", [])


class Main(unittest.TestCase):

    def _run(self, doc, allow="", mode="judge"):
        with tempfile.TemporaryDirectory() as tmp:
            s, a = Path(tmp) / "s.json", Path(tmp) / "a.txt"
            if doc is not None:
                s.write_text(json.dumps(doc) if not isinstance(doc, str)
                             else doc)
            a.write_text(allow)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = scan.main(["ci-scan.py", mode, "img", str(s), str(a)])
            self.out = out.getvalue()
            return rc

    def test_clean_passes(self):
        self.assertEqual(self._run({"matches": [match("C", "High")]}), 0)

    def test_a_finding_fails(self):
        self.assertEqual(self._run({"matches": [match("C")]}), 1)

    def test_no_scan_file_or_garbage_fails(self):
        self.assertEqual(self._run(None), 1)
        self.assertEqual(self._run("not json"), 1)

    def test_report_warns_of_a_finding_and_passes(self):
        self.assertEqual(self._run({"matches": [match("C")]},
                                   mode="report"), 0)
        self.assertIn("::warning::img: C (critical)", self.out)
        self.assertNotIn("::error::", self.out)

    def test_report_warns_of_a_scan_that_did_not_run(self):
        self.assertEqual(self._run("not json", mode="report"), 0)
        self.assertIn("::warning::scan of img failed", self.out)

    def test_the_shipped_allowlist_parses(self):
        scan.read_allowlist((HERE.parent / "cve-allowlist.txt").read_text())


class Workflow(unittest.TestCase):
    """build-workload-images.yml runs the scan, before the push, weekly."""

    def setUp(self):
        self.text = (HERE.parent / "workflows" /
                     "build-workload-images.yml").read_text()

    def test_every_bundle_is_rebuilt_weekly(self):
        self.assertRegex(self.text, r"\n  schedule:\n    - cron: '[^']+'\n")

    def test_the_scan_judges_each_image_before_it_is_pushed(self):
        scan_at = self.text.index("ci-scan.py judge")
        self.assertLess(self.text.index("Build image"), scan_at)
        self.assertLess(scan_at, self.text.index("podman push"))
        self.assertIn(".forgejo/cve-allowlist.txt", self.text[scan_at:])

    def test_a_missing_scanner_or_a_failed_scan_stops_the_job(self):
        self.assertIn("command -v grype", self.text)
        self.assertRegex(self.text, r"if ! sudo (?:env [^\n]*?)?grype "
                                    r"(?:[^\n]*\\\n)*[^\n]*; then\n"
                                    r"[^\n]*\n\s*exit 1")

    def test_ci_runs_these_tests(self):
        self.assertIn("python3 .forgejo/scripts/test_ci_scan.py", self.text)


class Runners(unittest.TestCase):
    """Each runner bundle installs the scanner the workflows call. The
    forge's runner had none on 2026-10-14, and the workload image build
    refuses to push an image it has not scanned."""

    BUNDLES = ("forgejo-runner",)

    def _packages(self, bundle):
        text = (HERE.parents[1] / "workloads" / bundle
                / "cloud-init" / "user-data").read_text()
        command = text.split("dnf install -y --skip-broken", 1)[1]
        command = command.split("\n\n", 1)[0].replace("\\\n", " ")
        return command.split()

    def test_every_runner_installs_grype(self):
        for bundle in self.BUNDLES:
            with self.subTest(bundle=bundle):
                self.assertIn("grype", self._packages(bundle))


if __name__ == "__main__":
    os.chdir(HERE)
    unittest.main()
