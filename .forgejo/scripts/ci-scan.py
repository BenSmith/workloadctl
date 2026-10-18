#!/usr/bin/env python3
"""Judge a grype scan of an image: fail on a critical vulnerability that has
a fix, unless the allowlist accepts it, and fail on a scan that did not
happen.

    ci-scan.py judge IMAGE SCAN.json ALLOWLIST
    ci-scan.py report IMAGE SCAN.json ALLOWLIST

A scan that errored, or wrote no `matches`, is a failure, never a pass with
nothing found: a scanner that cannot read an image reports the same nothing
as a clean one (audit F26 read failed scans as 0 for weeks).

`report` says the same things as warnings and always exits 0: the daily
scan of every image the bundles run (scan-images.yml), which nothing waits
on.

The allowlist has one accepted vulnerability per line: its id, an image
pattern (fnmatch, `*` for any), and the reason. `#` starts a comment.
"""
import fnmatch
import json
import sys

FAIL_SEVERITY = "Critical"


def read_allowlist(text):
    entries = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        words = line.split(None, 2)
        if len(words) < 3:
            raise ValueError(f"allowlist line {number}: want ID IMAGE REASON")
        entries.append((words[0], words[1]))
    return entries


def accepted(vuln_id, image, allowlist):
    return any(vuln_id == vid and fnmatch.fnmatchcase(image, pattern)
               for vid, pattern in allowlist)


def failures(scan, image, allowlist):
    """The fixable criticals the allowlist does not accept, as
    (id, package, installed, fixed in)."""
    if not isinstance(scan, dict) or not isinstance(scan.get("matches"), list):
        raise ValueError("the scan has no matches list: it did not run")
    out = set()
    for match in scan["matches"]:
        vuln = match.get("vulnerability") or {}
        fix = vuln.get("fix") or {}
        if (vuln.get("severity") != FAIL_SEVERITY
                or fix.get("state") != "fixed"
                or accepted(vuln.get("id", ""), image, allowlist)):
            continue
        artifact = match.get("artifact") or {}
        out.add((vuln.get("id", "?"), artifact.get("name", "?"),
                 artifact.get("version", "?"),
                 ", ".join(fix.get("versions") or ())))
    return sorted(out)


def summary(scan):
    counts = {}
    for match in scan["matches"]:
        severity = (match.get("vulnerability") or {}).get("severity", "?")
        counts[severity] = counts.get(severity, 0) + 1
    return ", ".join(f"{n} {s.lower()}" for s, n in sorted(counts.items()))


def main(argv):
    if len(argv) != 5 or argv[1] not in ("judge", "report"):
        print(__doc__, file=sys.stderr)
        return 2
    mode, image, scan_path, allow_path = argv[1:]
    level, failed = ("error", 1) if mode == "judge" else ("warning", 0)
    try:
        with open(scan_path) as f:
            scan = json.load(f)
        with open(allow_path) as f:
            allowlist = read_allowlist(f.read())
        found = failures(scan, image, allowlist)
    except (OSError, ValueError) as e:
        print(f"::{level}::scan of {image} failed: {e}")
        return failed
    print(f"{image}: {summary(scan) or 'nothing found'}")
    for vuln_id, package, version, fixed in found:
        print(f"::{level}::{image}: {vuln_id} (critical) in {package} "
              f"{version}, fixed in {fixed}")
    return failed if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
