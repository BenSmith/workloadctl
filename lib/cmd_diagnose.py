"""
cmd_diagnose — explain why a workload isn't healthy.

The command: root check, config load, one run of the battery in
lib/diagnose_battery.py, and the rendering — a symbol per check, the fixes for
what failed or warns, and the exit status. `doctor` runs the same battery.
"""
import json
import sys

from cmd_validate import load_config_or_exit
from diagnose_battery import collect_diagnose_checks, warning_count_text
from workloadctl_core import WorkloadManager, require_root


def _print_numbered(heading, entries):
    print(heading)
    for i, c in enumerate(entries, 1):
        print(f"  {i}. {c['message']}")
        if "fix" in c:
            print(f"     {c['fix']}")
    print()


def cmd_diagnose(args, manager: WorkloadManager):
    """Diagnose workload runtime setup (user, subids, linger, SELinux)"""
    require_root()
    config = load_config_or_exit(args.workload, json_mode=args.json)

    checks, passed = collect_diagnose_checks(config, manager)
    checks_passed = sum(1 for c in checks if c["passed"])
    checks_total = len(checks)
    warned = [c for c in checks if c.get("warning")]

    if args.json:
        print(json.dumps({
            "workload": config.name,
            "passed": passed,
            "checks_passed": checks_passed,
            "checks_total": checks_total,
            "checks_warned": len(warned),
            "checks": checks
        }, indent=2))
        sys.exit(0 if passed else 1)

    print(f"Diagnosing workload: {config.name}")
    print()
    for c in checks:
        symbol = "✗" if not c["passed"] else "!" if c.get("warning") else "✓"
        print(f"{symbol} {c['message']}")
        if "fix" in c and (not c["passed"] or c.get("warning")):
            print(f"  Fix: {c['fix']}")

    print()
    summary = f"Checks: {checks_passed}/{checks_total} passed"
    if warned:
        summary += f", {warning_count_text(len(warned))}"
    print(summary)
    print()

    if not passed:
        _print_numbered("Issues found:", [c for c in checks if not c["passed"]])
    if warned:
        _print_numbered("Warnings:", warned)
    if not passed:
        sys.exit(1)

    # "healthy" alone would read as "running" on a workload that is off —
    # the same confusion the folded check exists to remove.
    state = "" if config.enabled else " (disabled — nothing is running)"
    count = f" ({warning_count_text(len(warned))})" if warned else ""
    print(f"✓ All checks passed{count} - workload is healthy{state}")
    sys.exit(0)
