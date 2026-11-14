#!/usr/bin/env python3
"""uid_reuse_rig.py — does a workload that gets a purged workload's uid keep
its user manager?

logind keeps a user's record for UserStopDelaySec (10 s) after its manager
is told to stop. A user created with that uid inside the window is filed
under the old name: logind looks for linger under that name, finds none,
and stops the new user's manager at its next clean-up, taking
/run/user/<uid> with it, and the new workload's restarts fail with
226/NAMESPACE. Purge and cleanup wait for logind to drop the uid
(workload_uid.wait_logind_release) before userdel frees it.

    sudo python3 tests/manual/uid_reuse_rig.py

Purges `rig-uid-a`, creates `rig-uid-b` at once, and checks that b got a's
uid, that logind files that uid under b's name with linger, and that b's
manager and workload survive a logind clean-up. On a build without the wait
the logind rows fail. The manager rows may not catch the kill: logind's
clean-up does not always reach the stale user inside the rig's 15 s.
Needs the workloadctl RPM and anonymous docker.io.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

IMAGE = "docker.io/library/alpine:latest"
NAMES = ("rig-uid-a", "rig-uid-b")
RESULTS = []


def run(argv, timeout=120):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout)


def record(label, ok, detail=""):
    RESULTS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          + (f": {detail}" if detail else ""), flush=True)


def write(name):
    d = Path("/etc/workloads.d") / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "workload.toml").write_text(
        f'[workload]\nname = "{name}"\nenabled = false\n\n'
        f'[container]\nimage = "{IMAGE}"\npull = "missing"\n'
        'command = ["sh", "-c", "exec sleep 1000000000"]\n')


def uid(name):
    out = run(["id", "-u", f"_wl-{name}"]).stdout.strip()
    return int(out) if out else None


def logind(u):
    out = run(["loginctl", "show-user", str(u), "-p", "Name",
               "-p", "Linger"]).stdout
    return dict(line.split("=", 1) for line in out.split())


def active(unit):
    return run(["systemctl", "is-active", unit]).stdout.strip() == "active"


def healthy(name, timeout=240):
    # A Type=exec unit reads active while its image is still being pulled.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if run(["workloadctl", "health", name]).returncode == 0:
            return True
        time.sleep(3)
    return False


def cleanup():
    for name in NAMES:
        run(["workloadctl", "disable", "--purge", name], timeout=180)
        run(["systemctl", "reset-failed", f"workload-{name}.service"])
        run(["rm", "-rf", f"/etc/workloads.d/{name}"])


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    measure()
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} rows passed")
    sys.exit(0 if all(RESULTS) else 1)


def measure():
    print("== premises")
    record("no rig workload is left over",
           not any(Path("/etc/workloads.d", n).exists() for n in NAMES))
    if not all(RESULTS):
        return
    try:
        write("rig-uid-a")
        r = run(["workloadctl", "enable", "rig-uid-a"], timeout=300)
        old = uid("rig-uid-a")
        record("premise: rig-uid-a comes up",
               r.returncode == 0 and healthy("rig-uid-a"),
               (r.stdout + r.stderr)[-400:] if r.returncode else f"uid {old}")
        if not all(RESULTS):
            return

        print("\n== purge rig-uid-a, then create rig-uid-b at once")
        t = time.monotonic()
        r = run(["workloadctl", "disable", "--purge", "rig-uid-a"],
                timeout=180)
        print(f"  purge took {time.monotonic() - t:.1f}s", flush=True)
        write("rig-uid-b")
        r = run(["workloadctl", "enable", "rig-uid-b"], timeout=300)
        healthy("rig-uid-b")
        new = uid("rig-uid-b")
        record("premise: rig-uid-b was given rig-uid-a's uid", new == old,
               f"a {old}, b {new}")
        if new is None:
            return
        state = logind(new)
        record("logind files the uid under rig-uid-b's name",
               state.get("Name") == "_wl-rig-uid-b", str(state))
        record("and has it lingering", state.get("Linger") == "yes",
               str(state))

        # A session closing is what made logind clean up in the found case.
        run(["runuser", "-l", "nobody", "-s", "/bin/sh", "-c", "true"])
        time.sleep(15)
        record("rig-uid-b's manager survives a logind clean-up",
               active(f"user@{new}.service"))
        record("and so does its workload",
               active("workload-rig-uid-b.service"))
    finally:
        cleanup()


if __name__ == "__main__":
    main()
