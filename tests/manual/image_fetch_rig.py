#!/usr/bin/env python3
"""image_fetch_rig.py — does a filtered container get its image from outside
its own filter, as a throwaway uid, and never pull it itself?

A filtered workload's egress lands on its own inspector, so its image is
fetched by `workload-image-fetch` (lib/image_fetch.py): a root start step
that runs skopeo as a DynamicUser= uid in a transient unit and loads the
archive as the workload user. Unit tests cover the decision and the argv;
this covers the seam: systemd-run from a unit's start step, the uid the
download really ran as, the load, the record, and what the workload's own
filter saw.

Arms, one after another:

- `rig-fetch`: filtered, pull = "newer", a small image in no store. First
  start, second start, registry blocked, killed mid-fetch, update with a
  rollback target, purge.
- `rig-fetch-big`: filtered, pull = "missing", a ~400 MB image: within the
  start timeout.
- `rig-fetch-tiny`: filtered, with a 16 MiB tmpfs over the fetch cache: the
  free-space check refuses.
- `rig-fetch-bad`: filtered, a tag that doesn't exist: the start fails and
  says why. The fetch step broken on purpose.
- `rig-fetch-open`: unfiltered control: no fetch step, podman pulls.
- `rig-fetch-mirror`: filtered, an image from a registry that doesn't
  exist (`rig-upstream.invalid`) whose one mirror is the homelab registry
  (`registry.local`), so it starts only if the fetch went through the
  mirror. Skipped when `registry.local` doesn't answer.

    sudo python3 tests/manual/image_fetch_rig.py [arm ...]

Arms are named without their `arm_` prefix (`main big tiny bad open
mirror`); none named runs them all.

Needs the workloadctl RPM installed, SELinux enforcing, and anonymous access
to registry.access.redhat.com and docker.io. Turns dontaudit rules off for
the run (`semodule -DB`) and restores them on exit. Exits non-zero on any
failed row.
"""
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

SMALL = "registry.access.redhat.com/hi/python:3.14"
BIG = "docker.io/library/python:3.14"
MISSING_TAG = "registry.access.redhat.com/hi/python:no-such-tag-rig"
AUDIT = "/var/log/audit/audit.log"
MARK = "FETCH-RIG-UP"
FETCH_BIN = "/usr/libexec/workloadctl/workload-image-fetch"
CACHE = Path("/var/cache/private/workloadctl-fetch")
BLOCK_CONF = Path("/etc/containers/registries.conf.d/99-image-fetch-rig.conf")
MIRROR_CONF = Path("/etc/containers/registries.conf.d/99-image-fetch-rig-mirror.conf")
MIRROR = "registry.local"
MIRRORED = "rig-upstream.invalid/library/alpine:latest"
NAMES = ("rig-fetch", "rig-fetch-big", "rig-fetch-tiny", "rig-fetch-bad",
         "rig-fetch-open", "rig-fetch-mirror")
RESULTS = []


def record(label, ok, detail=""):
    RESULTS.append(bool(ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          + (f": {detail}" if detail else ""), flush=True)


def run(argv, timeout=120, check=False):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, check=check)


def bundle(name, image, pull, filtered=True, shell=False):
    if shell:
        command = f'["sh", "-c", "echo {MARK}; exec sleep 1000000000"]'
    else:
        command = ('["python3", "-c", "import time; print(\\"' + MARK
                   + '\\", flush=True); time.sleep(10**9)"]')
    lines = [
        "[workload]", f'name = "{name}"', "enabled = false", "",
        "[container]", f'image = "{image}"', f'pull = "{pull}"',
        f"command = {command}", "",
    ]
    if filtered:
        lines += ["[network]", 'hosts = ["pypi.org"]', 'tls = "inspect"',
                  'ca_delivery = "env"', ""]
    return "\n".join(lines) + "\n"


def write(name, *args, **kw):
    d = Path("/etc/workloads.d") / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "workload.toml").write_text(bundle(name, *args, **kw))


def up(name, since, timeout=300):
    """Wait for the payload's marker in the journal (passthrough logging)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = run(["journalctl", "--since", f"@{since}", "-o", "cat",
                   "--no-pager", "-t", f"workload-{name}", "-g", MARK]).stdout
        if MARK in out:
            return True
        if run(["systemctl", "is-failed", "--quiet",
                f"workload-{name}.service"]).returncode == 0:
            return False
        time.sleep(2)
    return False


def unit_log(name, since):
    return run(["journalctl", "-u", f"workload-{name}.service", "--since",
                f"@{since}", "-o", "cat", "--no-pager"]).stdout


def show(unit, prop):
    return run(["systemctl", "show", unit, "-p", prop, "--value"]).stdout.strip()


def wl_uid(name):
    return int(run(["id", "-u", f"_wl-{name}"]).stdout.strip() or -1)


def user_image_id(name, ref):
    r = run(["workloadctl", "incant", name, "--", "image", "inspect",
             "--format", "{{.Id}}", ref])
    return r.stdout.strip() if r.returncode == 0 else ""


def cache_entries(name):
    d = CACHE / name
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


class UidWatch:
    """Poll the fetch unit's UID while a start runs: the unit is collected
    the moment it ends, so only a watch during the fetch can see who it
    ran as."""

    def __init__(self, name):
        self.unit = f"workload-image-fetch-{name}.service"
        self.uids, self.stop = set(), threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def loop(self):
        while not self.stop.is_set():
            if show(self.unit, "ActiveState") == "active":
                uid = show(self.unit, "UID")
                if uid.isdigit():
                    self.uids.add(int(uid))
            time.sleep(0.1)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join()


def var_tmp_since(marker):
    out = run(["find", "/var/tmp", "-newer", str(marker), "-not", "-path",
               "/var/tmp/systemd-private-*"]).stdout.split()
    return [p for p in out if p != "/var/tmp"]


def denials(offset):
    with open(AUDIT, "rb") as f:
        f.seek(offset)
        text = f.read().decode(errors="replace")
    keys = ("skopeo", "systemd-run", "image-fetch", "workloadctl-fetch",
            "podman")
    return sorted({line.split("msg=audit(")[1].split(": ", 1)[1][:240]
                   for line in text.splitlines()
                   if "avc:" in line and "denied" in line
                   and any(k in line for k in keys)})


def cleanup():
    run(["umount", str(CACHE)])
    BLOCK_CONF.unlink(missing_ok=True)
    MIRROR_CONF.unlink(missing_ok=True)
    for name in NAMES:
        run(["workloadctl", "disable", "--purge", name], timeout=180)
        run(["systemctl", "reset-failed", f"workload-{name}.service"])
        run(["rm", "-rf", f"/etc/workloads.d/{name}"])


def enable(name, since):
    r = run(["workloadctl", "enable", name], timeout=600)
    return r.returncode == 0 and up(name, since), r


def arm_main():
    name = "rig-fetch"
    print(f"\n== {name}: filtered, pull = newer, {SMALL}")
    write(name, SMALL, "newer")
    marker = Path("/run/image-fetch-rig.marker")
    marker.touch()
    time.sleep(1)
    since = int(time.time())
    with UidWatch(name) as watch:
        ok, r = enable(name, since)
    record("a filtered first start comes up with its image", ok,
           "" if ok else (r.stdout + r.stderr)[-800:] + unit_log(name, since)[-1500:])
    if not ok:
        return
    log = unit_log(name, since)
    unit = f"workload-{name}.service"
    pre, main = show(unit, "ExecStartPre"), show(unit, "ExecStart")
    record("systemd loaded the fetch step ahead of podman run",
           FETCH_BIN in pre and "podman run" in main, pre[:160])
    record("podman runs with --pull=never", "--pull=never" in main)
    record("the fetch loaded the image", "loaded '" + SMALL in log,
           log[-400:])
    uid = wl_uid(name)
    record("the download ran as a uid that is neither root nor _wl",
           bool(watch.uids) and all(u not in (0, uid) for u in watch.uids),
           f"seen {sorted(watch.uids)}, _wl {uid}")
    record("the download uid is a dynamic one (61184-65519)",
           bool(watch.uids) and all(61184 <= u <= 65519 for u in watch.uids))
    egress = run(["workloadctl", "egress", name], timeout=60).stdout
    record("the workload's filter saw no registry attempt",
           "redhat" not in egress and "registry" not in egress, egress[-300:])

    rec_path = Path(f"/var/lib/workloads/{name}/image-fetch.json")
    st = rec_path.stat() if rec_path.exists() else None
    rec = json.loads(rec_path.read_text()) if st else {}
    entry = rec.get(SMALL, {})
    record("the record is root's, mode 0600",
           st is not None and st.st_uid == 0
           and stat.S_IMODE(st.st_mode) == 0o600)
    record("the record holds the store's image id",
           entry.get("image_id") == user_image_id(name, SMALL)
           and str(entry.get("digest", "")).startswith("sha256:"), str(entry))
    record("no archive is left after the load", not cache_entries(name),
           str(cache_entries(name)))
    stray = var_tmp_since(marker)
    record("nothing was written to /var/tmp", not stray, str(stray[:5]))

    # Control for the egress row: the filter does log the workload's own
    # registry attempt.
    run(["workloadctl", "exec", name, "--", "python3", "-c",
         "import urllib.request as u\ntry: u.urlopen("
         "'https://registry.access.redhat.com/v2/', timeout=5)\n"
         "except Exception as e: print(e)"], timeout=60)
    time.sleep(2)
    egress = run(["workloadctl", "egress", name], timeout=60).stdout
    record("control: the filter records the workload's own registry attempt",
           "registry.access.redhat.com" in egress, egress[-300:])

    print("\n-- second start, pull = newer, same digest")
    since = int(time.time())
    run(["systemctl", "restart", unit], timeout=300)
    ok = up(name, since)
    log = unit_log(name, since)
    record("a second newer start comes up without fetching again",
           ok and "fetching '" not in log and "loaded '" not in log, log[-400:])

    print("\n-- registry blocked, pull = newer, image local")
    BLOCK_CONF.write_text('[[registry]]\nlocation = "registry.access.redhat.com"\n'
                          'blocked = true\n')
    since = int(time.time())
    run(["systemctl", "restart", unit], timeout=300)
    ok = up(name, since)
    log = unit_log(name, since)
    BLOCK_CONF.unlink()
    record("an unreachable registry: the newer start uses the local image",
           ok and "Using the local image" in log, log[-400:])

    print("\n-- start killed mid-fetch")
    run(["systemctl", "stop", unit], timeout=120)
    rec_path.unlink()
    run(["workloadctl", "incant", name, "--", "rmi", "-f", SMALL])
    fetch_unit = f"workload-image-fetch-{name}.service"
    run(["systemctl", "start", "--no-block", unit])
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if "copy" in show(fetch_unit, "ExecStart"):
            break
        time.sleep(0.2)
    copying = "copy" in show(fetch_unit, "ExecStart")
    # A stop during the start kills the start step, as a start timeout does.
    run(["systemctl", "stop", unit], timeout=120)
    time.sleep(1)
    survived = show(fetch_unit, "ActiveState") == "active"
    record("premise: a killed start leaves its fetch unit running",
           copying and survived, f"copying={copying} survived={survived}")
    run(["systemctl", "reset-failed", unit])
    since = int(time.time())
    run(["systemctl", "start", unit], timeout=600)
    ok = up(name, since)
    record("the next start stops it and fetches afresh", ok,
           unit_log(name, since)[-600:])
    record("no fetch unit and no archive remain",
           show(fetch_unit, "ActiveState") in ("inactive", "")
           and not cache_entries(name),
           f"{show(fetch_unit, 'ActiveState')} {cache_entries(name)}")

    print("\n-- update while filtered, with a rollback target")
    dry = run(["workloadctl", "update", name, "--dry-run"], timeout=60).stdout
    record("the update dry run says fetch", "fetch " + SMALL in dry, dry[-300:])
    run(["workloadctl", "incant", name, "--", "commit",
         f"workload-{name}", SMALL], timeout=120)
    local_id = user_image_id(name, SMALL)
    r = run(["workloadctl", "update", name], timeout=900)
    new_id = user_image_id(name, SMALL)
    rollback_id = user_image_id(name, f"localhost/workload-rollback/{name}:latest")
    record("update fetches while filtered", r.returncode == 0
           and new_id and new_id != local_id,
           (r.stdout + r.stderr)[-600:])
    record("the rollback tag lands on the image it replaced",
           bool(local_id) and rollback_id == local_id,
           f"local {local_id[:12]} rollback {rollback_id[:12]}")

    print("\n-- purge")
    run(["workloadctl", "disable", "--purge", name], timeout=180)
    record("disable --purge removes the record and the cache",
           not rec_path.exists() and not (CACHE / name).exists())


def arm_big():
    name = "rig-fetch-big"
    print(f"\n== {name}: filtered, pull = missing, {BIG}")
    write(name, BIG, "missing")
    since = int(time.time())
    t0 = time.monotonic()
    ok, r = enable(name, since)
    record("a large image fetches within the start timeout", ok,
           f"{time.monotonic() - t0:.0f}s" if ok else unit_log(name, since)[-800:])
    run(["workloadctl", "disable", "--purge", name], timeout=180)


def arm_tiny():
    name = "rig-fetch-tiny"
    print(f"\n== {name}: the fetch cache on a 16 MiB tmpfs")
    CACHE.mkdir(parents=True, exist_ok=True)
    run(["mount", "-t", "tmpfs", "-o", "size=16m,mode=0755", "tmpfs",
         str(CACHE)], check=True)
    try:
        write(name, SMALL, "missing")
        since = int(time.time())
        ok, r = enable(name, since)
        time.sleep(3)
        log = unit_log(name, since)
        record("the free-space check refuses a cache without room",
               not ok and "the fetch cache needs" in log, log[-500:])
    finally:
        run(["workloadctl", "disable", "--purge", name], timeout=180)
        run(["umount", str(CACHE)])


def arm_bad():
    name = "rig-fetch-bad"
    print(f"\n== {name}: a tag that doesn't exist")
    write(name, MISSING_TAG, "missing")
    since = int(time.time())
    ok, r = enable(name, since)
    time.sleep(3)
    log = unit_log(name, since)
    record("a failed fetch fails the start, and says it ran outside the filter",
           not ok and "outside the workload's filter failed" in log, log[-500:])
    record("and podman never ran", "podman run" not in log
           and MARK not in log)
    run(["workloadctl", "disable", "--purge", name], timeout=180)


def arm_open():
    name = "rig-fetch-open"
    print(f"\n== {name}: unfiltered control")
    write(name, SMALL, "missing", filtered=False)
    since = int(time.time())
    ok, r = enable(name, since)
    unit = f"workload-{name}.service"
    record("an unfiltered workload still pulls rootless", ok,
           "" if ok else unit_log(name, since)[-600:])
    record("its unit has no fetch step and keeps its pull policy",
           FETCH_BIN not in show(unit, "ExecStartPre")
           and "--pull=missing" in show(unit, "ExecStart"))
    run(["workloadctl", "disable", "--purge", name], timeout=180)


def arm_mirror():
    name = "rig-fetch-mirror"
    print(f"\n== {name}: {MIRRORED}, mirrored only by {MIRROR}")
    reach = run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                 f"https://{MIRROR}/v2/"], timeout=20).stdout
    if reach != "200":
        print(f"  [SKIP] {MIRROR} doesn't answer ({reach or 'no reply'})")
        return
    record("premise: the image's own registry doesn't resolve",
           run(["getent", "hosts", MIRRORED.split("/")[0]]).returncode != 0)
    MIRROR_CONF.write_text(
        f'[[registry]]\nlocation = "{MIRRORED.split("/")[0]}"\n'
        f'[[registry.mirror]]\nlocation = "{MIRROR}"\n')
    try:
        write(name, MIRRORED, "newer", shell=True)  # alpine: no python
        since = int(time.time())
        ok, r = enable(name, since)
        log = unit_log(name, since)
        record("a mirror-only image fetches through the mirror",
               ok and "loaded '" + MIRRORED in log, log[-600:])
    finally:
        MIRROR_CONF.unlink(missing_ok=True)
        run(["workloadctl", "disable", "--purge", name], timeout=180)


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    print("== premises")
    record("SELinux is enforcing", run(["getenforce"]).stdout.strip() == "Enforcing")
    record("workload-image-fetch is installed", Path(FETCH_BIN).exists())
    record("root's store lacks the images",
           run(["podman", "image", "exists", SMALL]).returncode != 0
           and run(["podman", "image", "exists", BIG]).returncode != 0)
    record("no rig workload is left over",
           not any(Path("/etc/workloads.d", n).exists() for n in NAMES))
    if not all(RESULTS):
        sys.exit("premises failed; nothing measured")

    offset = os.path.getsize(AUDIT)
    run(["semodule", "-DB"], timeout=300, check=True)
    try:
        arms = (arm_main, arm_big, arm_tiny, arm_bad, arm_open, arm_mirror)
        chosen = sys.argv[1:]
        unknown = set(chosen) - {a.__name__[4:] for a in arms}
        if unknown:
            sys.exit(f"no such arm: {sorted(unknown)}")
        for arm in arms:
            if chosen and arm.__name__[4:] not in chosen:
                continue
            try:
                arm()
            except Exception as e:  # noqa: BLE001
                record(f"{arm.__name__} ran to the end", False, repr(e))
        found = denials(offset)
        record("no denials for the fetch chain, dontaudit off", not found,
               "\n    ".join(found[:15]))
    finally:
        cleanup()
        run(["semodule", "-B"], timeout=300)

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} rows passed")
    sys.exit(0 if all(RESULTS) else 1)


if __name__ == "__main__":
    main()
