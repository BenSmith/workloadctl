#!/usr/bin/env python3
"""cdi_rig.py — does an NVIDIA (CDI) workload start in the default rootless
namespace, and refuse to start when that namespace would be reordered?

Runs on a host with no NVIDIA GPU: it writes a dummy /run/cdi/nvidia.yaml
whose one device, nvidia.com/gpu=all, bind-mounts a host directory. That is
the shape of every CDI mount the toolkit's real spec injects, and the one
podman idmaps under a user namespace of the container's own.

Two arms, each with gpu = "nvidia" and extra_groups = ["video"]:

- `rig-cdi`: the default userns (keep-id);
- `rig-cdi-root`: userns = "keep-id:uid=0,gid=0".

    sudo python3 tests/manual/cdi_rig.py

Needs the workloadctl RPM under test installed, podman with CDI, a
/dev/dri/card* node owned root:video 0660, network for the image, and
SELinux enforcing. Exits non-zero on any failed row.
"""
import base64
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

IMAGE = "docker.io/library/python:3-alpine"
AUDIT = "/var/log/audit/audit.log"
SPEC = Path("/run/cdi/nvidia.yaml")
DUMMY_DIR = Path("/usr/local/share/cdi-rig")
DUMMY_TEXT = "cdi-rig-dummy\n"
MARK = "CDI-RIG-RESULT "
GUARD = "/usr/libexec/workloadctl/workload-cdi-subids"
RESULTS = []


@dataclass(frozen=True)
class Arm:
    name: str
    userns: str | None


ARMS = (Arm("rig-cdi", None), Arm("rig-cdi-root", "keep-id:uid=0,gid=0"))

DUMMY_SPEC = f"""\
cdiVersion: "0.6.0"
kind: nvidia.com/gpu
devices:
- name: all
  containerEdits:
    mounts:
    - hostPath: {DUMMY_DIR}
      containerPath: /opt/cdi-rig
      options: [ro, nosuid, nodev, bind]
"""

PROBE = r'''
import glob, json, os, time
R = {}
def err(e): return f"{type(e).__name__}:{e.errno}"
def opens(path):
    try:
        os.close(os.open(path, os.O_RDWR))
        return "ok"
    except OSError as e:
        return err(e)
try:
    R["dummy"] = open("/opt/cdi-rig/file").read()
except OSError as e:
    R["dummy"] = err(e)
R["uid_map"] = [l.split() for l in open("/proc/self/uid_map")]
R["gid_map"] = [l.split() for l in open("/proc/self/gid_map")]
R["ids"] = [os.getuid(), os.getgid()]
R["groups"] = os.getgroups()
R["capeff"] = [l.split()[1] for l in open("/proc/self/status")
               if l.startswith("CapEff:")][0]
cards = sorted(glob.glob("/dev/dri/card*"))
R["card"] = cards[0] if cards else None
R["card_first"] = opens(cards[0]) if cards else "absent"
try:
    os.setgroups([0])
    R["setgroups"] = "ok"
    R["card_after"] = opens(cards[0]) if cards else "absent"
except OSError as e:
    R["setgroups"] = err(e)
print("CDI-RIG-RESULT " + json.dumps(R), flush=True)
while True: time.sleep(3600)
'''

ONE_LINE = ("import base64; exec(base64.b64decode('"
            + base64.b64encode(PROBE.encode()).decode() + "'))")


def toml_for(arm):
    lines = [
        "[workload]", f'name = "{arm.name}"', "enabled = false", "",
        "[container]", f'image = "{IMAGE}"',
        f"command = {json.dumps(['python3', '-c', ONE_LINE])}", "",
        "[devices]", 'gpu = "nvidia"', "",
        "[security]", 'extra_groups = ["video"]',
    ]
    if arm.userns:
        lines.append(f'userns = "{arm.userns}"')
    lines += ["", "[network]", 'mode = "pasta"', ""]
    return "\n".join(lines) + "\n"


def record(label, ok, detail=""):
    RESULTS.append(bool(ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          + (f": {detail}" if detail else ""), flush=True)


def run(argv, timeout=120, **kw):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, **kw)


def as_user(user, uid, argv, timeout=180):
    return run(["sudo", "-u", user, f"XDG_RUNTIME_DIR=/run/user/{uid}",
                *argv], timeout=timeout, cwd="/")


def report(name, since, timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = run(["journalctl", "--since", f"@{since}", "-o", "cat",
                   "--no-pager", "-g", f"^{MARK}"]).stdout
        lines = [l for l in out.splitlines() if l.startswith(MARK)]
        if lines:
            return json.loads(lines[-1][len(MARK):])
        time.sleep(3)
    raise RuntimeError(f"no result from {name}:\n" + run(
        ["journalctl", "-u", f"workload-{name}", "-n", "40",
         "--no-pager"]).stdout)


def denials(offset):
    """Denials for any container domain since `offset`."""
    with open(AUDIT, "rb") as f:
        f.seek(offset)
        text = f.read().decode(errors="replace")
    return [l for l in text.splitlines()
            if "avc:" in l and "denied" in l
            and ("container_" in l or ":wl_" in l)]


def exec_paths(unit, prop):
    """The program paths of a parsed Exec* property, in order."""
    out = run(["systemctl", "show", unit, "-p", prop, "--value"]).stdout
    return [part.split("path=", 1)[1].split(" ;", 1)[0].strip()
            + " " + part.split("argv[]=", 1)[1].split(" ;", 1)[0]
            for part in out.split("{")[1:] if "path=" in part]


def config_json(user, uid, container):
    """The OCI config.json podman wrote for `container`, as text."""
    r = as_user(user, uid, ["podman", "inspect", container])
    if r.returncode:
        return None
    path = json.loads(r.stdout)[0].get("OCIConfigPath")
    return Path(path).read_text() if path and Path(path).exists() else None


def subid_main(user, path):
    for line in Path(path).read_text().splitlines():
        u, start, count = line.split(":")
        if u == user and count != "1":
            return int(start), int(count)
    return None


def enable(arm):
    d = Path("/etc/workloads.d") / arm.name
    d.mkdir(parents=True, exist_ok=True)
    (d / "workload.toml").write_text(toml_for(arm))
    since = int(time.time())
    r = run(["workloadctl", "enable", arm.name], timeout=400)
    if r.returncode:
        raise RuntimeError(f"enable failed:\n{r.stdout[-2000:]}"
                           f"{r.stderr[-2000:]}")
    return report(arm.name, since)


def teardown(arm):
    run(["workloadctl", "disable", "--purge", arm.name], timeout=240)
    run(["systemctl", "reset-failed", f"workload-{arm.name}.service"])
    run(["rm", "-rf", f"/etc/workloads.d/{arm.name}"])


def default_arm(arm, offset):
    print(f"\n== {arm.name} (default keep-id)", flush=True)
    unit = f"workload-{arm.name}.service"
    user = f"_wl-{arm.name}"
    res = enable(arm)
    print("  " + json.dumps(res))
    uid = int(run(["id", "-u", user]).stdout)
    base, count = subid_main(user, "/etc/subuid")
    gbase, gcount = subid_main(user, "/etc/subgid")

    pre = exec_paths(unit, "ExecStartPre")
    guard = [i for i, p in enumerate(pre) if p.startswith(GUARD)]
    migrate = [i for i, p in enumerate(pre) if "system migrate" in p]
    record("parsed ExecStartPre runs the guard before migrate",
           len(guard) == 1 and migrate and guard[0] < migrate[0],
           "\n    " + "\n    ".join(pre))
    after = run(["systemctl", "show", unit, "-p", "After",
                 "--value"]).stdout.split()
    requires = run(["systemctl", "show", unit, "-p", "Requires",
                    "--value"]).stdout.split()
    record("ordered after nvidia-cdi-refresh, requiring no CDI unit",
           "nvidia-cdi-refresh.service" in after
           and not any("nvidia" in u for u in requires),
           f"requires={requires}")
    record("the CDI mount is in the container", res["dummy"] == DUMMY_TEXT,
           repr(res["dummy"]))
    cfg = config_json(user, uid, f"workload-{arm.name}")
    record("its config.json has no idmap", cfg is not None
           and "idmap" not in cfg, "no config.json" if cfg is None else "")
    record("uid_map is 0 → uid, N → base + N - 1",
           res["uid_map"] == [["0", str(uid), "1"],
                              ["1", str(base), str(count)]],
           f"{res['uid_map']} (uid {uid}, base {base})")
    record("gid_map is 0 → gid, N → base + N - 1",
           res["gid_map"] == [["0", str(uid), "1"],
                              ["1", str(gbase), str(gcount)]],
           f"{res['gid_map']} (gid {uid}, base {gbase})")
    record("the process is 0:0", res["ids"] == [0, 0], str(res["ids"]))
    record("default keep-id: no effective capability",
           int(res["capeff"], 16) == 0, res["capeff"])
    record("the first process opens a root:video 0660 card by keep-groups",
           res["card_first"] == "ok", f"{res['card']}: {res['card_first']}")

    # The premise: the same device under keep-id fails on the idmap.
    print("\n== premise: keep-id + the CDI device", flush=True)
    bug = "rig-cdi-keepid"
    as_user(user, uid, ["podman", "rm", "-f", bug])
    r = as_user(user, uid, ["podman", "run", "--name", bug, "--userns=keep-id",
                            "--device=nvidia.com/gpu=all", IMAGE, "true"])
    out = (r.stdout + r.stderr).strip()
    record("keep-id + CDI device fails to start", r.returncode != 0,
           out[-400:])
    bug_cfg = config_json(user, uid, bug)
    record("its config.json carries idmap on the CDI mount",
           bug_cfg is not None and "idmap" in bug_cfg,
           "no config.json" if bug_cfg is None else "")
    as_user(user, uid, ["podman", "rm", "-f", bug])

    print("\n== guard: an extra subgid line", flush=True)
    run(["systemctl", "stop", unit], timeout=120)
    subgid = Path("/etc/subgid")
    original = subgid.read_text()
    try:
        subgid.write_text(original + f"{user}:39:1\n")
        since = int(time.time())
        r = run(["systemctl", "start", unit], timeout=180)
        result = run(["systemctl", "show", unit, "-p", "Result",
                      "--value"]).stdout.strip()
        log = run(["journalctl", "-u", unit, "--since", f"@{since}",
                   "--no-pager", "-o", "cat"]).stdout
        record("the unit refuses to start", r.returncode != 0,
               f"Result={result}")
        record("the refusal names the line",
               "needs exactly one" in log and f"{user}:39:1" in log,
               log[-500:])
        record("no container was started",
               as_user(user, uid, ["podman", "ps", "-q"]).stdout.strip() == "")
        d = run(["workloadctl", "diagnose", "--json", arm.name], timeout=180)
        checks = {c.get("name") or c.get("check"): c
                  for c in json.loads(d.stdout or "{}").get("checks", [])}
        sd = checks.get("subgid_delegations", {})
        record("diagnose reports subgid_delegations",
               sd and not sd.get("passed"), sd.get("message", "absent"))
    finally:
        subgid.write_text(original)
        run(["systemctl", "reset-failed", unit])
    r = run(["systemctl", "start", unit], timeout=180)
    record("control: with the line gone it starts again", r.returncode == 0,
           r.stderr[-300:])
    teardown(arm)


def root_arm(arm):
    print(f"\n== {arm.name} (keep-id:uid=0,gid=0)", flush=True)
    res = enable(arm)
    print("  " + json.dumps(res))
    record("keep-id root: root's capabilities stay",
           int(res["capeff"], 16) != 0, res["capeff"])
    record("the first process opens the card", res["card_first"] == "ok",
           res["card_first"])
    record("setgroups succeeds", res["setgroups"] == "ok", res["setgroups"])
    record("after setgroups the card is refused",
           str(res.get("card_after")).startswith("PermissionError"),
           str(res.get("card_after")))
    teardown(arm)


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    print("== premises", flush=True)
    record("SELinux is enforcing",
           run(["getenforce"]).stdout.strip() == "Enforcing")
    record("no real NVIDIA device", not Path("/dev/nvidiactl").exists())
    cards = sorted(Path("/dev/dri").glob("card*"))
    st = cards[0].stat() if cards else None
    record("a card node is root:video 0660",
           st is not None and st.st_uid == 0 and st.st_gid == 39
           and st.st_mode & 0o777 == 0o660, str(cards[:1]))
    if SPEC.exists():
        record("no CDI spec is already at /run/cdi/nvidia.yaml", False)
    if not all(RESULTS):
        sys.exit("premises failed; nothing measured")

    DUMMY_DIR.mkdir(parents=True, exist_ok=True)
    (DUMMY_DIR / "file").write_text(DUMMY_TEXT)
    SPEC.parent.mkdir(parents=True, exist_ok=True)
    SPEC.write_text(DUMMY_SPEC)
    offset = os.path.getsize(AUDIT)
    try:
        for arm, body in zip(ARMS, (lambda a: default_arm(a, offset),
                                    root_arm)):
            try:
                body(arm)
            except Exception as e:
                record(f"{arm.name} ran", False, f"{type(e).__name__}: {e}")
                teardown(arm)
        found = denials(offset)
        record("no container-domain denial", not found,
               "\n    ".join(found[:10]))
    finally:
        SPEC.unlink(missing_ok=True)
        run(["rm", "-rf", str(DUMMY_DIR)])

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} rows passed")
    sys.exit(0 if all(RESULTS) else 1)


if __name__ == "__main__":
    main()
