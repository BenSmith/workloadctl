#!/usr/bin/env python3
"""device_rig.py — does sunshine-streaming's configuration reach a real GPU
under enforcing, and leave the host's sound card out?

The runtime rung's test_runtime_devices covers uinput, seccomp and rlimits in
a VM, which has neither a render node nor a sound card. This runs the same
configuration on a host that has both, as two arms:

- `sunshine`: sunshine-streaming's [devices] (gpu = "auto"), [security],
  device volumes and policy.cil, on a plain image;
- `control`: the same without gpu, which must lose the render node and
  /dev/kfd.

The payload does a real handshake with each device rather than an open: the
DRM version ioctl on the render node (the driver's name) and the KFD version
ioctl. It lists /dev/snd, which must be empty: the stream's audio is the
container's own PipeWire sink. Each arm then reads audit.log for its type's
denials.

    sudo python3 tests/manual/device_rig.py

Needs an AMD GPU (/dev/dri/renderD*, /dev/kfd), a sound card and workloadctl
installed; SELinux enforcing. Exits non-zero on any failed row.
"""
import base64
import json
import os
import subprocess
import sys
import time
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SUNSHINE = REPO / "workloads" / "sunshine-streaming"
IMAGE = "docker.io/library/python:3-alpine"
AUDIT = "/var/log/audit/audit.log"
MARK = "DEVICE-RIG-RESULT "
DEVICE_VOLUMES = ("/run/udev:", "/dev/input:")
RESULTS = []

PROBE = r'''
import ctypes, fcntl, glob, json, os, struct
R = {}
def err(e): return type(e).__name__ + ":" + str(e.errno)
def drm(path):
    fd = os.open(path, os.O_RDWR)
    try:
        name = ctypes.create_string_buffer(64)
        v = struct.pack("iii4xQQQQQQ", 0, 0, 0, 64, ctypes.addressof(name),
                        0, 0, 0, 0)
        buf = bytearray(v)
        fcntl.ioctl(fd, 0xC0406400, buf)
        return name.value.decode()
    finally:
        os.close(fd)
def kfd():
    fd = os.open("/dev/kfd", os.O_RDWR)
    try:
        major, minor = struct.unpack("II", fcntl.ioctl(fd, 0x80084B01, bytes(8)))
        return f"{major}.{minor}"
    finally:
        os.close(fd)
R["render_nodes"] = sorted(glob.glob("/dev/dri/renderD*"))
for label, call in (("drm", lambda: drm(R["render_nodes"][0])), ("kfd", kfd)):
    try:
        R[label] = call()
    except (OSError, IndexError) as e:
        R[label] = err(e) if isinstance(e, OSError) else "absent"
R["snd"] = sorted(glob.glob("/dev/snd/*"))
R["label"] = open("/proc/self/attr/current").read().strip("\0\n")
print("DEVICE-RIG-RESULT " + json.dumps(R), flush=True)
import time
while True: time.sleep(3600)
'''


# A unit's command line takes no newline, so the probe goes in encoded.
ONE_LINE = ("import base64; exec(base64.b64decode('"
            + base64.b64encode(PROBE.encode()).decode() + "'))")


def record(label, ok, detail=""):
    RESULTS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))


def run(argv, timeout=120, check=False):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, check=check)


def toml_value(v):
    return json.dumps(v) if not isinstance(v, dict) else (
        "{ " + ", ".join(f"{k} = {json.dumps(x)}" for k, x in v.items()) + " }")


def bundle(name, control):
    s = tomllib.loads((SUNSHINE / "workload.toml").read_text())
    security = dict(s["security"])
    devices = {"devices": s["devices"]["devices"]}
    if not control:
        devices["gpu"] = s["devices"]["gpu"]
    volumes = [v for v in s["storage"]["volumes"] if v.startswith(DEVICE_VOLUMES)]
    lines = [
        "[workload]", f'name = "{name}"', "enabled = false", "",
        "[container]", f'image = "{IMAGE}"',
        f"command = {toml_value(['python3', '-c', ONE_LINE])}", "",
        "[devices]", *(f"{k} = {toml_value(v)}" for k, v in devices.items()), "",
        "[security]", *(f"{k} = {toml_value(v)}" for k, v in security.items()), "",
        "[storage]", f"volumes = {toml_value(volumes)}", "",
        "[network]", 'mode = "pasta"', "",
    ]
    return "\n".join(lines) + "\n"


def report(name, since, timeout=240):
    """The probe's line, from the journal: the payload's stdout goes there
    (the passthrough log driver), so podman logs has none."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = run(["journalctl", "--since", f"@{since}", "-o", "cat",
                   "--no-pager", "-g", f"^{MARK}"]).stdout
        lines = [line for line in out.splitlines() if line.startswith(MARK)]
        if lines:
            return json.loads(lines[-1][len(MARK):])
        time.sleep(3)
    raise RuntimeError(f"no result from {name}:\n"
                       + run(["journalctl", "-u", f"workload-{name}", "-n", "40",
                              "--no-pager"]).stdout)


def denials(offset, name):
    kind = "wl_" + name.replace("-", "_")
    with open(AUDIT, "rb") as f:
        f.seek(offset)
        text = f.read().decode(errors="replace")
    return [line for line in text.splitlines()
            if "avc:" in line and "denied" in line
            and f"scontext=system_u:system_r:{kind}.process:" in line]


def arm(name, control):
    print(f"\n== {name} ({'control: no gpu' if control else 'sunshine'})")
    d = Path("/etc/workloads.d") / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "workload.toml").write_text(bundle(name, control))
    (d / "policy.cil").write_text((SUNSHINE / "policy.cil").read_text())
    offset = os.path.getsize(AUDIT)
    since = int(time.time())
    try:
        r = run(["workloadctl", "enable", name], timeout=300)
        if r.returncode:
            raise RuntimeError(f"enable failed:\n{r.stdout[-1500:]}{r.stderr[-1500:]}")
        result = report(name, since)
        print("  " + json.dumps(result))
        return result, denials(offset, name)
    finally:
        run(["workloadctl", "disable", "--purge", name], timeout=180)
        run(["systemctl", "reset-failed", f"workload-{name}.service"])
        run(["rm", "-rf", str(d)])


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    print("== premises")
    renders = sorted(Path("/dev/dri").glob("renderD*"))
    record("SELinux is enforcing", run(["getenforce"]).stdout.strip() == "Enforcing")
    record("the host has a render node", bool(renders), str(renders))
    record("the host has /dev/kfd", Path("/dev/kfd").exists())
    record("the host has a sound card", bool(list(Path("/dev/snd").glob("controlC*"))))
    if not all(RESULTS):
        sys.exit("premises failed; nothing measured")

    full, full_denials = arm("rig-devices", control=False)
    record("the render node is in the container", bool(full["render_nodes"]),
           str(full["render_nodes"]))
    record("the DRM version ioctl names the driver", full.get("drm") == "amdgpu",
           str(full.get("drm")))
    record("the KFD version ioctl answers", "." in str(full.get("kfd")),
           str(full.get("kfd")))
    record("the host's sound card stays out", full.get("snd") == [],
           str(full.get("snd")))
    record("sunshine's policy leaves it no denial", not full_denials,
           "\n    ".join(full_denials[:10]))

    ctl, ctl_denials = arm("rig-devices-ctl", control=True)
    record("control: no gpu, no render node", not ctl["render_nodes"],
           str(ctl["render_nodes"]))
    record("control: no gpu, no /dev/kfd", not str(ctl.get("kfd")).count("."),
           str(ctl.get("kfd")))
    record("control: no denial either", not ctl_denials,
           "\n    ".join(ctl_denials[:10]))

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} rows passed")
    sys.exit(0 if all(RESULTS) else 1)


if __name__ == "__main__":
    main()
