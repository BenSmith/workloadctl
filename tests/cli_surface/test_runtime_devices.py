"""
test_runtime_devices.py — a streaming workload reaches the devices it is given
and no others, on a real host.

rt-devices is sunshine-streaming's device, group, seccomp, rlimit and SELinux
configuration (tests/test_rt_devices.py holds it equal) on a plain image whose
payload, rt-devices-probe.py, reports what it could do. The unit tests see
flags; only a live payload shows that they add up:

- it makes a keyboard through /dev/uinput, and the node appears under the
  bind-mounted /dev/input, opens once udev gives it to `uinput`, and reads
  back the key written to it;
- it opens no node a real device made. Those stay `input`'s, and the payload
  holds DAC_OVERRIDE, which in its user namespace does not reach a file of
  an unmapped owner. Opening one would read every key typed at the host
  (audit F16);
- no sound device comes in: the stream's audio needs none;
- the bwrap syscalls seccomp_allow names work, and a 32-bit syscall runs,
  which the baseline kills;
- LimitNICE and LimitRTPRIO reach the payload and it can use them;
- sunshine's own policy.cil leaves the payload no denial.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import base64
import json
import time
from pathlib import Path

import pytest

from fixtures import WORKLOADS_DIR, _enable_workload, _purge_workload, dump_journal

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-devices"
USER = "_wl-rt-devices"
CONTAINER = "workload-rt-devices"
TYPE = "wl_rt_devices"
MARK = "RT-DEVICES-RESULT "
POLICY = Path(__file__).parents[2] / "workloads" / "sunshine-streaming" / "policy.cil"
AUDIT = "/var/log/audit/audit.log"


def _install(target):
    probe = (WORKLOADS_DIR / "rt-devices-probe.py").read_text()
    toml = (WORKLOADS_DIR / "rt-devices.toml").read_text()
    assert '"PROBE"' in toml
    # A unit's command line takes no newline, so the probe goes in encoded.
    encoded = base64.b64encode(probe.encode()).decode()
    toml = toml.replace('"PROBE"', json.dumps(
        f"import base64; exec(base64.b64decode('{encoded}'))"))
    target.run(["mkdir", "-p", f"/etc/workloads.d/{WORKLOAD}"], sudo=True, check=True)
    target.put_content(toml, f"/etc/workloads.d/{WORKLOAD}/workload.toml")
    target.put_content(POLICY.read_text(), f"/etc/workloads.d/{WORKLOAD}/policy.cil")


def _report(target, since, timeout=90):
    """The probe's line, from the journal: the payload's stdout goes there
    (the passthrough log driver), so podman logs has none."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = target.run(["journalctl", "--since", f"@{since}", "-o", "cat",
                        "--no-pager", "-g", f"^{MARK}"], sudo=True, check=False)
        lines = [line for line in r.stdout.splitlines() if line.startswith(MARK)]
        if lines:
            return json.loads(lines[-1][len(MARK):])
        time.sleep(2)
    pytest.fail(f"{CONTAINER} printed no {MARK.strip()} in {timeout}s")


def _audit_size(target):
    r = target.run(["stat", "-c", "%s", AUDIT], sudo=True, check=True)
    return int(r.stdout.strip())


def _denials_since(target, offset):
    r = target.run(["sh", "-c", f"tail -c +{offset + 1} {AUDIT} | grep -a 'avc:.*denied' || true"],
                   sudo=True, check=True)
    # The payload's own denials: a crashed payload is also the target of
    # systemd-coredump's, which say nothing about its policy.
    return [line for line in r.stdout.splitlines()
            if f"scontext=system_u:system_r:{TYPE}.process:" in line]


@pytest.fixture(scope="module")
def run(target):
    offset = _audit_size(target)
    since = int(target.run(["date", "+%s"], sudo=False, check=True).stdout)
    _install(target)
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=240)
            report = _report(target, since)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise
        print(f"\n----- {WORKLOAD} probe -----\n{json.dumps(report, indent=2)}")
        yield report, _denials_since(target, offset)
    finally:
        _purge_workload(target, WORKLOAD)


def test_the_payload_runs_confined(run):
    """The rest means nothing for a payload outside its filter or type."""
    report, _ = run
    assert report.get("seccomp") == "2", report
    assert f"{TYPE}.process" in report.get("label", ""), report


def test_it_makes_a_keyboard_and_reads_its_key_back(run):
    report, _ = run
    assert report.get("uinput_open") == "ok", report
    assert report.get("virtual_node"), report
    assert report.get("virtual_open") == "ok", report
    assert report.get("key_read_back") is True, report


def test_no_node_a_real_device_made_opens(run):
    report, _ = run
    physical = report.get("physical")
    assert physical, f"no real input device to try: {report}"
    opened = [node for node, result in physical.items() if result != "EACCES"]
    assert not opened, f"real input nodes not refused EACCES: {physical}"


def test_no_sound_device_comes_in(run):
    """The stream's audio is the container's own PipeWire sink."""
    report, _ = run
    assert report.get("snd") == [], report


def test_bwraps_syscalls_and_32_bit_code_run(run):
    report, _ = run
    assert report.get("namespaces") == "ok", report
    assert report.get("elf32_rc") == 42, report


def test_the_scheduling_limits_reach_the_payload(run):
    report, _ = run
    assert report.get("rlimit_nice") == [40, 40], report
    assert report.get("rlimit_rtprio") == [20, 20], report
    assert report.get("nice") == -10, report
    assert report.get("rt") == "ok", report


def test_sunshines_policy_leaves_it_no_denial(run):
    _, denials = run
    assert not denials, "\n".join(denials)
