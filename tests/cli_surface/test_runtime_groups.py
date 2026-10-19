"""
test_runtime_groups.py — a workload's processes hold the groups extra_groups
names, on a real host.

systemd-sysusers and `usermod -aG` both report success for a membership in a
group the image defines only in /usr/lib/group, and add none; so do the unit
tests, which never meet a real group database. On Fedora bootc that is video,
render and input, the groups GPU bundles name. A workload that lacks them
starts normally and fails only when it opens a device, so the row reads the
groups off the running payload itself.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload, dump_journal

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-groups"
USER = "_wl-rt-groups"
CONTAINER = "workload-rt-groups"
GROUPS = ("video", "render")


def _gid(target, group):
    r = target.run(["getent", "group", group], sudo=False, check=True)
    return int(r.stdout.split(":")[2])


def test_payload_holds_its_extra_groups(target):
    _install_toml(target, "rt-groups.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        wanted = {group: _gid(target, group) for group in GROUPS}
        uid = target.run(["id", "-u", USER], sudo=False, check=True).stdout.strip()
        # The payload's host pid, from the workload user's own podman: with
        # extra groups the container gets explicit id maps, so it runs as a
        # subordinate uid and no process of the workload uid is the payload.
        # runuser keeps the caller's cwd, which _wl-* cannot traverse.
        pid_fmt = "{{.State.Pid}}"
        r = target.run(
            ["sh", "-c",
             f"cd / && runuser -u {USER} -- "
             f"env XDG_RUNTIME_DIR=/run/user/{uid} "
             f"podman inspect --format '{pid_fmt}' {CONTAINER}"],
            sudo=True, check=False,
        )
        pid = r.stdout.strip()
        assert pid.isdigit() and int(pid) > 0, (
            f"no running payload pid for {CONTAINER} (got {r.stdout!r} / {r.stderr!r})"
        )
        status = target.run(["cat", f"/proc/{pid}/status"],
                            sudo=True, check=True).stdout
        held = {int(g) for line in status.splitlines()
                if line.startswith("Groups:") for g in line.split()[1:]}
        missing = {group: gid for group, gid in wanted.items() if gid not in held}
        where = target.run(["grep", "-E", "^(video|render):", "/etc/group"],
                           sudo=False, check=False).stdout
        assert not missing, (
            f"{USER}'s payload lacks {missing}; it holds {sorted(held)}.\n"
            f"/etc/group lines for the groups:\n{where or '(none)'}"
        )
    finally:
        _purge_workload(target, WORKLOAD)
