"""
test_runtime_pasta.py — B4 runtime check: pasta restart resilience, proven on a
real kernel.

Guards the "pasta stale-pause" failure: a libpod
pause process left over from a previous invocation, whose PrivateTmp `/tmp` has
been destroyed, gets joined by the next `podman run` via the rootless join
shortcut, and pasta then fails its sandbox mount with
`pivot_root(): No such file or directory` — the unit silently restart-loops.
The fix is the head unit's two ExecStartPre cleanup steps
(`podman system migrate` + `rm -f .../pause.pid .../ns_handles`), which force a
*fresh* pause in the live mount namespace.

The check has two layers, primary first:

  * The **observable surface** (the DoD, always asserted): a pasta workload
    survives repeated restarts *and* host-side podman calls (which historically
    migrated/re-armed the stale pause) without falling into the ENOENT
    restart-loop — active every time, NRestarts never climbing toward
    StartLimitBurst. Never weakened to "active once".

  * A **best-effort faithful arm** (asserted only if it establishes): leave a
    stale pause — one planted, a pasta pause escaped to a scope whose
    PrivateTmp `/tmp` is then destroyed, or the stopped workload's own, which
    the arm's `podman run` proves stale by failing pasta's sandbox mount — and
    prove the workload still starts clean over it. In a Fedora 45 gate run
    on 2026-11-08 the stop left one. Folded inline (no extra VM boot); if the arm can't be
    established in this environment it is logged and skipped, and the primary
    surface above carries the guarantee. It is expected to arm under gate mode
    (the real bootc image) where the shipped rootless stack is present.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload, _wait_active

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-basic"           # the shipped pasta+health fixture (network.mode = pasta)
USER = "_wl-rt-basic"
IMAGE = "docker.io/library/caddy:2-alpine"  # matches rt-basic.toml
SERVICE = f"workload-{WORKLOAD}.service"


def _resolve_uid(target) -> str:
    r = target.run(["id", "-u", USER], sudo=False, check=True)
    uid = r.stdout.strip()
    assert uid.isdigit(), f"could not resolve uid for {USER}: {r.stdout!r}"
    return uid


def _rootless(target, uid: str, args: list, check=False):
    """Run a podman call as the workload user, faithfully (cwd=/, live user
    bus + XDG_RUNTIME_DIR), the way a host-side operator touch would — this is
    the operation that historically migrated the stale pause into a scope."""
    joined = " ".join(args)
    return target.run(
        ["sh", "-c",
         f"cd / && runuser -u {USER} -- "
         f"env XDG_RUNTIME_DIR=/run/user/{uid} "
         f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "
         f"{joined}"],
        sudo=True, check=check,
    )


def _nrestarts(target) -> int:
    r = target.run(["systemctl", "show", SERVICE, "-p", "NRestarts", "--value"],
                   sudo=False, check=False)
    v = r.stdout.strip()
    return int(v) if v.isdigit() else 0


def _start_limit_burst(target) -> int:
    r = target.run(["systemctl", "show", SERVICE, "-p", "StartLimitBurst", "--value"],
                   sudo=False, check=False)
    v = r.stdout.strip()
    # 0 means "no limit"; treat as the systemd default of 5 for the headroom check.
    return int(v) if v.isdigit() and v != "0" else 5


def _diagnose(target, uid: str):
    """Failure dump: unit journal tail + the pasta pause tmp dir listing."""
    j = target.run(["journalctl", "--no-pager", "-n", "80", "-u", SERVICE],
                   sudo=True, check=False)
    ls = target.run(["ls", "-la", f"/run/user/{uid}/libpod/tmp/"],
                    sudo=True, check=False)
    print(f"\n----- journalctl -u {SERVICE} (tail) -----\n{j.stdout}\n{j.stderr}\n"
          f"----- ls -la /run/user/{uid}/libpod/tmp/ -----\n{ls.stdout}\n{ls.stderr}\n"
          f"--------------------------------------------------------")


def _assert_active(target, uid: str, ctx: str):
    """Wait for the unit to be genuinely up again and assert it; dump on failure."""
    try:
        _wait_active(target, WORKLOAD, timeout=90)
    except TimeoutError:
        _diagnose(target, uid)
        raise
    state = target.run(["systemctl", "is-active", SERVICE],
                       sudo=False, check=False).stdout.strip()
    if state != "active":
        _diagnose(target, uid)
    assert state == "active", f"{SERVICE} is {state!r} {ctx}, expected active"


# What pasta prints when the pause it joins has lost its /tmp: the failure
# this test guards, met by the arm's own `podman run`.
STALE_SANDBOX = "Failed to mount empty tmpfs for sandboxing"


def _arm_stale_pause(target, uid: str) -> str | None:
    """Best-effort: leave the workload user a stale pasta pause.

    Stop the workload (linger keeps user@<uid>.service up, so a pause outlives
    the unit that made it), then run a pasta `podman run` inside a transient
    PrivateTmp unit. Either of two outcomes leaves a stale pause:

    - "planted": no pause was left, so this run made one; it escapes to a
      podman-pause-*.scope, and when the transient unit exits its PrivateTmp
      /tmp is destroyed under it;
    - "left by the stop": the workload's own pause outlived the stop, the run
      joined it, and pasta failed its sandbox mount (STALE_SANDBOX): the stale
      pause is already there.

    Returns which, or None when neither: rootless podman inside a bare
    `systemd-run --uid` transient unit does not always come up in every
    environment. --pipe, since podman's own output goes to its scope's
    journal, not the unit's; --collect, so a failed run leaves no failed
    unit behind.
    """
    target.run(["systemctl", "stop", SERVICE], sudo=True, check=False)
    arm_unit = "wlrt-armpause"
    arm = target.run(
        ["sh", "-c",
         f"cd / && systemd-run --uid={uid} --unit={arm_unit} "
         f"-p PrivateTmp=yes --collect --pipe --wait --quiet "
         f"--setenv=XDG_RUNTIME_DIR=/run/user/{uid} "
         f"--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "
         f"podman run --rm --network=pasta --entrypoint=/bin/sh {IMAGE} -c 'exit 0'"],
        sudo=True, check=False,
    )
    paused = target.run(["test", "-f", f"/run/user/{uid}/libpod/tmp/pause.pid"],
                        sudo=True, check=False).ok
    aj = target.run(["journalctl", "--no-pager", "-n", "20",
                     "-u", f"{arm_unit}.service"], sudo=True, check=False)
    how = None
    if paused and arm.rc == 0:
        how = "planted"
    elif paused and STALE_SANDBOX in arm.stdout + arm.stderr:
        how = "left by the stop"
    print(f"\n----- stale-pause arm: {how or 'not established'} (arm rc={arm.rc}) -----\n"
          f"{arm.stderr[-1500:]}\n{aj.stdout}\n"
          f"----------------------------------------------------")
    return how


def test_pasta_restart_resilience(target):
    """A pasta workload survives 3 restart+host-podman-touch cycles staying
    active every time and never climbing NRestarts toward StartLimitBurst, and
    (best-effort) starts clean over a deliberately-armed stale pasta pause."""
    _install_toml(target, "rt-basic.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            _diagnose(target, _resolve_uid(target))
            raise

        uid = _resolve_uid(target)
        burst = _start_limit_burst(target)

        # --- Primary: restart + host-side podman touch, 3x ---
        for i in range(1, 4):
            r = target.run(["systemctl", "restart", SERVICE], sudo=True, check=False)
            if r.rc != 0:
                _diagnose(target, uid)
            assert r.rc == 0, f"iteration {i}: `systemctl restart {SERVICE}` failed:\n{r.stderr}"
            _assert_active(target, uid, f"after restart iteration {i}")
            # Host-side podman touch: the op that historically re-armed the pause.
            _rootless(target, uid, ["podman", "ps"])
            _assert_active(target, uid, f"after podman touch iteration {i}")

        # No auto-restart storm: the pasta ENOENT loop would drive NRestarts up
        # toward StartLimitBurst. A healthy unit stays well under it.
        nr = _nrestarts(target)
        print(f"\n----- {SERVICE} NRestarts={nr} StartLimitBurst={burst} -----")
        if nr >= burst:
            _diagnose(target, uid)
        assert nr < burst, (
            f"{SERVICE} NRestarts={nr} reached StartLimitBurst={burst} — "
            f"restart-loop (pasta stale-pause regression?)"
        )

        # --- Best-effort: faithful stale-pause arm, then prove clean recovery ---
        how = _arm_stale_pause(target, uid)
        if how:
            target.run(["systemctl", "start", SERVICE], sudo=True, check=False)
            _assert_active(target, uid, f"after starting over a stale pause ({how})")
        else:
            print("stale-pause arm not established in this environment; "
                  "observable-surface assertions above carry the invariant "
                  "(the arm is expected to establish under gate mode).")
    finally:
        _purge_workload(target, WORKLOAD)
