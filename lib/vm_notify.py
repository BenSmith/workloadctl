"""The VM service's main process: passt, QEMU, readiness, and the guest's exit.

Starts passt and QEMU as children, on the two ends of one socket pair, and
stays alive as the unit's MainPID, connects to QEMU's QMP socket, sends
READY=1 once the guest's vCPUs run, watches the guest's cloud-init from a
daemon thread, and exits with QEMU's status -- or, in [vm].restart =
"on-reboot" mode, with a status that tells a reboot from a poweroff. A passt
that exits takes QEMU down with it, and the unit fails: a guest with no
network looks healthy from everywhere else.
"""
import os
import signal
import socket
import subprocess
import sys
import threading
import time

from egress_selinux import passt_launch_argv, qemu_launch_argv, vm_socketpair
from config_parser import SOCKET_DIR
from qmp import QMPClient
from vm_provision import (marker_reports_failure, marker_vouches_for,
                          read_provision_marker, record_guest_provision_result)
from vm_defs import PASST_ARGS_END, PASST_ARGS_FLAG, PASST_FD_TOKEN
from workload_lib import workload_state_dir

# How long to keep asking the guest whether cloud-init finished, and how often.
# READY=1 goes out when the vCPUs start (~1 s); provisioning runs for tens of
# seconds on a plain seed and for many minutes on one whose runcmd installs
# packages, so the budget is generous — it costs one local socket round trip
# per poll, and the watch exits the moment the guest answers.
PROVISION_WATCH_TIMEOUT = 1800.0
PROVISION_POLL_INTERVAL = 15.0

# How long passt has to exit once QEMU has, before it is killed.
PASST_STOP_TIMEOUT = 5.0


def split_argv(args: list[str]) -> tuple[list[str], list[str]]:
    """The unit's words after the name: (passt's argv, QEMU's argv).

    passt's is empty for a bridged VM, whose ExecStart carries no
    PASST_ARGS_FLAG.
    """
    if not args or args[0] != PASST_ARGS_FLAG:
        return [], list(args)
    try:
        end = args.index(PASST_ARGS_END, 1)
    except ValueError:
        raise ValueError(f"{PASST_ARGS_FLAG} without {PASST_ARGS_END}")
    return list(args[1:end]), list(args[end + 1:])


def start_passt(passt_cmd: list[str], qemu_cmd: list[str], uid: int):
    """Start passt on one end of a socket pair; QEMU's argv for the other.

    Returns passt's Popen, QEMU's argv with PASST_FD_TOKEN replaced, and
    QEMU's end, which the caller passes to QEMU and then closes.
    """
    passt_end, qemu_end = vm_socketpair(uid)
    try:
        passt_fd = passt_end.fileno()
        passt = subprocess.Popen(
            passt_launch_argv([*passt_cmd, "--fd", str(passt_fd)], uid),
            stdin=subprocess.DEVNULL, pass_fds=(passt_fd,))
    except BaseException:
        qemu_end.close()
        raise
    finally:
        passt_end.close()
    qemu_cmd = [arg.replace(PASST_FD_TOKEN, str(qemu_end.fileno()))
                for arg in qemu_cmd]
    return passt, qemu_cmd, qemu_end


def stop_passt(passt) -> None:
    """Stop passt once QEMU has gone."""
    if passt.poll() is not None:
        return
    passt.terminate()
    try:
        passt.wait(timeout=PASST_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        passt.kill()
        passt.wait()


def watch_passt(passt, proc, lost: threading.Event) -> None:
    """Take QEMU down if passt exits under it."""
    rc = passt.wait()
    if proc.poll() is None:
        lost.set()
        print(f"workload-vm-notify: passt exited ({rc}) under a running "
              f"guest; stopping QEMU", file=sys.stderr)
        try:
            proc.terminate()
        except ProcessLookupError:
            pass


def sd_notify(msg: str):
    notify_socket = os.environ.get("NOTIFY_SOCKET", "")
    if not notify_socket:
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            if notify_socket.startswith("@"):
                notify_socket = "\0" + notify_socket[1:]
            s.connect(notify_socket)
            s.sendall(msg.encode())
    except OSError:
        pass


def wait_running(qmp: QMPClient, timeout: float = 120.0):
    """Block until the guest vCPUs are running or `timeout` expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reply = qmp.execute("query-status")
        if bool(reply.get("return", {}).get("running", False)):
            return
        time.sleep(0.5)
    raise TimeoutError(f"Guest did not enter running state within {timeout:.0f}s")


def watch_provisioning(name: str,
                       deadline: float = PROVISION_WATCH_TIMEOUT,
                       interval: float = PROVISION_POLL_INTERVAL) -> None:
    """Record whether this instance's cloud-init actually finished.

    READY=1 means "the vCPUs are running", which is true a good half-minute
    before the guest is provisioned — so nothing on the host has ever known
    whether the per-instance modules (users, sudo drop-ins, runcmd) completed.
    A first boot cut short leaves them half-done *and* marked done by the
    guest's own semaphores, and the host then pins that instance-id forever
    because the seed content never changed. See lib/vm_provision.py.

    We are the VM service's main process, we run as the workload user that owns
    the state dir, and we already live for the guest's whole lifetime, so this
    is the one place that can watch without a new unit. Best-effort throughout:
    every failure path just leaves no record, which callers read as "not
    observed" rather than as a broken guest.

    The question goes to the guest over SSH rather than qemu-guest-agent: the
    agent is confined to virt_qemu_ga_t, which stock guest policy does not let
    read cloud-init's state at all (see lib/vm_provision.py). So the first polls
    of a cold boot normally fail simply because sshd is not up yet, which is an
    ordinary "ask again", not a fault.
    """
    try:
        state_dir = workload_state_dir(name)
        instance_id = (state_dir / ".cloud-init-instance-id").read_text().strip()
    except OSError:
        return
    if not instance_id:
        return

    marker = read_provision_marker(state_dir)
    if (marker_vouches_for(marker, instance_id)
            or marker_reports_failure(marker, instance_id)):
        return  # outcome already recorded for this instance; nothing to watch

    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            status = record_guest_provision_result(state_dir, instance_id, name)
        except Exception as e:
            print(f"workload-vm-notify: provisioning watch error: {e}",
                  file=sys.stderr)
            return
        if status is not None:
            print(f"workload-vm-notify: cloud-init reported {status} for "
                  f"instance {instance_id}", flush=True)
            return
        time.sleep(interval)

    print(f"workload-vm-notify: cloud-init outcome unknown for instance "
          f"{instance_id} after {deadline:.0f}s (the guest never answered). "
          f"Provisioning is unverified, not failed.", file=sys.stderr)


def monitor_shutdown_reason(name: str, proc) -> str | None:
    """Watch the guest's QMP SHUTDOWN event and return its `reason`.

    Used only in [vm].restart = "on-reboot" mode to tell a guest reboot from a
    poweroff. QEMU runs with -no-reboot, so both exit QEMU with status 0; only
    the SHUTDOWN event distinguishes them:
      "guest-reset"    → the guest rebooted (should relaunch)
      "guest-shutdown" → the guest powered off (should stay down)
    Watches a DEDICATED monitor (qmp-notify.sock) so it never contends with the
    control socket (ExecStop's system_powerdown) or the metrics socket. Reads
    until the event arrives or the monitor closes (QEMU gone). Best-effort:
    returns None on any error, so a monitoring hiccup falls back to QEMU's own
    exit code rather than breaking the VM lifecycle.
    """
    sock_path = str(SOCKET_DIR / name / "qmp-notify.sock")
    qmp = QMPClient()
    try:
        qmp.connect(sock_path, timeout=60.0, recv_timeout=2.0)
        qmp.negotiate()
        while True:
            try:
                msg = qmp.next_message()
            except ConnectionError:
                return None  # monitor closed before a SHUTDOWN was seen
            if msg is None:
                # Read timeout: keep waiting only while QEMU is alive. (Buffered
                # messages are still drained first — recv returns queued bytes
                # before it ever signals close — so a SHUTDOWN emitted right
                # before exit isn't lost to this liveness check.)
                if proc.poll() is not None:
                    return None
                continue
            if msg.get("event") == "SHUTDOWN":
                return msg.get("data", {}).get("reason")
    except Exception as e:
        print(f"workload-vm-notify: shutdown-reason monitor error: {e}",
              file=sys.stderr)
        return None
    finally:
        qmp.close()


def supervise(name: str, qemu_cmd: list[str],
              passt_cmd: list[str] | None = None) -> int:
    """Run passt and QEMU for one VM and hold the unit's main PID.

    READY=1 goes out when the guest's vCPUs run, the cloud-init watch runs
    beside QEMU for its whole lifetime, and the status is QEMU's own unless
    on-reboot mode translates the guest's shutdown reason into one, or passt
    exited under it.
    """
    uid = os.getuid()
    passt = qemu_end = None
    if passt_cmd:
        passt, qemu_cmd, qemu_end = start_passt(passt_cmd, qemu_cmd, uid)
    try:
        return run_qemu(name, qemu_cmd, uid, passt, qemu_end)
    finally:
        if passt is not None:
            stop_passt(passt)


def run_qemu(name: str, qemu_cmd: list[str], uid: int, passt=None,
             qemu_end=None) -> int:
    """QEMU's part of supervise: start, readiness, exit status."""
    qmp_sock = str(SOCKET_DIR / name / "qmp.sock")

    # Start QEMU as a child process. We stay alive to hold the service's
    # main PID; systemd tracks *us* for cgroup membership.
    #
    # qemu_launch_argv prefixes runcon so QEMU enters svirt_t (ADR 006 step 3).
    # runcon execs QEMU in its own process rather than forking, so `proc` is
    # still QEMU itself — the pid we signal below and the pid systemd sees are
    # unchanged by confinement.
    # The unit runs as the workload user, whose uid gives the VM its level.
    try:
        proc = subprocess.Popen(
            qemu_launch_argv(qemu_cmd, uid), stdin=subprocess.DEVNULL,
            pass_fds=(qemu_end.fileno(),) if qemu_end is not None else ())
    finally:
        if qemu_end is not None:
            qemu_end.close()
    lost, stopping = threading.Event(), threading.Event()
    if passt is not None:
        threading.Thread(target=watch_passt, args=(passt, proc, lost),
                         name="passt-watch", daemon=True).start()

    # Forward SIGTERM/SIGINT to QEMU. In a normal stop the graceful ExecStop
    # (workload-vm-shutdown) has already powered the guest off and QEMU has
    # exited before systemd's kill phase, so this never fires. It's the
    # last-resort hard kill if the guest ignored ACPI and ExecStop timed out;
    # if QEMU is already dead these are no-ops.
    def _forward(sig, _frame):
        # systemd's stop signals passt as well: its exit then is the stop's.
        stopping.set()
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)

    qmp = QMPClient()
    try:
        # Wait up to 60 s for QEMU to create the QMP socket -- and give each
        # read the same budget. QEMU opens the listener before machine init
        # and only services the monitor once its main loop runs, so the
        # greeting can lag a successful connect by seconds on a loaded host
        # (the run that found this was nested, with a disk copy just landed).
        # A read timeout is a TimeoutError and would land in the no-READY arm
        # below, leaving a booted guest to sit out TimeoutStartSec.
        qmp.connect(qmp_sock, timeout=60.0, recv_timeout=60.0)
        qmp.negotiate()
        # Wait up to 120 s for guest vCPUs to start running
        wait_running(qmp, timeout=120.0)
        sd_notify("READY=1")
    except TimeoutError as e:
        print(f"workload-vm-notify: {e}", file=sys.stderr)
        sd_notify(f"STATUS=Timeout waiting for QMP: {e}")
        # Don't kill QEMU — let systemd's TimeoutStartSec handle it.
        # We fall through to proc.wait() so we exit when QEMU does.
    except Exception as e:
        # Best-effort: still send READY so the unit doesn't hang on this
        # wrapper, but flag the degraded state via STATUS so `systemctl
        # status` and the journal make the broken QMP path visible.
        print(f"workload-vm-notify: QMP error: {e}", file=sys.stderr)
        sd_notify(f"STATUS=Degraded: QMP unavailable ({e}); guest may still be running")
        sd_notify("READY=1")
    finally:
        qmp.close()

    # Watch the guest's cloud-init from here on. A daemon thread so it can never
    # hold up the exit paths below: whatever it has learned by the time QEMU
    # goes away is already persisted, and what it hasn't is simply unrecorded.
    threading.Thread(target=watch_provisioning, args=(name,),
                     name="provision-watch", daemon=True).start()

    # on-reboot mode: the generator arms this env var and adds qmp-notify.sock.
    # Translate the guest's shutdown reason into an exit code the unit's
    # Restart=on-failure acts on — nonzero for a reboot (relaunch), 0 for a
    # poweroff (stay down). Anything else falls through to QEMU's own code.
    reboot_exit = os.environ.get("WORKLOADCTL_VM_REBOOT_EXIT")
    if reboot_exit:
        reason = monitor_shutdown_reason(name, proc)
        rc = proc.wait()
        if lost.is_set() and not stopping.is_set():
            return 1
        if reason == "guest-reset":
            return int(reboot_exit)
        if reason == "guest-shutdown":
            return 0
        return rc

    # Wait for QEMU to exit and propagate its exit code
    rc = proc.wait()
    return 1 if lost.is_set() and not stopping.is_set() else rc
