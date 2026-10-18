#!/usr/bin/env python3
"""passt runs beside QEMU, so QEMU can run its own -sandbox (audit F21).

QEMU's `-netdev passt` launched passt itself, and a filter QEMU installs is
inherited by what it starts: passt failed under even `-sandbox on`
(measured with QEMU 10.2.2, 2026-10). QEMU's own netdev made a socket pair
and gave passt one end as `--fd` (net/passt.c); workload-vm-notify now does
the same before QEMU starts, and QEMU takes the other end as a stream
netdev. passt has to reach passt_t: run as svirt_t it cannot create the user
namespace it isolates itself in (the dev host's policy, read 2026-10-14:
svirt_t has no user_namespace create, passt_t has).

A bridged VM's QEMU ran qemu-bridge-helper itself, so it ran without
-sandbox; the wrapper now runs the helper and hands QEMU the tap's fd, as
QEMU's bridge netdev did (net/tap.c).

Tested here: the wrapper's argv split, the pair and both launches, passt's
death taking QEMU down, the bridge helper's tap, the labelled pair, runcon's
contexts, and the generator's ExecStart parsed by the wrapper's own split.
"""

import os
import shlex
import signal
import socket
import threading
import unittest
from unittest import mock

import egress_selinux
import gen_vm
import vm_notify
from vm_defs import BRIDGE_HELPER, PASST_FD_TOKEN, QEMU_SANDBOX, TAP_FD_TOKEN
from workload_mcs import mcs_level


class TheSplit(unittest.TestCase):
    def test_without_either_flag_it_is_qemu_alone(self):
        self.assertEqual(vm_notify.split_argv(["qemu", "-m", "1G"]),
                         ([], None, ["qemu", "-m", "1G"]))

    def test_passts_words_end_at_the_marker(self):
        self.assertEqual(
            vm_notify.split_argv(["--passt", "passt", "-t", "1:2", "--",
                                  "qemu", "--", "x"]),
            (["passt", "-t", "1:2"], None, ["qemu", "--", "x"]))

    def test_a_bridged_vm_names_its_bridge(self):
        self.assertEqual(
            vm_notify.split_argv(["--bridge", "br0", "--", "qemu", "--"]),
            ([], "br0", ["qemu", "--"]))

    def test_a_missing_marker_is_refused(self):
        for flag in ("--passt", "--bridge"):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                vm_notify.split_argv([flag, "x", "qemu"])

    def test_a_bridge_is_one_word(self):
        with self.assertRaises(ValueError):
            vm_notify.split_argv(["--bridge", "br0", "br1", "--", "qemu"])


def _is_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


class FakeProc:
    """A Popen that records its argv and fds, and exits when told."""

    def __init__(self, argv, **kw):
        self.argv, self.kw = argv, kw
        self.returncode = None
        self.exited = threading.Event()
        self.signals = []
        # Whether each passed fd is open at the launch, as the child sees it.
        self.fds_open = [_is_open(fd) for fd in kw.get("pass_fds", ())]

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if not self.exited.wait(timeout):
            raise vm_notify.subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode

    def exit(self, rc):
        self.returncode = rc
        self.exited.set()

    def send_signal(self, sig):
        self.signals.append(sig)
        self.exit(-sig)

    def terminate(self):
        self.send_signal(signal.SIGTERM)

    def kill(self):
        self.send_signal(signal.SIGKILL)


PASST_CMD = ["/usr/bin/passt", "--quiet", "--foreground"]
QEMU_CMD = ["/usr/bin/qemu-system-x86_64",
            f"-netdev stream,id=net0,addr.type=fd,addr.str={PASST_FD_TOKEN}",
            "-nographic"]
QEMU_TAP_CMD = ["/usr/bin/qemu-system-x86_64",
                f"-netdev tap,id=net0,fd={TAP_FD_TOKEN}", "-nographic"]


class TheLaunch(unittest.TestCase):
    """start_passt and supervise, with Popen, runcon and QMP faked."""

    def setUp(self):
        self.procs = []
        self.handlers = {}
        self.pairs = []

        self.helper_gives_a_tap = True
        self.helper_rc = 0
        self.taps = []

        def popen(argv, **kw):
            proc = FakeProc(argv, **kw)
            self.procs.append(proc)
            if argv[0] == BRIDGE_HELPER:
                self._helper(proc)
            return proc

        def pair(uid):
            ends = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            self.pairs.append((uid, ends))
            return ends

        self._patch(vm_notify.subprocess, "Popen", popen)
        self._patch(vm_notify, "vm_socketpair", pair)
        self._patch(vm_notify, "passt_launch_argv",
                    lambda cmd, uid: ["runcon", f"passt@{uid}", *cmd])
        self._patch(vm_notify, "qemu_launch_argv",
                    lambda cmd, uid: ["runcon", f"svirt@{uid}", *cmd])
        self._patch(vm_notify, "QMPClient", mock.MagicMock)
        self._patch(vm_notify, "wait_running", lambda qmp, timeout: None)
        self._patch(vm_notify, "sd_notify", lambda msg: None)
        self._patch(vm_notify, "watch_provisioning", lambda name: None)
        self._patch(vm_notify.signal, "signal",
                    lambda sig, handler: self.handlers.update({sig: handler}))
        self._patch(vm_notify.os, "getuid", lambda: 10007)
        self._patch(vm_notify, "PASST_LOSS_GRACE", 0.2)

    def _patch(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _helper(self, proc):
        """qemu-bridge-helper: a tap's fd over --fd's socket, then exit."""
        fd = int(next(a for a in proc.argv
                      if a.startswith("--fd=")).split("=", 1)[1])
        if self.helper_gives_a_tap:
            tap, keep = os.pipe()
            self.addCleanup(os.close, keep)
            with socket.socket(fileno=os.dup(fd)) as sock:
                socket.send_fds(sock, [b"\0"], [tap])
            os.close(tap)
            self.taps.append(keep)
        proc.exit(self.helper_rc if self.helper_gives_a_tap else 1)

    def _supervise_in_thread(self, passt_cmd=PASST_CMD):
        result = {}
        thread = threading.Thread(target=lambda: result.update(
            rc=vm_notify.supervise("vm1", list(QEMU_CMD), passt_cmd)))
        thread.start()
        return thread, result

    def _wait_for(self, n):
        for _ in range(200):
            if len(self.procs) >= n:
                return
            threading.Event().wait(0.01)
        self.fail(f"only {len(self.procs)} processes started")

    def test_passt_gets_one_end_and_qemu_the_other(self):
        passt, qemu_cmd, qemu_end = vm_notify.start_passt(
            PASST_CMD, QEMU_CMD, 10007)
        self.addCleanup(qemu_end.close)
        self.assertEqual(self.pairs[0][0], 10007)
        passt_end, pair_qemu_end = self.pairs[0][1]
        self.assertIs(qemu_end, pair_qemu_end)
        fd = passt.kw["pass_fds"][0]
        self.assertEqual(passt.argv, ["runcon", "passt@10007", *PASST_CMD,
                                      "--fd", str(fd)])
        self.assertEqual(passt.fds_open, [True])
        # The parent's copy of passt's end is closed once passt has it.
        self.assertEqual(passt_end.fileno(), -1)
        self.assertIn(f"addr.str={qemu_end.fileno()}", qemu_cmd[1])
        self.assertNotIn(PASST_FD_TOKEN, " ".join(qemu_cmd))

    def test_supervise_starts_both_and_stops_passt_after_qemu(self):
        thread, result = self._supervise_in_thread()
        self._wait_for(2)
        passt, qemu = self.procs
        self.assertEqual(passt.argv[:2], ["runcon", "passt@10007"])
        self.assertEqual(qemu.argv[:2], ["runcon", "svirt@10007"])
        qemu_fd = qemu.kw["pass_fds"][0]
        self.assertIn(f"addr.str={qemu_fd}", qemu.argv[3])
        self.assertEqual(qemu.fds_open, [True])
        qemu.exit(0)
        thread.join(5)
        self.assertEqual(result["rc"], 0)
        self.assertEqual(passt.signals, [signal.SIGTERM])
        # Both ends are closed in the wrapper.
        for end in self.pairs[0][1]:
            self.assertEqual(end.fileno(), -1)

    def test_passt_exiting_under_a_guest_takes_qemu_down_and_fails(self):
        thread, result = self._supervise_in_thread()
        self._wait_for(2)
        passt, qemu = self.procs
        passt.exit(1)
        thread.join(5)
        self.assertEqual(qemu.signals, [signal.SIGTERM])
        self.assertEqual(result["rc"], 1)

    def test_passt_exiting_in_a_stop_is_the_stops(self):
        """systemd's stop signals passt and the wrapper; QEMU is told by
        the wrapper, not by the watcher, and the status is QEMU's."""
        thread, result = self._supervise_in_thread()
        self._wait_for(2)
        passt, qemu = self.procs
        for _ in range(200):
            if signal.SIGTERM in self.handlers:
                break
            threading.Event().wait(0.01)
        qemu.send_signal = lambda sig: qemu.signals.append(sig)
        self.handlers[signal.SIGTERM](signal.SIGTERM, None)
        passt.exit(0)
        threading.Event().wait(0.4)
        self.assertEqual(qemu.signals, [signal.SIGTERM])
        qemu.exit(0)
        thread.join(5)
        self.assertEqual(result["rc"], 0)

    def test_passt_leaving_as_qemu_shuts_down_is_not_a_loss(self):
        """QEMU closes its end as it exits, and passt follows it out."""
        thread, result = self._supervise_in_thread()
        self._wait_for(2)
        passt, qemu = self.procs
        passt.exit(0)
        qemu.exit(0)
        thread.join(5)
        self.assertEqual(qemu.signals, [])
        self.assertEqual(result["rc"], 0)

    def test_without_a_network_qemu_starts_alone(self):
        thread, result = self._supervise_in_thread(passt_cmd=[])
        self._wait_for(1)
        (qemu,) = self.procs
        self.assertEqual(qemu.kw["pass_fds"], ())
        self.assertEqual(self.pairs, [])
        qemu.exit(0)
        thread.join(5)
        self.assertEqual(result["rc"], 0)

    def test_a_bridged_vm_gets_its_tap_from_the_helper(self):
        result = {}
        thread = threading.Thread(target=lambda: result.update(
            rc=vm_notify.supervise("vm1", list(QEMU_TAP_CMD), [], "br0")))
        thread.start()
        self._wait_for(2)
        helper, qemu = self.procs
        helper_fd = helper.kw["pass_fds"][0]
        self.assertEqual(helper.argv, [BRIDGE_HELPER, "--use-vnet",
                                       f"--fd={helper_fd}", "--br=br0"])
        self.assertEqual(qemu.argv[:2], ["runcon", "svirt@10007"])
        tap = qemu.kw["pass_fds"][0]
        self.assertEqual(qemu.argv[3], f"-netdev tap,id=net0,fd={tap}")
        self.assertEqual(qemu.fds_open, [True])
        self.assertEqual(self.pairs, [])
        qemu.exit(0)
        thread.join(5)
        self.assertEqual(result["rc"], 0)
        # The wrapper's copy of the tap is closed once QEMU has it.
        self.assertFalse(_is_open(tap))

    def _refused_start(self):
        """supervise on a bridge, bounded: a QEMU started anyway is a
        failure here, not a hang."""
        raised = []

        def run():
            try:
                vm_notify.supervise("vm1", list(QEMU_TAP_CMD), [], "br0")
            except RuntimeError as e:
                raised.append(e)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(5)
        started = [p.argv[0] for p in self.procs]
        for proc in self.procs:
            proc.exit(0)
        thread.join(5)
        self.assertEqual(started, [BRIDGE_HELPER])
        self.assertEqual(len(raised), 1)

    def test_a_helper_giving_no_tap_stops_the_start(self):
        self.helper_gives_a_tap = False
        self._refused_start()

    def test_a_helper_failing_after_the_tap_stops_the_start(self):
        self.helper_rc = 1
        self._refused_start()


class TheContexts(unittest.TestCase):
    def test_passt_enters_passt_t_at_the_vms_level(self):
        argv = egress_selinux.passt_launch_argv(
            ["/usr/bin/passt"], 10007, enabled=True, runcon="/bin/sh")
        self.assertEqual(argv, [
            "/bin/sh", f"system_u:system_r:passt_t:{mcs_level(10007)}",
            "/usr/bin/passt"])

    def test_without_selinux_passt_runs_bare(self):
        self.assertEqual(egress_selinux.passt_launch_argv(
            ["/usr/bin/passt"], 10007, enabled=False), ["/usr/bin/passt"])

    def test_the_pair_is_made_at_qemus_context_and_the_label_reset(self):
        writes = []
        real_write = os.write

        def write(fd, data):
            writes.append(data)
            return real_write(fd, data)

        with mock.patch.object(egress_selinux.os, "write", write):
            a, b = egress_selinux.vm_socketpair(10007, enabled=True,
                                                attr=os.devnull)
        a.close()
        b.close()
        self.assertEqual(writes, [
            egress_selinux.vm_qemu_context(10007).encode(), b""])

    def test_without_selinux_the_pair_is_unlabelled(self):
        with mock.patch.object(egress_selinux.os, "open") as opened:
            a, b = egress_selinux.vm_socketpair(10007, enabled=False)
        a.close()
        b.close()
        opened.assert_not_called()


class TheUnit(unittest.TestCase):
    """The generator's ExecStart, read by the wrapper's own split."""

    def _exec_start(self, network):
        config = {"workload": {"name": "web"}, "vm": {"network": network}}
        text = gen_vm.generate_vm_service(config, "_wl-web", 10007)
        joined = text.replace("\\\n", " ")
        line = next(ln for ln in joined.splitlines()
                    if ln.startswith("ExecStart="))
        words = shlex.split(line.split("=", 1)[1])
        self.assertTrue(words[0].endswith("/workload-vm-notify"))
        self.assertEqual(words[1], "web")
        return vm_notify.split_argv(words[2:])

    def test_a_passt_vm_hands_the_wrapper_both_commands(self):
        passt, bridge, qemu = self._exec_start({"egress": "open"})
        self.assertIsNone(bridge)
        self.assertEqual(passt[:3], ["/usr/bin/passt", "--quiet",
                                     "--foreground"])
        self.assertEqual(passt[-1], "$WL_PASST_DNS")
        self.assertNotIn("--fd", passt)
        self.assertTrue(qemu[0].endswith("qemu-system-x86_64"))
        netdev = qemu[qemu.index("-netdev") + 1]
        self.assertTrue(netdev.startswith("stream,id=net0,"))
        self.assertIn(f"addr.str={PASST_FD_TOKEN}", netdev)
        self.assertEqual(" ".join(qemu).count("-sandbox"), 1)
        self.assertIn(QEMU_SANDBOX.split(" ", 1)[1], qemu)

    def test_a_bridged_vm_hands_the_wrapper_its_bridge(self):
        passt, bridge, qemu = self._exec_start({"bridge": "br0"})
        self.assertEqual(passt, [])
        self.assertEqual(bridge, "br0")
        netdev = qemu[qemu.index("-netdev") + 1]
        self.assertEqual(netdev, f"tap,id=net0,fd={TAP_FD_TOKEN}")
        self.assertEqual(" ".join(qemu).count("-sandbox"), 1)
        self.assertIn(QEMU_SANDBOX.split(" ", 1)[1], qemu)


if __name__ == "__main__":
    unittest.main()
