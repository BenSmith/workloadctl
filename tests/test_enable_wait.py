#!/usr/bin/env python3
"""`enable --wait` and the container line in `status`.

A container unit is Type=exec, so it reads active from podman's exec on,
while the image may still be pulling. On the services host, a test that
ran `enable`, slept, read `status` and then stopped the workload stopped
it mid-pull: the container had never run, and "active (running)" said
nothing of that. `--wait` polls what `health` checks; `status` names the
container's own state.
"""

import io
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import cmd_enable
import cmd_inspect
from cli_parser import build_parser
from podman import PodmanError


def _report(*failing):
    checks = [{"check": "service_status", "healthy": True,
               "message": "Service active and running"}]
    checks += [{"check": c, "healthy": False, "message": m}
               for c, m in failing]
    return {"workload": "web", "checks": checks}, not failing


NO_CONTAINER = ("container_running", "Container not running")


class Clock:
    """A clock that the fake sleep advances."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = 0

    def __call__(self):
        return self.now

    def sleep(self, s):
        self.sleeps += 1
        self.now += s


class TheWaitFlag(unittest.TestCase):

    def parse(self, *argv):
        return build_parser().parse_args(["enable", "web", *argv])

    def test_absent_means_no_wait(self):
        self.assertIsNone(self.parse().wait)

    def test_bare_waits_the_default(self):
        self.assertEqual(self.parse("--wait").wait, 300)

    def test_a_value_is_the_timeout(self):
        self.assertEqual(self.parse("--wait", "60").wait, 60)


class WaitHealthy(unittest.TestCase):

    def setUp(self):
        self.config = types.SimpleNamespace(
            name="web", service_name="workload-web.service")
        self.clock = Clock()

    def wait(self, reports, timeout=30):
        it = iter(reports)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cmd_enable, "health_report",
                               side_effect=lambda c, m: next(it)), \
                mock.patch.object(cmd_enable, "emit_result") as emit, \
                redirect_stdout(out), redirect_stderr(err):
            try:
                cmd_enable._wait_healthy(self.config, None, timeout,
                                         clock=self.clock,
                                         sleep=self.clock.sleep)
                code = None
            except SystemExit as e:
                code = e.code
        return code, out.getvalue() + err.getvalue(), emit

    def test_returns_once_the_container_is_up(self):
        code, text, emit = self.wait(
            [_report(NO_CONTAINER), _report(NO_CONTAINER), _report()])
        self.assertIsNone(code)
        self.assertEqual(self.clock.sleeps, 2)
        self.assertIn("is healthy", text)
        emit.assert_not_called()

    def test_a_pull_that_outlasts_the_timeout_fails_naming_the_check(self):
        code, text, emit = self.wait([_report(NO_CONTAINER)] * 100,
                                     timeout=10)
        self.assertEqual(code, 1)
        self.assertIn("not healthy after 10s: Container not running", text)
        self.assertIn("stays enabled", text)
        (rows,), kw = emit.call_args
        self.assertEqual(rows[0]["result"], "failed")
        self.assertFalse(kw["ok"])
        self.assertLessEqual(self.clock.now, 10 + cmd_enable.WAIT_POLL)

    def test_every_failing_check_is_named(self):
        code, text, _ = self.wait(
            [_report(("container_health", "Container health: starting"),
                     ("port_accessibility", "Port 80 not accessible"))] * 50,
            timeout=4)
        self.assertEqual(code, 1)
        self.assertIn("Container health: starting; Port 80 not accessible",
                      text)


MANAGER = mock.MagicMock(name="manager")


class TheWaitIsWired(unittest.TestCase):
    """cmd_enable calls the wait after the start, and only when asked."""

    def run_enable(self, wait):
        args = types.SimpleNamespace(workload="web", wait=wait, json=False)
        config = mock.MagicMock(is_vm=False, service_name="workload-web.service")
        patches = [
            mock.patch.object(cmd_enable, n) for n in (
                "require_root", "workload_enabled_marker", "preflight_checks",
                "run_host_setup", "apply_selinux_policy", "apply_vm_fcontext",
                "generate_units", "provision_user", "apply_shares",
                "transfer_image", "start_service", "emit_result",
                "_wait_healthy")]
        patches += [
            mock.patch.object(cmd_enable, "WorkloadConfig",
                              return_value=config),
            mock.patch.object(cmd_enable, "workload_config_path",
                              return_value=mock.MagicMock(
                                  exists=lambda: True)),
            mock.patch.object(cmd_enable.subprocess, "run",
                              return_value=mock.MagicMock(returncode=3)),
        ]
        mocks = [p.start() for p in patches]
        self.addCleanup(mock.patch.stopall)
        with redirect_stdout(io.StringIO()):
            cmd_enable.cmd_enable(args, MANAGER)
        named = dict(zip(
            ("require_root", "workload_enabled_marker", "preflight_checks",
             "run_host_setup", "apply_selinux_policy", "apply_vm_fcontext",
             "generate_units", "provision_user", "apply_shares",
             "transfer_image", "start_service", "emit_result",
             "_wait_healthy"), mocks))
        return named, config

    def test_wait_runs_after_the_start_with_its_timeout(self):
        m, config = self.run_enable(45)
        m["_wait_healthy"].assert_called_once_with(config, MANAGER, 45)
        self.assertTrue(m["start_service"].called)

    def test_no_wait_without_the_flag(self):
        m, _ = self.run_enable(None)
        m["_wait_healthy"].assert_not_called()


class ContainerState(unittest.TestCase):

    def manager(self, status=None, health=None, raises=None, user=True):
        client = mock.MagicMock()
        client.container_status.side_effect = raises or (lambda n: status)
        client.container_health.return_value = health
        m = mock.MagicMock()
        m.user_exists.return_value = user
        m.podman.return_value = client
        return m

    def config(self, **kw):
        d = dict(is_vm=False, is_multi=False, container_name="workload-web")
        d.update(kw)
        return types.SimpleNamespace(**d)

    def test_running_with_health(self):
        state = cmd_inspect.container_state(
            self.config(), self.manager("Up 3 minutes", "healthy"))
        self.assertEqual(state, {"running": True, "status": "Up 3 minutes",
                                 "health": "healthy"})

    def test_no_container_yet(self):
        state = cmd_inspect.container_state(self.config(), self.manager())
        self.assertEqual(state, {"running": False, "status": None,
                                 "health": None})

    def test_nothing_to_ask(self):
        for config, manager in [
                (self.config(is_vm=True), self.manager()),
                (self.config(is_multi=True), self.manager()),
                (self.config(), self.manager(user=False)),
                (self.config(), None),
                (self.config(), self.manager(raises=PodmanError(1, "no", [])))]:
            self.assertIsNone(cmd_inspect.container_state(config, manager))


class ContainerLine(unittest.TestCase):

    def test_an_active_unit_with_no_container_says_so(self):
        line = cmd_inspect.container_line(
            {"running": False, "status": None, "health": None}, True)
        self.assertIn("none yet", line)
        self.assertIn("pulling the image", line)

    def test_an_inactive_unit(self):
        self.assertEqual(cmd_inspect.container_line(
            {"running": False, "status": None, "health": None}, False),
            "Container: not running")

    def test_running(self):
        self.assertEqual(cmd_inspect.container_line(
            {"running": True, "status": "Up 3 minutes", "health": "healthy"},
            True), "Container: running (Up 3 minutes), health: healthy")



class StatusShowsTheContainer(unittest.TestCase):
    """cmd_status asks container_state, in JSON and in text."""

    STATE = {"running": False, "status": None, "health": None}

    def status(self, as_json):
        args = types.SimpleNamespace(workload="web", json=as_json)
        config = mock.MagicMock(is_multi=False, service_name="workload-web.service")
        config.name = "web"
        out = io.StringIO()
        with mock.patch.object(cmd_inspect, "WorkloadConfig",
                               return_value=config), \
                mock.patch.object(cmd_inspect, "container_state",
                                  return_value=self.STATE) as asked, \
                mock.patch.object(cmd_inspect, "systemctl_show",
                                  return_value={}), \
                mock.patch.object(cmd_inspect, "units_outdated",
                                  return_value=False), \
                mock.patch.object(cmd_inspect, "units_from_other_build",
                                  return_value=None), \
                mock.patch.object(cmd_inspect, "uses_host_userns",
                                  return_value=False), \
                mock.patch.object(cmd_inspect.deployment, "read_marker",
                                  return_value=None), \
                mock.patch.object(cmd_inspect, "get_substrate"), \
                mock.patch.object(cmd_inspect.subprocess, "run",
                                  return_value=mock.MagicMock(returncode=0)), \
                redirect_stdout(out):
            cmd_inspect.cmd_status(args, "manager")
        asked.assert_called_once_with(config, "manager")
        return out.getvalue()

    def test_json_carries_it(self):
        import json
        self.assertEqual(json.loads(self.status(True))["container"],
                         self.STATE)

    def test_text_names_it(self):
        self.assertIn("Container: none yet", self.status(False))


if __name__ == "__main__":
    unittest.main()
