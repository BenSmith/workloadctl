"""Untagged images are pruned from a workload's own store after a verified
update, a recreate and an enable's transfer, and nowhere else."""

import io
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from subprocess import CompletedProcess
from unittest import mock

import cmd_enable
import cmd_images
import cmd_update
import substrate_container as container_mod
from podman import Podman
from substrate import ProvisionFailed
from substrate_container import ContainerSubstrate
from tests.test_substrate import SINGLE_TOML, _make_config, _patch_uid


def _proc(stdout="", stderr="", code=0):
    return CompletedProcess([], code, stdout=stdout, stderr=stderr)


class PruneDangling(unittest.TestCase):

    def podman(self):
        return Podman.for_user("_wl-test", 5001, "/var/lib/workloads/test/state")

    def test_argv_is_image_prune_f_as_the_workload_user(self):
        p = self.podman()
        with mock.patch.object(Podman, "_spawn",
                               return_value=_proc("deadbeef\n")) as spawn:
            self.assertTrue(p.prune_dangling())
        (args,), _ = spawn.call_args
        self.assertEqual(tuple(args), ("image", "prune", "-f"))
        self.assertNotIn("-a", args)
        self.assertNotIn("--all", args)
        cmd = p._build_cmd(*args)
        self.assertEqual(cmd[-3:], ["image", "prune", "-f"])
        self.assertIn("HOME=/var/lib/workloads/test/state", " ".join(cmd))

    def test_nothing_removed_is_false(self):
        with mock.patch.object(Podman, "_spawn", return_value=_proc("")):
            self.assertFalse(self.podman().prune_dangling())

    def test_failed_prune_warns_and_does_not_raise(self):
        with mock.patch.object(Podman, "_spawn",
                               return_value=_proc("", "boom", 125)), \
                redirect_stderr(io.StringIO()) as err, \
                redirect_stdout(io.StringIO()) as out:
            self.assertFalse(self.podman().prune_dangling())
        self.assertIn("boom", err.getvalue() + out.getvalue())

    def test_raising_prune_warns_and_does_not_raise(self):
        with mock.patch.object(Podman, "_spawn", side_effect=OSError("gone")), \
                redirect_stderr(io.StringIO()) as err, \
                redirect_stdout(io.StringIO()) as out:
            self.assertFalse(self.podman().prune_dangling())
        self.assertIn("gone", err.getvalue() + out.getvalue())

    def test_images_prune_goes_through_the_method(self):
        entry = types.SimpleNamespace(pw_name="_wl-test", pw_uid=10005,
                                      pw_dir="/var/lib/workloads/test/state")
        pod = mock.MagicMock()
        pod.prune_dangling.return_value = True
        buf = io.StringIO()
        with mock.patch.object(cmd_images, "require_root"), \
                mock.patch("pwd.getpwall", return_value=[entry]), \
                mock.patch.object(cmd_images.Podman, "for_user",
                                  return_value=pod) as for_user, \
                redirect_stdout(buf):
            cmd_images.cmd_images(types.SimpleNamespace(
                json=False, workload=None, subcommand="prune"), mock.MagicMock())
        for_user.assert_called_once_with(
            "_wl-test", 10005, "/var/lib/workloads/test/state")
        pod.prune_dangling.assert_called_once_with()
        self.assertIn("Image pruning complete", buf.getvalue())


class UpdatePrunes(unittest.TestCase):

    def cfg(self, name, health=True):
        c = mock.Mock()
        c.name = name
        c.has_health_check.return_value = health
        c.is_multi = False
        c.service_name = f"workload-{name}.service"
        c.container_health_blocks.return_value = [(name, f"workload-{name}", {})]
        return c

    def verify(self, entries, health, active=True):
        """entries: [(cfg, old_ids)]; health: {name: status}. Returns
        (rollbacks, {name: its Podman mock})."""
        pods = {}
        for cfg, _ in entries:
            pod = mock.Mock()
            pod.container_health.return_value = health.get(cfg.name, "healthy")
            pods[cfg.name] = pod
        mgr = mock.Mock()
        mgr.podman.side_effect = lambda c: pods[c.name]
        with mock.patch.object(cmd_update.time, "sleep"), \
                mock.patch.object(cmd_update, "_health_wait_seconds",
                                  return_value=0), \
                mock.patch.object(cmd_update.subprocess, "run",
                                  return_value=mock.Mock(
                                      returncode=0 if active else 3)), \
                mock.patch.object(cmd_update, "_do_rollback") as rb, \
                redirect_stdout(io.StringIO()):
            n = cmd_update._verify_all(entries, mgr)
        self.rb = rb
        return n, pods

    def test_healthy_prunes(self):
        n, pods = self.verify([(self.cfg("a"), {"a": "old"})], {})
        self.assertEqual(n, 0)
        pods["a"].prune_dangling.assert_called_once_with()

    def test_active_without_health_check_prunes(self):
        n, pods = self.verify([(self.cfg("a", health=False), {"a": "old"})], {})
        self.assertEqual(n, 0)
        pods["a"].prune_dangling.assert_called_once_with()

    def test_starting_then_healthy_prunes(self):
        cfg = self.cfg("a")
        cfg.container_health_blocks.return_value = [
            ("a", "workload-a", {"interval": "5s"})]
        pod = mock.Mock()
        pod.container_health.side_effect = ["starting", "healthy"]
        mgr = mock.Mock()
        mgr.podman.return_value = pod
        with mock.patch.object(cmd_update.time, "sleep"), \
                mock.patch.object(cmd_update, "_health_wait_seconds",
                                  return_value=0), \
                redirect_stdout(io.StringIO()):
            cmd_update._verify_all([(cfg, {"a": "old"})], mgr)
        pod.prune_dangling.assert_called_once_with()

    def test_rollback_does_not_prune(self):
        n, pods = self.verify([(self.cfg("a"), {"a": "old"})],
                              {"a": "unhealthy"})
        self.assertEqual(n, 1)
        self.rb.assert_called_once()
        pods["a"].prune_dangling.assert_not_called()

    def test_crashed_rollback_does_not_prune(self):
        n, pods = self.verify([(self.cfg("a", health=False), {"a": "old"})],
                              {}, active=False)
        self.assertEqual(n, 1)
        pods["a"].prune_dangling.assert_not_called()

    def test_unhealthy_without_previous_image_does_not_prune(self):
        n, pods = self.verify([(self.cfg("a"), {"a": None})],
                              {"a": "unhealthy"})
        self.assertEqual(n, 0)
        self.rb.assert_not_called()
        pods["a"].prune_dangling.assert_not_called()

    def test_all_prunes_only_the_healthy_workload(self):
        a, b = self.cfg("a"), self.cfg("b")
        n, pods = self.verify([(a, {"a": "old"}), (b, {"b": "old"})],
                              {"a": "healthy", "b": "unhealthy"})
        self.assertEqual(n, 1)
        pods["a"].prune_dangling.assert_called_once_with()
        pods["b"].prune_dangling.assert_not_called()

    def test_failed_prune_does_not_fail_the_update(self):
        cfg = self.cfg("a")
        pod = mock.Mock()
        pod.container_health.return_value = "healthy"
        pod.run.return_value = _proc("", "boom", 125)
        real = Podman.prune_dangling
        mgr = mock.Mock()
        mgr.podman.return_value = pod
        pod.prune_dangling.side_effect = lambda: real(pod)
        with mock.patch.object(cmd_update.time, "sleep"), \
                mock.patch.object(cmd_update, "_health_wait_seconds",
                                  return_value=0), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            n = cmd_update._verify_all([(cfg, {"a": "old"})], mgr)
        self.assertEqual(n, 0)


class RecreatePrunes(unittest.TestCase):

    def substrate(self):
        config = _make_config(SINGLE_TOML, "test-wl")
        manager = mock.MagicMock()
        manager.user_exists.return_value = True
        return ContainerSubstrate(config, manager), manager

    def test_recreate_prunes_after_the_restart(self):
        sub, manager = self.substrate()
        order = mock.Mock()
        order.attach_mock(manager.podman.return_value.prune_dangling, "prune")
        with _patch_uid(10001), \
                mock.patch.object(container_mod, "restart_workload_service",
                                  order.restart):
            with redirect_stdout(io.StringIO()):
                sub.reprovision(recreate=True)
        self.assertEqual([c[0] for c in order.mock_calls],
                         ["restart", "prune"])
        manager.podman.assert_called_with(sub.config)

    def test_recreate_does_not_prune_when_the_restart_fails(self):
        import subprocess
        sub, manager = self.substrate()
        with _patch_uid(10001), \
                mock.patch.object(
                    container_mod, "restart_workload_service",
                    side_effect=subprocess.CalledProcessError(1, "x")), \
                redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            with self.assertRaises(ProvisionFailed):
                sub.reprovision(recreate=True)
        manager.podman.return_value.prune_dangling.assert_not_called()

    def test_recreate_without_the_user_does_not_prune(self):
        """Recreate can run before the workload user exists; the restart is
        then a plain systemctl one, and there is no store to prune."""
        sub, manager = self.substrate()
        manager.user_exists.return_value = False
        with mock.patch.object(container_mod.subprocess, "run") as run, \
                redirect_stdout(io.StringIO()):
            sub.reprovision(recreate=True)
        run.assert_called_once()
        manager.podman.assert_not_called()

    def test_update_path_never_prunes_before_the_rollback_tag(self):
        """transfer_one_image runs before the old image is tagged as the
        rollback target; a prune in between could delete that image."""
        sub, manager = self.substrate()
        pod = manager.podman.return_value
        pod.image_id.side_effect = ["old-id", "new-id"]
        order = mock.Mock()
        order.attach_mock(pod, "pod")
        with mock.patch.object(container_mod, "transfer_one_image",
                               order.transfer), \
                mock.patch.object(container_mod, "restart_workload_service"), \
                _patch_uid(10001), \
                mock.patch.object(container_mod.Podman, "for_root"), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            sub.reprovision()
        names = [c[0] for c in order.mock_calls]
        self.assertIn("transfer", names)
        self.assertIn("pod.tag", names)
        self.assertLess(names.index("transfer"), names.index("pod.tag"))
        self.assertNotIn("pod.prune_dangling", names)

    def test_vm_recreate_never_prunes(self):
        from substrate_vm import VMSubstrate
        from tests.test_substrate import _make_vm_config
        manager = mock.MagicMock()
        sub = VMSubstrate(_make_vm_config(), manager)
        with mock.patch("subprocess.run", return_value=_proc()), \
                redirect_stdout(io.StringIO()):
            sub.reprovision(recreate=True)
        manager.podman.assert_not_called()


class EnablePrunes(unittest.TestCase):

    def test_enable_prunes_after_the_transfer(self):
        order = mock.Mock()
        mgr = mock.MagicMock()
        order.attach_mock(mgr.podman.return_value.prune_dangling, "prune")
        args = types.SimpleNamespace(workload="web", wait=None, json=False)
        config = mock.MagicMock(is_vm=False,
                                service_name="workload-web.service")
        names = ("require_root", "workload_enabled_marker", "preflight_checks",
                 "run_host_setup", "apply_selinux_policy", "apply_vm_fcontext",
                 "generate_units", "provision_user", "apply_shares",
                 "start_service", "emit_result", "_wait_healthy")
        for n in names:
            self.enterContext(mock.patch.object(cmd_enable, n))
        self.enterContext(mock.patch.object(
            cmd_enable, "transfer_image", order.transfer))
        self.enterContext(mock.patch.object(
            cmd_enable, "WorkloadConfig", return_value=config))
        self.enterContext(mock.patch.object(
            cmd_enable, "workload_config_path",
            return_value=mock.MagicMock(exists=lambda: True)))
        self.enterContext(mock.patch.object(
            cmd_enable.subprocess, "run",
            return_value=mock.MagicMock(returncode=3)))
        with redirect_stdout(io.StringIO()):
            cmd_enable.cmd_enable(args, mgr)
        self.assertEqual([c[0] for c in order.mock_calls],
                         ["transfer", "prune"])
        mgr.podman.assert_called_with(config)

    def test_enable_does_not_prune_a_vm(self):
        mgr = mock.MagicMock()
        args = types.SimpleNamespace(workload="web", wait=None, json=False)
        config = mock.MagicMock(is_vm=True, service_name="workload-web.service")
        for n in ("require_root", "workload_enabled_marker",
                  "preflight_checks", "run_host_setup",
                  "apply_selinux_policy", "apply_vm_fcontext",
                  "generate_units", "provision_user", "apply_shares",
                  "transfer_image", "start_service", "emit_result",
                  "_wait_healthy"):
            self.enterContext(mock.patch.object(cmd_enable, n))
        self.enterContext(mock.patch.object(
            cmd_enable, "WorkloadConfig", return_value=config))
        self.enterContext(mock.patch.object(
            cmd_enable, "workload_config_path",
            return_value=mock.MagicMock(exists=lambda: True)))
        self.enterContext(mock.patch.object(
            cmd_enable.subprocess, "run",
            return_value=mock.MagicMock(returncode=3)))
        with redirect_stdout(io.StringIO()):
            cmd_enable.cmd_enable(args, mgr)
        mgr.podman.assert_not_called()


if __name__ == "__main__":
    unittest.main()
