"""The forge takes no sign-ups, and forgejo-runner's setup hook creates its
runner for one user, organisation or repository, never for the whole forge.

Audit L19 (2026-10-17): the services host's forge had open sign-up and its
runner was created with POST /api/v1/admin/actions/runners, an instance
runner (owner_id 0, repo_id 0), so anyone on the LAN could sign up, push a
workflow and run it on the runner VM, whose jobs have sudo and reach the
image signing key. On the proving host a runner the hook created at its
default scope belonged to the token's user, and the same POST at /admin
made an instance runner. Forgejo 15 asks for write:user, write:repository
or write:organization at those scopes, write:admin at the instance.
"""
import json
import os
import tomllib
import stat
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WORKLOADS = Path(__file__).resolve().parent.parent / "workloads"
SETUP = WORKLOADS / "forgejo-runner" / "setup.sh"
NAME = "forgejo-runner"


class TestTheForge(unittest.TestCase):

    def test_sign_up_is_off(self):
        with open(WORKLOADS / "forgejo" / "workload.toml", "rb") as f:
            env = tomllib.load(f)["container"]["environment"]
        self.assertEqual(env.get("FORGEJO__service__DISABLE_REGISTRATION"),
                         "true")


class Forge(BaseHTTPRequestHandler):
    """Records each request; lists one stale runner named like ours."""

    def _answer(self, code, body=b""):
        self.server.calls.append((self.command, self.path))
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._answer(200, json.dumps([{"id": 7, "name": NAME}]).encode())

    def do_DELETE(self):
        self._answer(204)

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        self._answer(201, b'{"uuid": "u-1", "token": "t-1"}')

    def log_message(self, *args):
        pass


class TestRunnerScope(unittest.TestCase):

    def _enable(self, scope=None):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        server = ThreadingHTTPServer(("127.0.0.1", 0), Forge)
        server.calls = []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        url = "http://127.0.0.1:%d" % server.server_port
        lines = ["[vm.cloud_init.template_vars]",
                 'FORGEJO_ADMIN_URL = "%s"' % url,
                 'SAME_HOST_HOSTNAMES = "forge.local"']
        if scope is not None:
            lines.append('FORGEJO_RUNNER_SCOPE = "%s"' % scope)
        (tmp / "workload.toml").write_text("\n".join(lines) + "\n")
        creds = tmp / "credstore"
        creds.mkdir()
        (creds / "forgejo-admin-token").write_text("sealed")
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        # decrypt prints the token; encrypt writes stdin to its last argument.
        stub = bin_dir / "systemd-creds"
        stub.write_text('#!/bin/bash\n'
                        'if [ "$1" = decrypt ]; then echo admin-token; '
                        'else cat > "${@: -1}"; fi\n')
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        script = SETUP.read_text()
        self.assertIn("/etc/credstore.encrypted", script)
        script = script.replace("/etc/credstore.encrypted", str(creds))
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
               "WORKLOAD_NAME": NAME, "WORKLOAD_INSTANCE_DIR": str(tmp)}
        result = subprocess.run(["bash", "-c", script, "setup.sh", "enable"],
                                env=env, capture_output=True, text=True,
                                timeout=30)
        return result, server.calls

    def _assert_scope(self, scope, prefix):
        result, calls = self._enable(scope)
        self.assertEqual(result.returncode, 0, result.stderr)
        runners = "/api/v1/%s/actions/runners" % prefix
        self.assertEqual(calls, [("GET", runners),
                                 ("DELETE", runners + "/7"),
                                 ("POST", runners)])

    def test_by_default_the_runner_is_the_tokens_users(self):
        self._assert_scope(None, "user")

    def test_a_name_is_an_organisation(self):
        self._assert_scope("homelab", "orgs/homelab")

    def test_owner_and_repo_is_one_repository(self):
        self._assert_scope("ben/hypervisor", "repos/ben/hypervisor")

    def test_a_scope_that_is_not_a_name_is_refused_before_any_request(self):
        for scope in ("../admin", "a/b/c", "/admin", "a b"):
            with self.subTest(scope=scope):
                result, calls = self._enable(scope)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_nothing_is_created_for_the_whole_forge(self):
        self.assertNotIn("admin/actions/runners", SETUP.read_text())


if __name__ == "__main__":
    unittest.main()
