"""What a bundle's instance offers the LAN before anyone configures it.

Audit L19 step 2b (2026-10-17) read every bundle as shipped. Apps that
ask for no login were published on every host interface (F44: SwarmUI's
Server tab starts backends, registry:2 takes anonymous pushes); smb-server's default share
was guest-writable; Sunshine's web UI answered the LAN while its first
visitor set the admin (F45; the image's origin_web_ui_allowed=wan sat in
/etc/sunshine/sunshine.conf, which Sunshine never reads, so its default,
lan, held); and the Pi-hole bundles set v5 variables v6 ignores,
WEBPASSWORD and PIHOLE_DNS_ (F46).
"""
import re
import tomllib
import unittest
from pathlib import Path

WORKLOADS = Path(__file__).resolve().parent.parent / "workloads"

# Container ports that ask for no login: published on loopback only.
NO_LOGIN = {
    "comfyui": {"8188"},
    "llamacpp": {"8080"},
    "oobabooga": {"7860", "5000"},
    "proxy-stack": {"1080"},
    "registry": {"5000"},
    "swarmui": {"7801"},
}


def published(bundle):
    with open(WORKLOADS / bundle / "workload.toml", "rb") as f:
        return tomllib.load(f).get("network", {}).get("ports", [])


class TestNoLoginMeansLoopback(unittest.TestCase):

    def test_each_is_published_on_loopback_only(self):
        present = [b for b in NO_LOGIN if (WORKLOADS / b).is_dir()]
        self.assertGreaterEqual(len(present), 6)
        for bundle in present:
            for spec in published(bundle):
                container_port = spec.split("/")[0].rsplit(":", 1)[-1]
                if container_port in NO_LOGIN[bundle]:
                    with self.subTest(bundle=bundle, spec=spec):
                        self.assertTrue(spec.startswith("127.0.0.1:"))

    def test_every_one_is_still_published(self):
        for bundle in (b for b in NO_LOGIN if (WORKLOADS / b).is_dir()):
            ports = {s.split("/")[0].rsplit(":", 1)[-1]
                     for s in published(bundle)}
            with self.subTest(bundle=bundle):
                self.assertLessEqual(NO_LOGIN[bundle], ports)


class TestGuestsOnlyRead(unittest.TestCase):

    def test_no_guest_share_is_writable(self):
        text = (WORKLOADS / "smb-server" / "smb.conf").read_text()
        shares = re.split(r"^\[([^\]]+)\]\s*$", text, flags=re.M)[1:]
        checked = 0
        for name, body in zip(shares[::2], shares[1::2]):
            opts = dict(
                (k.strip().lower(), v.strip().lower())
                for k, _, v in (line.partition("=") for line in
                                body.splitlines())
                if v and not k.strip().startswith(("#", ";")))
            if opts.get("guest ok") == "yes":
                checked += 1
                with self.subTest(share=name):
                    self.assertNotEqual(opts.get("writable"), "yes")
                    self.assertNotEqual(opts.get("read only"), "no")
        self.assertGreater(checked, 0)


class TestFirstVisitors(unittest.TestCase):

    MARKER = "sunshine-prestart <<'SCRIPT'\n"

    def sunshine_bundles(self):
        bundles = [path.parent for path in WORKLOADS.glob("*/Containerfile")
                   if self.MARKER in path.read_text()]
        self.assertIn(WORKLOADS / "sunshine-streaming", bundles)
        for bundle in bundles:
            text = (bundle / "Containerfile").read_text()
            script = text.split(self.MARKER, 1)[1].split("\nSCRIPT\n", 1)[0]
            yield bundle, text, script

    def test_sunshines_web_ui_answers_this_machine_only(self):
        # Sunshine reads only the user's sunshine.conf, which the prestart
        # rewrites; a line in /etc/sunshine/sunshine.conf does nothing.
        for bundle, _, script in self.sunshine_bundles():
            with self.subTest(bundle=bundle.name):
                self.assertIn("/^origin_web_ui_allowed=/d", script)
                self.assertIn(
                    'echo "origin_web_ui_allowed=pc" >> "$CONF"', script)
                setup = (bundle / "setup.sh").read_text()
                opened = [line for line in setup.splitlines()
                          if "--add-port" in line]
                self.assertTrue(opened)
                for line in opened:
                    self.assertNotIn("SUNSHINE_WEB_PORT", line)

    def test_sunshines_login_comes_from_the_workloads_secret(self):
        # The prestart writes the login before Sunshine first answers; the
        # unit passes the variables in and keeps them from the games.
        for bundle, text, script in self.sunshine_bundles():
            with self.subTest(bundle=bundle.name):
                self.assertIn(
                    'if [ -n "${SUNSHINE_WEB_PASSWORD:-}" ]; then', script)
                self.assertIn(
                    '/usr/bin/sunshine --creds "${SUNSHINE_WEB_USER:-admin}"',
                    script)
                unit = text.split("sunshine.service <<'UNIT'\n", 1)[1]
                unit = unit.split("\nUNIT\n", 1)[0].replace("\\\n", " ")
                lines = unit.splitlines()
                passed = [word for line in lines
                          if line.startswith("PassEnvironment=")
                          for word in line.split("=", 1)[1].split()]
                self.assertIn("SUNSHINE_WEB_USER", passed)
                self.assertIn("SUNSHINE_WEB_PASSWORD", passed)
                start = [line for line in lines
                         if line.startswith("ExecStart=")]
                self.assertEqual(len(start), 1)
                self.assertIn(
                    "unset SUNSHINE_WEB_USER SUNSHINE_WEB_PASSWORD &&",
                    start[0])


class TestPiHoleSix(unittest.TestCase):

    def test_no_bundle_sets_a_variable_v6_ignores(self):
        for path in WORKLOADS.glob("*/workload.toml"):
            with open(path, "rb") as f:
                doc = tomllib.load(f)
            envs = [doc.get("container", {}).get("environment", {})]
            envs += [c.get("environment", {})
                     for c in doc.get("containers", [])]
            for env in envs:
                for name in ("WEBPASSWORD", "PIHOLE_DNS_"):
                    with self.subTest(bundle=path.parent.name, name=name):
                        self.assertNotIn(name, env)

    def test_no_password_is_set_empty(self):
        # "" turns v6's login off; unset makes a random one.
        for path in WORKLOADS.glob("*/workload.toml"):
            with open(path, "rb") as f:
                doc = tomllib.load(f)
            env = doc.get("container", {}).get("environment", {})
            with self.subTest(bundle=path.parent.name):
                self.assertNotEqual(
                    env.get("FTLCONF_webserver_api_password"), "")


if __name__ == "__main__":
    unittest.main()
