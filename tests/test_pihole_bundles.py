"""The two Pi-hole bundles: their upstreams, their first gravity run, and
what a dead service does to the unit.

On the proving host (2026-10-16) proxy-stack's Squid refused its own
squid.conf (`cache_effective_user root` is fatal under Squid 7); dropped to
squid, it could not open /dev/stdout, since it opens its logs after the drop
and the container's stdout is journald's socket. The monitor that saw it die
exited 0, so Restart=on-failure never fired; a dead Pi-hole in pihole-vpn
ended the same way. Its first start on a fresh cache also raced `squid -z`,
which returns before it has made the cache directories. Both bundles exported PIHOLE_DNS_,
a Pi-hole v5 variable v6 ignores, so the tunnel's resolver was never Pi-hole's
upstream. And proxy-stack pointed the container at 127.0.0.1 before FTL was
up, so a fresh volume's gravity run, which comes first, waited 120 s for DNS.
"""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

WORKLOADS = Path(__file__).resolve().parent.parent / "workloads"
BUNDLES = ("pihole-vpn", "proxy-stack")


class TestEntrypoint(unittest.TestCase):
    """An entrypoint under bash, its absolute paths moved into a temporary
    directory and Pi-hole's start.sh stubbed to exit at once."""

    def _run(self, bundle):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (tmp / "wireguard").mkdir()
        (tmp / "wireguard" / "wg0.conf").write_text(
            "[Interface]\nDNS = 10.2.0.1, 10.2.0.3\n")
        (tmp / "resolv.conf").write_text("nameserver 169.254.1.1\n")
        (tmp / "wg-up.sh").write_text("wg_up() { :; }\nwg_down() { :; }\n")
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        stubs = {
            "start.sh": f'echo "$FTLCONF_dns_upstreams" > {tmp}/upstreams\n'
                        f'cp {tmp}/resolv.conf {tmp}/resolv-at-start\n',
            "microsocks": "exec sleep 30\n",
            "squid": "exit 0\n",
            "chown": "exit 0\n",
        }
        for name, body in stubs.items():
            path = bin_dir / name
            path.write_text("#!/bin/bash\n" + body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        script = (WORKLOADS / bundle / "entrypoint.sh").read_text()
        for old, new in (("/wg-up.sh", f"{tmp}/wg-up.sh"),
                         ("/usr/bin/start.sh", f"{bin_dir}/start.sh"),
                         ("/etc/wireguard", f"{tmp}/wireguard"),
                         ("/etc/resolv.conf", f"{tmp}/resolv.conf")):
            self.assertTrue(old in script, old)
            script = script.replace(old, new)
        # proxy-stack's wait for FTL, at a port nothing here listens on.
        script = script.replace("/dev/tcp/127.0.0.1/53",
                                "/dev/tcp/127.0.0.1/1")
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
        env.pop("UPSTREAM_DNS", None)
        result = subprocess.run(["bash", "-c", script], env=env,
                                capture_output=True, text=True, timeout=30)
        return result, tmp

    def test_a_dead_pi_hole_fails_the_unit(self):
        for bundle in BUNDLES:
            with self.subTest(bundle=bundle):
                result, _ = self._run(bundle)
                self.assertEqual(result.returncode, 1, result.stdout)

    def test_pi_hole_gets_the_tunnels_resolvers_as_v6_reads_them(self):
        for bundle in BUNDLES:
            with self.subTest(bundle=bundle):
                _, tmp = self._run(bundle)
                self.assertEqual((tmp / "upstreams").read_text(),
                                 "10.2.0.1;10.2.0.3\n")

    def test_gravity_resolves_through_the_tunnel(self):
        for bundle in BUNDLES:
            with self.subTest(bundle=bundle):
                _, tmp = self._run(bundle)
                self.assertEqual((tmp / "resolv-at-start").read_text(),
                                 "nameserver 10.2.0.1\n")


class TestSquid(unittest.TestCase):

    def test_squid_starts_as_its_own_user(self):
        conf = (WORKLOADS / "proxy-stack" / "squid.conf").read_text()
        self.assertNotIn("cache_effective_user", conf)
        script = (WORKLOADS / "proxy-stack" / "entrypoint.sh").read_text()
        runs = [line for line in script.splitlines()
                if "squid -z" in line or "squid -N" in line]
        self.assertEqual(len(runs), 2)
        for line in runs:
            self.assertTrue(line.startswith("capsh --user=squid -- -c "),
                            line)
        # Without -N, squid -z returns before its directories exist, and
        # the Squid started next finds one missing and stops.
        self.assertIn('"squid -z -N"', runs[0])


if __name__ == "__main__":
    unittest.main()
