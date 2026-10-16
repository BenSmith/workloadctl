"""The WireGuard bundles bring their tunnel up through one wg-up.sh.

wg-quick's default-route handling sets src_valid_mark, and /proc/sys/net is
read-only in a container; the images also have no resolvconf for DNS=. On
the proving host (2026-10-16) wireguard-vpn failed on the README's own
full-tunnel config, and a first version of the fix, whose AllowedIPs parse
ran the prefixes together, routed nothing into the tunnel. wg-up.sh hands
wg-quick Table = off and no DNS=, and routes the tunnel itself.
"""
import os
import stat
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

WORKLOADS = Path(__file__).resolve().parent.parent / "workloads"
HELPER = WORKLOADS / "wireguard-vpn" / "wg-up.sh"


def _wireguard_bundles():
    for toml in sorted(WORKLOADS.glob("*/workload.toml")):
        security = tomllib.loads(toml.read_text()).get("security", {})
        if "generic" in security.get("seccomp_netlink", []):
            yield toml.parent


class TestEveryBundleUsesTheHelper(unittest.TestCase):

    def test_each_carries_the_same_helper_and_uses_it(self):
        bundles = list(_wireguard_bundles())
        self.assertGreaterEqual(len(bundles), 5)
        for bundle in bundles:
            with self.subTest(bundle=bundle.name):
                self.assertEqual((bundle / "wg-up.sh").read_text(),
                                 HELPER.read_text())
                containerfile = (bundle / "Containerfile").read_text()
                self.assertIn("COPY --link --chmod=0644 wg-up.sh /wg-up.sh",
                              containerfile)
                entrypoint = (bundle / "entrypoint.sh").read_text()
                self.assertIn(". /wg-up.sh", entrypoint)
                self.assertIn("wg_up\n", entrypoint)
                self.assertIn("wg_down\n", entrypoint)
                self.assertNotIn("wg-quick up", entrypoint)
                self.assertNotIn("wg-quick down", entrypoint)


class TestWgUp(unittest.TestCase):
    """wg_up under bash, with ip, wg and wg-quick stubbed to record what
    they are asked."""

    def _run(self, conf, v6_address=False, endpoint="203.0.113.5:51820"):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        log = tmp / "calls"
        stubs = {
            "ip": f"""
echo "ip $*" >> {log}
case "$*" in
  "route show default") echo "default via 192.168.0.1 dev eth0" ;;
  "-6 addr show dev wg0 scope global")
    [ -n "$V6" ] && echo "    inet6 fd00::2/128 scope global" ;;
esac
exit 0
""",
            "wg": f"""
echo "wg $*" >> {log}
[ "$*" = "show wg0 endpoints" ] && printf 'PUB=\\t{endpoint}\\n'
exit 0
""",
            "wg-quick": f"""
echo "wg-quick $*" >> {log}
cp "$2" {tmp}/handed
""",
        }
        for name, body in stubs.items():
            path = bin_dir / name
            path.write_text("#!/bin/bash\n" + body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        config = tmp / "wg0.conf"
        config.write_text(conf)
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
               "WG_INTERFACE": "wg0", "WG_CONFIG": str(config),
               "WG_RUN_DIR": str(tmp / "run")}
        if v6_address:
            env["V6"] = "1"
        result = subprocess.run(
            ["bash", "-c", f"set -e; . {HELPER}; wg_up; echo DNS=$(wg_dns)"],
            env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = log.read_text().splitlines()
        return calls, (tmp / "handed").read_text(), result.stdout

    CONF = """[Interface]
PrivateKey = k
Address = 10.2.0.2/32
DNS = 10.2.0.1, 10.2.0.3
Table = 51820

[Peer]
PublicKey = p
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example:51820
"""

    def test_a_full_tunnel_is_routed_through_two_halves(self):
        calls, _, _ = self._run(self.CONF)
        self.assertIn("ip route add 0.0.0.0/1 dev wg0", calls)
        self.assertIn("ip route add 128.0.0.0/1 dev wg0", calls)

    def test_wg_quick_gets_table_off_and_no_dns(self):
        _, handed, _ = self._run(self.CONF)
        self.assertIn("[Interface]\nTable = off\n", handed)
        self.assertNotIn("DNS", handed)
        self.assertNotIn("Table = 51820", handed)

    def test_the_resolved_endpoint_stays_on_the_real_path(self):
        calls, _, _ = self._run(self.CONF)
        self.assertIn("ip route replace 203.0.113.5 via 192.168.0.1 dev eth0",
                      calls)

    def test_the_lan_stays_local_but_not_ten_slash_eight(self):
        calls, _, _ = self._run(self.CONF)
        self.assertIn("ip route add 192.168.0.0/16 dev eth0", calls)
        self.assertIn("ip route add 172.16.0.0/12 dev eth0", calls)
        self.assertFalse(any("10.0.0.0/8" in c for c in calls))

    def test_ipv6_is_routed_only_when_the_tunnel_has_an_address(self):
        calls, _, out = self._run(self.CONF)
        self.assertFalse(any(c.startswith("ip -6 route add") for c in calls))
        self.assertIn("::/0 not routed", out)
        calls, _, _ = self._run(self.CONF, v6_address=True)
        self.assertIn("ip -6 route add ::/1 dev wg0", calls)
        self.assertIn("ip -6 route add 8000::/1 dev wg0", calls)

    def test_a_split_tunnel_routes_its_prefixes(self):
        conf = self.CONF.replace("AllowedIPs = 0.0.0.0/0, ::/0",
                                 "AllowedIPs = 10.2.0.0/16,192.0.2.0/24")
        calls, _, _ = self._run(conf)
        self.assertIn("ip route add 10.2.0.0/16 dev wg0", calls)
        self.assertIn("ip route add 192.0.2.0/24 dev wg0", calls)
        self.assertFalse(any("0.0.0.0/1" in c for c in calls))

    def test_dns_is_the_first_ipv4_server(self):
        _, _, out = self._run(self.CONF)
        self.assertIn("DNS=10.2.0.1\n", out)


if __name__ == "__main__":
    unittest.main()
