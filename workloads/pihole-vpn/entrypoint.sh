#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
. /wg-up.sh

if [ ! -f "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

# Parse DNS server(s) from WireGuard config. UPSTREAM_DNS env var overrides it.
# Pi-hole expects semicolon-separated upstreams; wg0.conf uses comma-separated.
if [ -n "$UPSTREAM_DNS" ]; then
    VPN_DNS="$UPSTREAM_DNS"
else
    VPN_DNS=$(grep -iE '^\s*DNS\s*=' "$WG_CONFIG" | head -n1 | sed 's/.*=\s*//' | tr -d ' ' | tr ',' ';')
    if [ -z "$VPN_DNS" ]; then
        echo "ERROR: No DNS server found in $WG_CONFIG and UPSTREAM_DNS not set"
        exit 1
    fi
fi

echo "Pi-hole VPN starting..."
echo "WireGuard interface: $WG_INTERFACE"
echo "Upstream DNS: $VPN_DNS (via VPN tunnel)"

# Pi-hole v6 takes its upstreams from FTLCONF_ variables.
export FTLCONF_dns_upstreams="$VPN_DNS"

cleanup() {
    echo "Shutting down..."
    [ -n "${PIHOLE_PID:-}" ] && kill "$PIHOLE_PID" 2>/dev/null || true
    wg_down
    exit "${1:-0}"
}
trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard interface..."
wg_up

# The container's own lookups, a fresh volume's first gravity run among
# them, go through the tunnel. In place: podman bind-mounts this file, and a
# new inode would not reach it.
RESOLVER=$(echo "${VPN_DNS%%;*}" \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
if [ -n "$RESOLVER" ]; then
    echo "nameserver $RESOLVER" > /etc/resolv.conf
fi

echo "Starting Pi-hole..."
/usr/bin/start.sh &
PIHOLE_PID=$!
# A stop arrives as a signal, whose trap exits 0; Pi-hole exiting on its own
# is a failure, so systemd restarts the unit.
wait "$PIHOLE_PID" || true
echo "ERROR: Pi-hole exited"
cleanup 1
