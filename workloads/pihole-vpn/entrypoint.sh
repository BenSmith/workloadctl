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

# Override Pi-hole's upstream DNS with the VPN DNS server(s)
export PIHOLE_DNS_="$VPN_DNS"

cleanup() {
    echo "Shutting down..."
    [ -n "${PIHOLE_PID:-}" ] && kill "$PIHOLE_PID" 2>/dev/null || true
    wg_down
    exit 0
}
trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard interface..."
wg_up

echo "Starting Pi-hole..."
/usr/bin/start.sh &
PIHOLE_PID=$!
wait "$PIHOLE_PID"
cleanup
