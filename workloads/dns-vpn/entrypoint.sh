#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
. /wg-up.sh
DNS_PORT="${DNS_PORT:-53}"

if [ ! -f "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

# Parse DNS server from WireGuard config. UPSTREAM_DNS env var overrides it.
if [ -n "$UPSTREAM_DNS" ]; then
    VPN_DNS="$UPSTREAM_DNS"
else
    VPN_DNS=$(grep -iE '^\s*DNS\s*=' "$WG_CONFIG" | head -n1 | sed 's/.*=\s*//' | tr -d ' ' | cut -d',' -f1)
    if [ -z "$VPN_DNS" ]; then
        echo "ERROR: No DNS server found in $WG_CONFIG and UPSTREAM_DNS not set"
        exit 1
    fi
fi

echo "DNS-over-VPN proxy starting..."
echo "WireGuard interface: $WG_INTERFACE"
echo "Upstream DNS: $VPN_DNS (via VPN tunnel)"
echo "Listening on port: $DNS_PORT"

cleanup() {
    echo "Shutting down..."
    kill "$DNSMASQ_PID" 2>/dev/null || true
    wg_down
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard interface..."
wg_up

echo "Starting DNS proxy..."
dnsmasq \
    --no-daemon \
    --no-resolv \
    --no-hosts \
    --domain-needed \
    --bogus-priv \
    --server="$VPN_DNS" \
    --listen-address=0.0.0.0 \
    --port="$DNS_PORT" \
    --user=root \
    &
DNSMASQ_PID=$!

echo ""
echo "DNS proxy ready — forwarding to $VPN_DNS via VPN"
echo "  Test: dig @<this-host-ip> example.com"

while true; do
    if ! ip link show "$WG_INTERFACE" &>/dev/null; then
        echo "ERROR: WireGuard interface disappeared!"
        exit 1
    fi
    if ! kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        echo "ERROR: dnsmasq process died!"
        exit 1
    fi
    # In the background: bash runs the SIGTERM trap only between
    # commands, and a foreground sleep would hold it past podman's
    # stop timeout.
    sleep 30 &
    wait $!
done
