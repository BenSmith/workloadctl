#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
. /wg-up.sh
SOCKS_PORT="${SOCKS_PORT:-1080}"

echo "VPN SOCKS5 proxy starting..."
echo "WireGuard interface: $WG_INTERFACE"
echo "SOCKS5 port: $SOCKS_PORT"

if [ ! -f "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

cleanup() {
    echo "Shutting down..."
    kill "$MICROSOCKS_PID" 2>/dev/null || true
    wg_down
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard interface..."
wg_up

# The proxy resolves names through the tunnel's resolver. In place:
# podman bind-mounts this file, and a new inode would not reach it.
TUNNEL_DNS=$(wg_dns)
if [ -n "$TUNNEL_DNS" ]; then
    echo "nameserver $TUNNEL_DNS" > /etc/resolv.conf
fi

echo "Starting SOCKS5 proxy on port $SOCKS_PORT..."
microsocks -p "$SOCKS_PORT" &
MICROSOCKS_PID=$!

echo ""
echo "Verifying VPN connection..."
PUBLIC_IP=$(curl -s --max-time 10 --socks5 "127.0.0.1:$SOCKS_PORT" https://ipinfo.io/ip || echo "unavailable")
echo "Public IP via VPN: $PUBLIC_IP"

echo ""
echo "SOCKS5 proxy ready — use socks5://127.0.0.1:$SOCKS_PORT"
echo "  curl --socks5 127.0.0.1:$SOCKS_PORT https://ipinfo.io/ip"

while true; do
    if ! ip link show "$WG_INTERFACE" &>/dev/null; then
        echo "ERROR: WireGuard interface disappeared!"
        exit 1
    fi
    if ! kill -0 "$MICROSOCKS_PID" 2>/dev/null; then
        echo "ERROR: microsocks process died!"
        exit 1
    fi
    # In the background: bash runs the SIGTERM trap only between
    # commands, and a foreground sleep would hold it past podman's
    # stop timeout.
    sleep 30 &
    wait $!
done
