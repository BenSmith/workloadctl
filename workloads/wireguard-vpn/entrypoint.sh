#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
. /wg-up.sh

echo "WireGuard VPN starting..."
echo "Interface: $WG_INTERFACE"

if [ ! -s "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

cleanup() {
    echo "Shutting down WireGuard..."
    wg_down
    echo "WireGuard stopped"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard interface..."
wg_up

# In place: podman bind-mounts this file, and a new inode would not reach
# the mount.
TUNNEL_DNS=$(wg_dns)
if [ -n "$TUNNEL_DNS" ]; then
    echo "nameserver $TUNNEL_DNS" > /etc/resolv.conf
    echo "DNS: $TUNNEL_DNS (via the tunnel)"
fi

echo "WireGuard interface up!"
wg show "$WG_INTERFACE"

echo ""
echo "Checking public IP..."
PUBLIC_IP=$(curl -s --max-time 5 https://ipinfo.io/ip || echo "Could not determine IP")
echo "Public IP: $PUBLIC_IP"

echo ""
echo "VPN tunnel active. Monitoring connection..."
while true; do
    if ! ip link show "$WG_INTERFACE" &>/dev/null; then
        echo "ERROR: WireGuard interface disappeared!"
        exit 1
    fi
    # In the background: bash runs the SIGTERM trap only between commands,
    # and a foreground sleep would hold it past podman's stop timeout.
    sleep 30 &
    wait $!
done
