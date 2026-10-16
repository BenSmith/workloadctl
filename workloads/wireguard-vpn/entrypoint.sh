#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
RUN_CONFIG="/run/wireguard/${WG_INTERFACE}.conf"

echo "WireGuard VPN starting..."
echo "Interface: $WG_INTERFACE"

if [ ! -s "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

# The endpoint keeps a route on the real path, so the handshake does not
# try to enter the tunnel it carries.
ENDPOINT=$(grep -iE '^[[:space:]]*Endpoint[[:space:]]*=' "$WG_CONFIG" \
    | head -n1 | cut -d= -f2- | tr -d '[:space:]')
if [ -z "$ENDPOINT" ]; then
    echo "ERROR: no Endpoint found in $WG_CONFIG"
    exit 1
fi
ENDPOINT_HOST="${ENDPOINT%:*}"
ENDPOINT_PORT="${ENDPOINT##*:}"
if [[ "$ENDPOINT_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ENDPOINT_IP="$ENDPOINT_HOST"
else
    ENDPOINT_IP=$(getent ahostsv4 "$ENDPOINT_HOST" | awk '{print $1; exit}')
fi
if [ -z "$ENDPOINT_IP" ]; then
    echo "ERROR: could not resolve VPN endpoint host '$ENDPOINT_HOST'"
    exit 1
fi
echo "VPN endpoint: $ENDPOINT_HOST -> $ENDPOINT_IP:$ENDPOINT_PORT"

DEFAULT_IFACE=$(ip route show default | awk '{print $5; exit}')
DEFAULT_GW=$(ip route show default | awk '{print $3; exit}')
if [ -z "$DEFAULT_IFACE" ]; then
    echo "ERROR: no default route in the container's network namespace"
    exit 1
fi

# /proc/sys/net is read-only in the container, so wg-quick's default-route
# policy routing (it sets src_valid_mark) cannot work here, and the image
# has no resolvconf for DNS=. Table = off leaves wg-quick the keys, peers and
# addresses; the routes and the resolver are set below.
TUNNEL_DNS=$(grep -iE '^[[:space:]]*DNS[[:space:]]*=' "$WG_CONFIG" \
    | head -n1 | cut -d= -f2- | tr -d '[:space:]' | cut -d, -f1)
ALLOWED_IPS=$(grep -iE '^[[:space:]]*AllowedIPs[[:space:]]*=' "$WG_CONFIG" \
    | cut -d= -f2- | tr ',' '\n' | tr -d ' \t\r')
mkdir -p /run/wireguard
sed -e '/^[[:space:]]*DNS[[:space:]]*=/Id' \
    -e '/^[[:space:]]*Table[[:space:]]*=/Id' \
    -e '/^\[Interface\]/a Table = off' \
    "$WG_CONFIG" > "$RUN_CONFIG"
chmod 600 "$RUN_CONFIG"

cleanup() {
    echo "Shutting down WireGuard..."
    ip link del "$WG_INTERFACE" 2>/dev/null || true
    echo "WireGuard stopped"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

ip link del "$WG_INTERFACE" 2>/dev/null || true
echo "Bringing up WireGuard interface..."
wg-quick up "$RUN_CONFIG"

# A default route in AllowedIPs becomes two /1 routes, more specific than
# the container's default without replacing it; any other prefix is routed
# as it stands. LAN ranges stay on the real interface, but not 10.0.0.0/8:
# providers put their tunnel addresses and resolvers there.
if [ -n "$DEFAULT_GW" ]; then
    ip route replace "$ENDPOINT_IP" via "$DEFAULT_GW" dev "$DEFAULT_IFACE"
else
    ip route replace "$ENDPOINT_IP" dev "$DEFAULT_IFACE"
fi
for lan in 192.168.0.0/16 172.16.0.0/12; do
    ip route add "$lan" dev "$DEFAULT_IFACE" 2>/dev/null || true
done
# IPv6 prefixes go into the tunnel only when it has an IPv6 address.
V6=$(ip -6 addr show dev "$WG_INTERFACE" scope global 2>/dev/null \
    | grep -c inet6 || true)
for prefix in $ALLOWED_IPS; do
    case "$prefix" in
        0.0.0.0/0)
            ip route add 0.0.0.0/1 dev "$WG_INTERFACE"
            ip route add 128.0.0.0/1 dev "$WG_INTERFACE" ;;
        *:*)
            if [ "$V6" -eq 0 ]; then
                echo "No IPv6 address on $WG_INTERFACE; $prefix not routed"
            elif [ "$prefix" = "::/0" ]; then
                ip -6 route add ::/1 dev "$WG_INTERFACE"
                ip -6 route add 8000::/1 dev "$WG_INTERFACE"
            else
                ip -6 route add "$prefix" dev "$WG_INTERFACE"
            fi ;;
        *)
            ip route add "$prefix" dev "$WG_INTERFACE" ;;
    esac
done

# In place: podman bind-mounts this file, and a new inode would not reach
# the mount.
if [[ "$TUNNEL_DNS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "nameserver $TUNNEL_DNS" > /etc/resolv.conf
    echo "DNS: $TUNNEL_DNS (via the tunnel)"
elif [ -n "$TUNNEL_DNS" ]; then
    echo "WARNING: DNS= entry '$TUNNEL_DNS' is not an IPv4 address; DNS left as it was"
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
