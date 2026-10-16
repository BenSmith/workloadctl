#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
. /wg-up.sh

if [ ! -f "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

# Parse VPN DNS from WireGuard config. UPSTREAM_DNS env var overrides it.
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

echo "Proxy stack starting..."
echo "WireGuard interface: $WG_INTERFACE"
echo "VPN upstream DNS: $VPN_DNS"
echo "SOCKS5 port: $SOCKS_PORT"

# Pi-hole v6 takes its upstreams from FTLCONF_ variables.
export FTLCONF_dns_upstreams="$VPN_DNS"

cleanup() {
    echo "Shutting down..."
    [ -n "$SQUID_PID" ]    && kill "$SQUID_PID"    2>/dev/null || true
    [ -n "$MICROSOCKS_PID" ] && kill "$MICROSOCKS_PID" 2>/dev/null || true
    [ -n "$PIHOLE_PID" ]   && kill "$PIHOLE_PID"   2>/dev/null || true
    wg_down
    exit "${1:-0}"
}
trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard..."
wg_up

# Until Pi-hole answers, the container resolves through the tunnel: a fresh
# volume's first gravity run needs DNS before FTL starts. In place: podman
# bind-mounts this file, and a new inode would not reach it.
RESOLVER=$(echo "${VPN_DNS%%;*}" \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
if [ -n "$RESOLVER" ]; then
    echo "nameserver $RESOLVER" > /etc/resolv.conf
fi

# microsocks needs no Pi-hole; it resolves through whichever resolver the
# container has.
echo "Starting microsocks..."
microsocks -p "$SOCKS_PORT" &
MICROSOCKS_PID=$!

# Start Pi-hole (s6-overlay, manages FTL and lighttpd internally).
echo "Starting Pi-hole..."
/usr/bin/start.sh &
PIHOLE_PID=$!

# Squid's only resolver is Pi-hole (squid.conf), so it waits for port 53.
echo "Waiting for Pi-hole DNS..."
for i in $(seq 1 120); do
    if bash -c 'echo >/dev/tcp/127.0.0.1/53' 2>/dev/null; then
        echo "Pi-hole DNS ready"
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        break
    fi
    if ! kill -0 "$PIHOLE_PID" 2>/dev/null; then
        echo "ERROR: Pi-hole died!"
        cleanup 1
    fi
    [ "$i" -eq 120 ] && \
        echo "Warning: Pi-hole DNS not ready after 120s, continuing anyway"
    sleep 1
done

# Squid starts as its own user: it opens its logs after dropping root, and
# the container's stdout is journald's socket, which cannot be opened by
# path. A pipe the squid user made can be.
echo "Starting Squid..."
chown squid:squid /var/spool/squid
capsh --user=squid -- -c "squid -z -N" 2>/dev/null || true
rm -f /var/spool/squid/squid.pid
capsh --user=squid -- -c "exec squid -N > >(cat) 2>&1" &
SQUID_PID=$!

echo ""
echo "Proxy stack ready:"
echo "  Squid proxy:   :3128 (HTTP/HTTPS cache → VPN)"
echo "  SOCKS5 proxy:  :$SOCKS_PORT (→ VPN)"
echo "  Pi-hole DNS:   :53   (DNS blocking → VPN upstream)"
echo "  Pi-hole admin: :80"

# Monitor all services; a death exits non-zero, so systemd restarts the unit.
while true; do
    if ! kill -0 "$PIHOLE_PID"     2>/dev/null; then echo "ERROR: Pi-hole died!";    cleanup 1; fi
    if ! kill -0 "$MICROSOCKS_PID" 2>/dev/null; then echo "ERROR: microsocks died!"; cleanup 1; fi
    if ! kill -0 "$SQUID_PID"      2>/dev/null; then echo "ERROR: Squid died!";      cleanup 1; fi
    # In the background: bash runs the SIGTERM trap only between
    # commands, and a foreground sleep would hold it past podman's
    # stop timeout.
    sleep 15 &
    wait $!
done
