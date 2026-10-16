# wg-up.sh: a WireGuard tunnel from a provider's config, in a container.
#
# Sourced by the entrypoint, with WG_INTERFACE and WG_CONFIG set. Every
# WireGuard bundle carries the same copy, since an image builds from its own
# directory; tests/test_wireguard_bundles.py holds them equal.
#
# /proc/sys/net is read-only in a container, so wg-quick's default-route
# policy routing (it sets src_valid_mark) cannot work, and the images carry
# no resolvconf for DNS=. wg-quick gets a copy with Table = off and no DNS=,
# which leaves it the keys, peers and addresses; the routes are set here.
# Busybox's tools are enough: the pihole bundles are Alpine.

# The first IPv4 server in the config's DNS=, or nothing.
wg_dns() {
    grep -iE '^[[:space:]]*DNS[[:space:]]*=' "$WG_CONFIG" | head -n1 \
        | cut -d= -f2- | tr ',' '\n' | tr -d ' \t\r' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1
}

wg_up() {
    local run iface gw iface6 gw6 allowed endpoint prefix v6
    iface=$(ip route show default | awk '{print $5; exit}')
    gw=$(ip route show default | awk '{print $3; exit}')
    iface6=$(ip -6 route show default 2>/dev/null | awk '{print $5; exit}')
    gw6=$(ip -6 route show default 2>/dev/null | awk '{print $3; exit}')
    if [ -z "$iface" ]; then
        echo "ERROR: no default route in the container's network namespace"
        return 1
    fi
    allowed=$(grep -iE '^[[:space:]]*AllowedIPs[[:space:]]*=' "$WG_CONFIG" \
        | cut -d= -f2- | tr ',' '\n' | tr -d ' \t\r')

    run="${WG_RUN_DIR:-/run/wireguard}/${WG_INTERFACE}.conf"
    mkdir -p "${WG_RUN_DIR:-/run/wireguard}"
    grep -viE '^[[:space:]]*(DNS|Table)[[:space:]]*=' "$WG_CONFIG" \
        | awk '{ print } /^\[Interface\]/ { print "Table = off" }' > "$run"
    chmod 600 "$run"

    ip link del "$WG_INTERFACE" 2>/dev/null || true
    wg-quick up "$run"

    # Each endpoint, as wg resolved it, keeps a route on the real path, so
    # the handshake does not enter the tunnel it carries.
    for endpoint in $(wg show "$WG_INTERFACE" endpoints | awk '{print $2}'); do
        endpoint=${endpoint%:*}
        endpoint=${endpoint#[}
        endpoint=${endpoint%]}
        case "$endpoint" in
            *.*.*.*)
                ip route replace "$endpoint" ${gw:+via "$gw"} dev "$iface" ;;
            *:*)
                [ -n "$iface6" ] && ip -6 route replace "$endpoint" \
                    ${gw6:+via "$gw6"} dev "$iface6" ;;
        esac
        echo "VPN endpoint: $endpoint"
    done

    # A default route becomes two /1 routes, more specific than the
    # container's default without replacing it; any other prefix is routed
    # as it stands, and IPv6 only when the tunnel has an IPv6 address. LAN
    # ranges stay on the real interface, but not 10.0.0.0/8: providers put
    # their tunnel addresses and resolvers there.
    for prefix in 192.168.0.0/16 172.16.0.0/12; do
        ip route add "$prefix" dev "$iface" 2>/dev/null || true
    done
    v6=$(ip -6 addr show dev "$WG_INTERFACE" scope global 2>/dev/null \
        | grep -c inet6 || true)
    for prefix in $allowed; do
        case "$prefix" in
            0.0.0.0/0)
                ip route add 0.0.0.0/1 dev "$WG_INTERFACE"
                ip route add 128.0.0.0/1 dev "$WG_INTERFACE" ;;
            *:*)
                if [ "$v6" -eq 0 ]; then
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
}

# Deleting the link takes its routes with it.
wg_down() {
    ip link del "$WG_INTERFACE" 2>/dev/null || true
}
