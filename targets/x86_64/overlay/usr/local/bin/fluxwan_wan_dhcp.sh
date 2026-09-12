#!/bin/sh
# FluxWAN Multi-WAN udhcpc Hook Script
# Invoked by Busybox udhcpc upon lease events: bound, renew, deconfig

[ -z "$1" ] && exit 1

case "$1" in
    deconfig)
        ip addr flush dev "$interface" 2>/dev/null || true
        ip link set "$interface" up 2>/dev/null || true
        rm -f "/run/fluxwan_wan_${interface}.lease"
        ;;
    bound|renew)
        PREFIX=24
        if [ -n "$mask" ]; then
            case "$mask" in
                255.255.255.255) PREFIX=32 ;;
                255.255.255.254) PREFIX=31 ;;
                255.255.255.252) PREFIX=30 ;;
                255.255.255.248) PREFIX=29 ;;
                255.255.255.240) PREFIX=28 ;;
                255.255.255.224) PREFIX=27 ;;
                255.255.255.192) PREFIX=26 ;;
                255.255.255.128) PREFIX=25 ;;
                255.255.255.0)   PREFIX=24 ;;
                255.255.254.0)   PREFIX=23 ;;
                255.255.252.0)   PREFIX=22 ;;
                255.255.248.0)   PREFIX=21 ;;
                255.255.240.0)   PREFIX=20 ;;
                255.255.0.0)     PREFIX=16 ;;
                255.0.0.0)       PREFIX=8  ;;
                *)               PREFIX=24 ;;
            esac
        fi

        ip addr flush dev "$interface" 2>/dev/null || true
        ip addr add "$ip/$PREFIX" dev "$interface" 2>/dev/null || ip addr replace "$ip/$PREFIX" dev "$interface" 2>/dev/null || true
        ip link set "$interface" up 2>/dev/null || true

        cat > "/run/fluxwan_wan_${interface}.lease" << EOF
IP=$ip
NETMASK=${mask:-$subnet}
GATEWAY=$router
DNS=$dns
TIMESTAMP=$(date +%s)
EOF

        TABLE_ID=$(cat "/run/fluxwan_table_${interface}" 2>/dev/null)
        [ -z "$TABLE_ID" ] && TABLE_ID=101
        if [ -n "$router" ]; then
            ip route replace default via "$router" dev "$interface" table "$TABLE_ID" proto static 2>/dev/null || true
        fi

        sysctl -w net.ipv4.conf.${interface}.rp_filter=2 >/dev/null 2>&1 || true
        ;;
esac
exit 0