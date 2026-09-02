#!/usr/bin/env bash
# ==============================================================================
# FluxWAN RB5009 Netboot Server Setup Script
# Configures DHCP / BOOTP & TFTP server for MikroTik RouterBOOT Recovery
# ==============================================================================
set -euo pipefail

NET_IF="${1:-eth0}"
TFTP_DIR="/srv/tftp"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ITB_IMAGE="$PROJECT_ROOT/dist/fluxwan-rb5009.itb"

echo "======================================================================"
echo "   FluxWAN MikroTik RB5009 Netboot Recovery Server                    "
echo "======================================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] ERROR: Must be run as root."
    exit 1
fi

echo "[1/4] Preparing TFTP directory ($TFTP_DIR)..."
mkdir -p "$TFTP_DIR"
if [ -f "$ITB_IMAGE" ]; then
    cp -f "$ITB_IMAGE" "$TFTP_DIR/fluxwan-rb5009.itb"
    echo "    * Copied fluxwan-rb5009.itb to TFTP root."
else
    echo "[!] Warning: $ITB_IMAGE not found yet. Please run build_rb5009_image.sh first."
fi

echo "[2/4] Configuring Network Interface $NET_IF..."
ip addr flush dev "$NET_IF" 2>/dev/null || true
ip addr add 192.168.88.2/24 dev "$NET_IF"
ip link set "$NET_IF" up

echo "[3/4] Starting dnsmasq (DHCP/BOOTP + TFTP)..."
# Kill existing dnsmasq instances
killall dnsmasq 2>/dev/null || true

cat << EOF > /tmp/dnsmasq_rb5009.conf
interface=$NET_IF
bind-interfaces
dhcp-range=192.168.88.10,192.168.88.50,255.255.255.0,1h
dhcp-option=3,192.168.88.2
dhcp-option=6,192.168.88.2

# TFTP Server
enable-tftp
tftp-root=$TFTP_DIR
dhcp-boot=fluxwan-rb5009.itb
EOF

dnsmasq -C /tmp/dnsmasq_rb5009.conf

echo ""
echo "======================================================================"
echo " [?] NETBOOT SERVER READY!                                            "
echo "======================================================================"
echo " Steps to Netboot MikroTik RB5009:"
echo "   1. Connect Ethernet cable between PC ($NET_IF) and ether1 on RB5009."
echo "   2. Power OFF RB5009."
echo "   3. Hold the RESET button and plug in the power cord."
echo "   4. Keep holding RESET until the LED starts flashing and turns solid."
echo "   5. Release RESET. RouterBOOT will request IP and download FIT image."
echo "======================================================================"
