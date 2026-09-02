#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Automated VM & Bare-Metal Deployment Script
# Supports: Proxmox VE, VMware ESXi, VirtualBox, KVM, Ubuntu, Debian, Alpine
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo "          FluxWAN Virtual Machine & OS Deployment Engine              "
echo "======================================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This installation script must be run as root (sudo)." >&2
    exit 1
fi

INSTALL_DIR="/opt/fluxwan"
echo "[+] Target Installation Directory: $INSTALL_DIR"

# 1. Detect OS & Install Dependencies
echo "[+] Step 1: Installing System Dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq build-essential clang llvm libbpf-dev iproute2 iptables conntrack ethtool python3 python3-pip curl
elif command -v apk >/dev/null 2>&1; then
    apk update
    apk add build-base clang llvm libbpf-dev iproute2 iptables conntrack ethtool python3 curl
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc clang llvm libbpf-devel iproute iptables conntrack-tools ethtool python3 curl
fi

# 2. Kernel Tuning for High-Performance Multi-WAN Routing
echo "[+] Step 2: Optimizing Linux Kernel sysctl parameters..."
cat <<EOF > /etc/sysctl.d/99-fluxwan.conf
# Enable IPv4 Packet Forwarding
net.ipv4.ip_forward = 1

# Loose Reverse Path Filtering for Multi-WAN Asymmetric Routing
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Increase Conntrack Table Limits
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 1800

# High-Throughput Socket Buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 10000
EOF
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-fluxwan.conf || true

# 3. Create Installation Directory & Copy Files
echo "[+] Step 3: Compiling & Installing FluxWAN binaries..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/bpf"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

# Generate embedded UI
python3 scripts/embed_ui.py || true

# Compile FluxWAN
make clean || true
make || gcc -O2 -Iinclude src/*.c -o fluxwan -lpthread

# Copy artifacts
cp -f fluxwan "$INSTALL_DIR/"
if [ -f bpf/xdp_router.bpf.o ]; then
    cp -f bpf/xdp_router.bpf.o "$INSTALL_DIR/bpf/" || true
fi

# Install default config if not exists
if [ ! -f "$INSTALL_DIR/config/fluxwan.json" ]; then
    cp -f config/fluxwan.json "$INSTALL_DIR/config/fluxwan.json"
fi

# 4. Install & Enable Systemd Service
echo "[+] Step 4: Configuring Systemd Service (fluxwan.service)..."
if [ -d /etc/systemd/system ]; then
    cp -f systemd/fluxwan.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable fluxwan.service
    systemctl restart fluxwan.service
    echo "[✓] FluxWAN Systemd service installed and started successfully!"
fi

echo "======================================================================"
echo "      FluxWAN Router Engine successfully installed on this VM!        "
echo "  Web Management UI is active at: http://<VM-IP-ADDRESS>:8080         "
echo "  Default Login: Username: admin | Password: admin                    "
echo "======================================================================"
