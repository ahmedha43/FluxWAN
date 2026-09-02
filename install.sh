#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Automated Installer & Systemd Service Deployer
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo "    🚀 Installing FluxWAN High-Performance Multi-WAN Aggregator       "
echo "======================================================================"

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./install.sh)"
  exit 1
fi

INSTALL_DIR="/opt/fluxwan"
CONFIG_DIR="/etc/fluxwan"
SYSTEMD_DIR="/etc/systemd/system"

echo "[+] Creating directories..."
mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/bpf" "$CONFIG_DIR"

echo "[+] Installing binaries & BPF bytecode..."
cp -f bin/fluxwan "$INSTALL_DIR/bin/fluxwan"
chmod 755 "$INSTALL_DIR/bin/fluxwan"

if [ -f bin/fluxwan_lab ]; then
  cp -f bin/fluxwan_lab "$INSTALL_DIR/bin/fluxwan_lab"
  chmod 755 "$INSTALL_DIR/bin/fluxwan_lab"
fi

if [ -d bpf ]; then
  cp -f bpf/*.bpf.o "$INSTALL_DIR/bpf/" 2>/dev/null || true
fi

echo "[+] Installing default configuration..."
if [ ! -f "$CONFIG_DIR/fluxwan.json" ]; then
  if [ -f config/fluxwan.json ]; then
    cp -f config/fluxwan.json "$CONFIG_DIR/fluxwan.json"
  else
    echo '{"lan":{"interface":"eth0","ip":"192.168.10.1","netmask":"255.255.255.0","dhcp_enabled":true},"wans":[]}' > "$CONFIG_DIR/fluxwan.json"
  fi
  chmod 600 "$CONFIG_DIR/fluxwan.json"
fi

echo "[+] Installing systemd service..."
if [ -d "$SYSTEMD_DIR" ] && [ -f systemd/fluxwan.service ]; then
  cp -f systemd/fluxwan.service "$SYSTEMD_DIR/fluxwan.service"
  systemctl daemon-reload || true
  systemctl enable fluxwan || true
  echo "[✓] Systemd service 'fluxwan' registered and enabled on boot."
fi

echo "======================================================================"
echo "  🎉 FluxWAN installed successfully to $INSTALL_DIR"
echo "  * Config:  $CONFIG_DIR/fluxwan.json"
echo "  * Start:   systemctl start fluxwan"
echo "  * Web UI:  http://<router-ip>:8080"
echo "======================================================================"