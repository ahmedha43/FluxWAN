#!/bin/bash
set -e

# FluxWAN Carrier-Grade Xray-core High-Performance Deployer
# Arguments: $1 = SERVER_NAME, $2 = OPTIONAL_UUID
SERVER_NAME=${1:-"FluxWAN_Node"}
SERVER_UUID=${2:-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "11111111-2222-3333-4444-555555555555")}

echo "=========================================================="
echo "  Deploying FluxWAN High-Speed VLESS Node: $SERVER_NAME   "
echo "  UUID: $SERVER_UUID                                      "
echo "=========================================================="

# 1. Kernel Optimization & TCP BBR Congestion Control
echo "[1/6] Optimizing Kernel & Enabling TCP BBR..."
cat << 'EOF' > /etc/sysctl.d/99-fluxwan-bbr.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_forward = 1
fs.file-max = 1000000
EOF
sysctl -p /etc/sysctl.d/99-fluxwan-bbr.conf >/dev/null 2>&1 || true

cat << 'EOF' > /etc/security/limits.d/99-fluxwan.conf
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
EOF

# 2. Firewall adjustment
echo "[2/6] Configuring Firewall..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 8080/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw disable >/dev/null 2>&1 || true
fi

# 3. Install dependencies
echo "[3/6] Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq curl wget unzip tar ca-certificates >/dev/null 2>&1 || true

# 4. Download and Install Official Xray-core
echo "[4/6] Installing latest official Xray-core..."
mkdir -p /usr/local/bin /usr/local/etc/xray /var/log/xray

ARCH="64"
XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
curl -sSL -m 30 "$XRAY_URL" -o /tmp/xray.zip
rm -rf /tmp/xray_extract
mkdir -p /tmp/xray_extract
unzip -o -q /tmp/xray.zip -d /tmp/xray_extract
cp -f /tmp/xray_extract/xray /usr/local/bin/xray
chmod +x /usr/local/bin/xray
rm -rf /tmp/xray.zip /tmp/xray_extract

echo "Xray Version: $(/usr/local/bin/xray version | head -n 1)"

# 5. Generate Configuration
echo "[5/6] Generating High-Throughput Xray Configuration..."
cat << EOF > /usr/local/etc/xray/config.json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vless-in-80",
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$SERVER_UUID",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/"
        }
      }
    },
    {
      "tag": "vless-in-8080",
      "port": 8080,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$SERVER_UUID",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/"
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIP"
      }
    },
    {
      "tag": "blocked",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}
EOF

# 6. Systemd Service setup
echo "[6/6] Setting up systemd service..."
cat << 'EOF' > /etc/systemd/system/xray.service
[Unit]
Description=FluxWAN Carrier Xray Service
Documentation=https://github.com/xtls/xray-core
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=always
RestartSec=3s
LimitNPROC=1000000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray >/dev/null 2>&1
systemctl restart xray
sleep 1

if systemctl is-active --quiet xray; then
    echo "=========================================================="
    echo "  SUCCESS: Xray Service is Active and Running!            "
    echo "=========================================================="
else
    echo "ERROR: Xray failed to start. Journal log:"
    journalctl -u xray -n 20 --no-pager
    exit 1
fi
