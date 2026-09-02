#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Real Network Lab — Topology Provisioning Script
# Creates Linux Network Namespaces, veth pairs, routing tables, and sysctls.
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo " [FluxWAN LAB] Provisioning Real Linux Network Namespaces & veth Topology"
echo "======================================================================"

# Ensure root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (sudo)." >&2
    exit 1
fi

# Clean up any leftover namespaces from previous runs
for ns in ns-lan ns-router ns-isp1 ns-isp2 ns-isp3 ns-internet; do
    if ip netns list | grep -qw "$ns"; then
        echo "[*] Cleaning up existing namespace: $ns"
        ip netns del "$ns" || true
    fi
done

# 1. Create Namespaces
echo "[+] Creating Network Namespaces..."
ip netns add ns-lan
ip netns add ns-router
ip netns add ns-isp1
ip netns add ns-isp2
ip netns add ns-isp3
ip netns add ns-internet

# 2. Enable Loopbacks
for ns in ns-lan ns-router ns-isp1 ns-isp2 ns-isp3 ns-internet; do
    ip netns exec "$ns" ip link set lo up
done

# 3. Create Virtual Ethernet (veth) Pairs
echo "[+] Creating veth interface pairs..."

# LAN Connection (Client <-> Router)
ip link add veth-lan-c type veth peer name veth-lan-r
ip link set veth-lan-c netns ns-lan
ip link set veth-lan-r netns ns-router

# WAN 1 Connection (Router <-> ISP 1)
ip link add veth-wan1-r type veth peer name veth-wan1-isp
ip link set veth-wan1-r netns ns-router
ip link set veth-wan1-isp netns ns-isp1

# WAN 2 Connection (Router <-> ISP 2)
ip link add veth-wan2-r type veth peer name veth-wan2-isp
ip link set veth-wan2-r netns ns-router
ip link set veth-wan2-isp netns ns-isp2

# WAN 3 Connection (Router <-> ISP 3)
ip link add veth-wan3-r type veth peer name veth-wan3-isp
ip link set veth-wan3-r netns ns-router
ip link set veth-wan3-isp netns ns-isp3

# ISP to Internet Server Connections
ip link add veth-isp1-net type veth peer name veth-net-isp1
ip link set veth-isp1-net netns ns-isp1
ip link set veth-net-isp1 netns ns-internet

ip link add veth-isp2-net type veth peer name veth-net-isp2
ip link set veth-isp2-net netns ns-isp2
ip link set veth-net-isp2 netns ns-internet

ip link add veth-isp3-net type veth peer name veth-net-isp3
ip link set veth-isp3-net netns ns-isp3
ip link set veth-net-isp3 netns ns-internet

# 4. Configure IP Addresses & Bring Up Links
echo "[+] Assigning IP Addresses..."

# --- NS-LAN (Client) ---
ip netns exec ns-lan ip addr add 192.168.1.100/24 dev veth-lan-c
ip netns exec ns-lan ip link set veth-lan-c up
ip netns exec ns-lan ip route add default via 192.168.1.1

# --- NS-ROUTER (FluxWAN Multi-WAN Appliance) ---
ip netns exec ns-router ip addr add 192.168.1.1/24 dev veth-lan-r
ip netns exec ns-router ip link set veth-lan-r up

ip netns exec ns-router ip addr add 10.10.1.2/24 dev veth-wan1-r
ip netns exec ns-router ip link set veth-wan1-r up

ip netns exec ns-router ip addr add 10.10.2.2/24 dev veth-wan2-r
ip netns exec ns-router ip link set veth-wan2-r up

ip netns exec ns-router ip addr add 10.10.3.2/24 dev veth-wan3-r
ip netns exec ns-router ip link set veth-wan3-r up

# Enable IP forwarding and loose reverse-path filtering for multi-WAN in router
ip netns exec ns-router sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns-router sysctl -qw net.ipv4.conf.all.rp_filter=2
ip netns exec ns-router sysctl -qw net.ipv4.conf.default.rp_filter=2
ip netns exec ns-router sysctl -qw net.ipv4.conf.veth-lan-r.rp_filter=2
ip netns exec ns-router sysctl -qw net.ipv4.conf.veth-wan1-r.rp_filter=2
ip netns exec ns-router sysctl -qw net.ipv4.conf.veth-wan2-r.rp_filter=2
ip netns exec ns-router sysctl -qw net.ipv4.conf.veth-wan3-r.rp_filter=2

# Configure iptables/nftables MASQUERADE on WAN interfaces inside ns-router
if command -v iptables >/dev/null 2>&1; then
    ip netns exec ns-router iptables -t nat -F
    ip netns exec ns-router iptables -t nat -A POSTROUTING -o veth-wan1-r -j MASQUERADE
    ip netns exec ns-router iptables -t nat -A POSTROUTING -o veth-wan2-r -j MASQUERADE
    ip netns exec ns-router iptables -t nat -A POSTROUTING -o veth-wan3-r -j MASQUERADE
fi

# --- NS-ISP1 ---
ip netns exec ns-isp1 ip addr add 10.10.1.1/24 dev veth-wan1-isp
ip netns exec ns-isp1 ip link set veth-wan1-isp up
ip netns exec ns-isp1 ip addr add 172.16.1.1/24 dev veth-isp1-net
ip netns exec ns-isp1 ip link set veth-isp1-net up
ip netns exec ns-isp1 sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns-isp1 ip route add 192.168.1.0/24 via 10.10.1.2 || true

# --- NS-ISP2 ---
ip netns exec ns-isp2 ip addr add 10.10.2.1/24 dev veth-wan2-isp
ip netns exec ns-isp2 ip link set veth-wan2-isp up
ip netns exec ns-isp2 ip addr add 172.16.2.1/24 dev veth-isp2-net
ip netns exec ns-isp2 ip link set veth-isp2-net up
ip netns exec ns-isp2 sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns-isp2 ip route add 192.168.1.0/24 via 10.10.2.2 || true

# --- NS-ISP3 ---
ip netns exec ns-isp3 ip addr add 10.10.3.1/24 dev veth-wan3-isp
ip netns exec ns-isp3 ip link set veth-wan3-isp up
ip netns exec ns-isp3 ip addr add 172.16.3.1/24 dev veth-isp3-net
ip netns exec ns-isp3 ip link set veth-isp3-net up
ip netns exec ns-isp3 sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns-isp3 ip route add 192.168.1.0/24 via 10.10.3.2 || true

# --- NS-INTERNET (Target Servers: 1.1.1.1, 8.8.8.8, 172.16.0.100) ---
ip netns exec ns-internet ip addr add 172.16.1.2/24 dev veth-net-isp1
ip netns exec ns-internet ip link set veth-net-isp1 up
ip netns exec ns-internet ip addr add 172.16.2.2/24 dev veth-net-isp2
ip netns exec ns-internet ip link set veth-net-isp2 up
ip netns exec ns-internet ip addr add 172.16.3.2/24 dev veth-net-isp3
ip netns exec ns-internet ip link set veth-net-isp3 up

# Add dummy internet IPs on loopback of target server namespace
ip netns exec ns-internet ip addr add 8.8.8.8/32 dev lo
ip netns exec ns-internet ip addr add 1.1.1.1/32 dev lo
ip netns exec ns-internet ip addr add 9.9.9.9/32 dev lo
ip netns exec ns-internet ip addr add 172.16.0.100/32 dev lo

# Return routes from Internet to WAN subnets
ip netns exec ns-internet ip route add 10.10.1.0/24 via 172.16.1.1 dev veth-net-isp1 || true
ip netns exec ns-internet ip route add 10.10.2.0/24 via 172.16.2.1 dev veth-net-isp2 || true
ip netns exec ns-internet ip route add 10.10.3.0/24 via 172.16.3.1 dev veth-net-isp3 || true

# 5. Generate FluxWAN Lab Configuration File
cat <<EOF > tests/lab/fluxwan_lab_config.json
{
  "lan": {
    "interface": "veth-lan-r",
    "ip": "192.168.1.1",
    "netmask": "255.255.255.0",
    "dhcp_enabled": true,
    "dhcp_start": "192.168.1.100",
    "dhcp_end": "192.168.1.200",
    "dhcp_lease_time": 43200
  },
  "wans": [
    {
      "id": 1,
      "name": "veth-wan1-r",
      "label": "WAN1_Fiber",
      "type": "static",
      "ip": "10.10.1.2",
      "netmask": "255.255.255.0",
      "gateway": "10.10.1.1",
      "dns": ["8.8.8.8"],
      "weight": 100,
      "probe_target": "8.8.8.8",
      "table_id": 101
    },
    {
      "id": 2,
      "name": "veth-wan2-r",
      "label": "WAN2_LTE",
      "type": "static",
      "ip": "10.10.2.2",
      "netmask": "255.255.255.0",
      "gateway": "10.10.2.1",
      "dns": ["1.1.1.1"],
      "weight": 50,
      "probe_target": "1.1.1.1",
      "table_id": 102
    },
    {
      "id": 3,
      "name": "veth-wan3-r",
      "label": "WAN3_Backup",
      "type": "static",
      "ip": "10.10.3.2",
      "netmask": "255.255.255.0",
      "gateway": "10.10.3.1",
      "dns": ["9.9.9.9"],
      "weight": 75,
      "probe_target": "9.9.9.9",
      "table_id": 103
    }
  ],
  "prober": {
    "interval_ms": 200,
    "timeout_ms": 500,
    "loss_window": 10,
    "max_acceptable_rtt_ms": 200,
    "max_acceptable_loss_pct": 20.0
  },
  "sticky": {
    "enabled": true,
    "timeout_seconds": 300
  },
  "web": {
    "bind_ip": "127.0.0.1",
    "port": 8080
  },
  "auth": {
    "enabled": true,
    "username": "admin",
    "password": "admin",
    "session_token": "flux_lab_token_123"
  }
}
EOF

echo "[✓] Real Linux Network Lab Topology successfully provisioned and ready."
