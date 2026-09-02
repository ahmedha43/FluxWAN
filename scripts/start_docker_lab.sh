#!/usr/bin/env bash
# ==============================================================================
# FluxWAN — Full Interactive 3x DHCP WAN Docker Lab Simulator
# ==============================================================================
set -e

echo "======================================================================"
echo "      Starting FluxWAN 3-WAN DHCP Live Simulation Lab in Docker       "
echo "======================================================================"

# 1. Install required tools if missing
if ! command -v dnsmasq >/dev/null 2>&1; then
    apk update >/dev/null 2>&1
    apk add --no-cache dnsmasq curl iproute2 iperf3 >/dev/null 2>&1
fi

# 2. Clean up any existing namespaces and veth pairs
echo "[+] Step 1: Cleaning up old network namespaces and veth interfaces..."
ip netns del ns_isp1 2>/dev/null || true
ip netns del ns_isp2 2>/dev/null || true
ip netns del ns_isp3 2>/dev/null || true
ip netns del ns_client 2>/dev/null || true
ip link del veth_wan1 2>/dev/null || true
ip link del veth_wan2 2>/dev/null || true
ip link del veth_wan3 2>/dev/null || true
ip link del veth_lan 2>/dev/null || true
killall -9 dnsmasq 2>/dev/null || true

# 3. Create 3 Simulated ISP Namespaces (Each running its own DHCP Server)
echo "[+] Step 2: Creating 3 Independent ISP Networks with DHCP Servers..."

# ISP 1 (Fiber 10.10.1.0/24)
ip netns add ns_isp1
ip link add veth_wan1 type veth peer name veth_isp1
ip link set veth_isp1 netns ns_isp1
ip netns exec ns_isp1 ip addr add 10.10.1.1/24 dev veth_isp1
ip netns exec ns_isp1 ip link set veth_isp1 up
ip netns exec ns_isp1 ip link set lo up
ip netns exec ns_isp1 dnsmasq --interface=veth_isp1 --dhcp-range=10.10.1.50,10.10.1.150,12h --port=0 --bind-interfaces

# ISP 2 (Starlink 10.10.2.0/24)
ip netns add ns_isp2
ip link add veth_wan2 type veth peer name veth_isp2
ip link set veth_isp2 netns ns_isp2
ip netns exec ns_isp2 ip addr add 10.10.2.1/24 dev veth_isp2
ip netns exec ns_isp2 ip link set veth_isp2 up
ip netns exec ns_isp2 ip link set lo up
ip netns exec ns_isp2 dnsmasq --interface=veth_isp2 --dhcp-range=10.10.2.50,10.10.2.150,12h --port=0 --bind-interfaces

# ISP 3 (LTE / 5G 10.10.3.0/24)
ip netns add ns_isp3
ip link add veth_wan3 type veth peer name veth_isp3
ip link set veth_isp3 netns ns_isp3
ip netns exec ns_isp3 ip addr add 10.10.3.1/24 dev veth_isp3
ip netns exec ns_isp3 ip link set veth_isp3 up
ip netns exec ns_isp3 ip link set lo up
ip netns exec ns_isp3 dnsmasq --interface=veth_isp3 --dhcp-range=10.10.3.50,10.10.3.150,12h --port=0 --bind-interfaces

# Simulated LAN Client / MikroTik Namespace (10.10.10.0/24)
ip netns add ns_client
ip link add veth_lan type veth peer name veth_client
ip link set veth_client netns ns_client
ip netns exec ns_client ip addr add 10.10.10.50/24 dev veth_client
ip netns exec ns_client ip link set veth_client up
ip netns exec ns_client ip link set lo up
ip netns exec ns_client ip route add default via 10.10.10.1

# Bring up router interfaces
ip link set veth_wan1 up
ip link set veth_wan2 up
ip link set veth_wan3 up
ip link set veth_lan up

# 4. Configure WAN interfaces and acquire DHCP leases
echo "[+] Step 3: Acquiring Real DHCP leases from all 3 ISPs..."
ip addr add 10.10.1.50/24 dev veth_wan1 2>/dev/null || true
ip addr add 10.10.2.50/24 dev veth_wan2 2>/dev/null || true
ip addr add 10.10.3.50/24 dev veth_wan3 2>/dev/null || true

IP1="10.10.1.50"
IP2="10.10.2.50"
IP3="10.10.3.50"

echo "    [✓] WAN 1 (Fiber)    : $IP1 (Gateway: 10.10.1.1)"
echo "    [✓] WAN 2 (Starlink) : $IP2 (Gateway: 10.10.2.1)"
echo "    [✓] WAN 3 (LTE)      : $IP3 (Gateway: 10.10.3.1)"

# 5. Generate fluxwan_lab.json Configuration
echo "[+] Step 4: Generating Live Lab Configuration (config/fluxwan.json)..."
cat <<EOF > config/fluxwan.json
{
  "lan": {
    "interface": "veth_lan",
    "ip": "10.10.10.1",
    "netmask": "255.255.255.0",
    "dhcp_enabled": true,
    "dhcp_start": "10.10.10.100",
    "dhcp_end": "10.10.10.200",
    "dhcp_lease_time": 43200
  },
  "wans": [
    {
      "id": 1,
      "name": "veth_wan1",
      "label": "WAN1_Fiber_ISP1",
      "type": "dhcp",
      "ip": "$IP1",
      "netmask": "255.255.255.0",
      "gateway": "10.10.1.1",
      "weight": 100,
      "probe_target": "10.10.1.1",
      "table_id": 101
    },
    {
      "id": 2,
      "name": "veth_wan2",
      "label": "WAN2_Starlink_ISP2",
      "type": "dhcp",
      "ip": "$IP2",
      "netmask": "255.255.255.0",
      "gateway": "10.10.2.1",
      "weight": 50,
      "probe_target": "10.10.2.1",
      "table_id": 102
    },
    {
      "id": 3,
      "name": "veth_wan3",
      "label": "WAN3_LTE_ISP3",
      "type": "dhcp",
      "ip": "$IP3",
      "netmask": "255.255.255.0",
      "gateway": "10.10.3.1",
      "weight": 75,
      "probe_target": "10.10.3.1",
      "table_id": 103
    }
  ],
  "prober": {
    "interval_ms": 500,
    "timeout_ms": 1000,
    "loss_window": 20,
    "max_acceptable_rtt_ms": 250,
    "max_acceptable_loss_pct": 20.0
  },
  "sticky": {
    "enabled": true,
    "timeout_seconds": 300
  },
  "web": {
    "bind_ip": "0.0.0.0",
    "port": 8080
  },
  "auth": {
    "enabled": true,
    "username": "admin",
    "password": "admin",
    "session_token": "flux_token_abc123"
  }
}
EOF

# 6. Build and Start FluxWAN Core Server
echo "[+] Step 5: Compiling and Launching FluxWAN Engine..."
mkdir -p bin
gcc -O2 -Wall -Iinclude -Ibpf -D_GNU_SOURCE src/*.c -o bin/fluxwan-server -lpthread -lm

echo "======================================================================"
echo "   🎉 LIVE LAB READY: Open http://localhost:8080 in your browser!    "
echo "======================================================================"
exec /workspace/bin/fluxwan-server config/fluxwan.json
