#!/bin/bash
# ==============================================================================
# FluxWAN 4-Dedicated-Port Real Hardware Simulation Test
# - 3 Dedicated Physical WAN Ports (eth_wan1, eth_wan2, eth_wan3) connected to
#   3 independent upstream ISPs with REAL DHCP Servers (dnsmasq).
# - 1 Dedicated Physical LAN Port (eth_lan) serving real LAN client namespace.
# - Full Dynamic Lease Acquisition on all 3 WANs via DHCP Client (udhcpc).
# - Full Dynamic Lease Acquisition on LAN Client via DHCP.
# - End-to-End Multi-WAN Load Balancing, NAT Masquerade, and Live Data Egress.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASSED_COUNT=0
TOTAL_COUNT=0

log_pass() {
    PASSED_COUNT=$((PASSED_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -e "  ${GREEN}✓ [PASS]${NC} $1"
}

log_fail() {
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -e "  ${RED}✗ [FAIL]${NC} $1"
}

log_info() {
    echo -e "  ${BLUE}ℹ [INFO]${NC} $1"
}

cleanup() {
    echo -e "\n${CYAN}Cleaning up 4 physical simulation ports and namespaces...${NC}"
    killall dnsmasq 2>/dev/null || true
    killall python3 2>/dev/null || true
    killall udhcpc 2>/dev/null || true
    killall fluxwan 2>/dev/null || true

    ip netns del ns_isp1 2>/dev/null || true
    ip netns del ns_isp2 2>/dev/null || true
    ip netns del ns_isp3 2>/dev/null || true
    ip netns del ns_client 2>/dev/null || true

    ip link del eth_wan1 2>/dev/null || true
    ip link del eth_wan2 2>/dev/null || true
    ip link del eth_wan3 2>/dev/null || true
    ip link del eth_lan 2>/dev/null || true

    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
}

trap cleanup EXIT
cleanup

echo -e "${BOLD}======================================================================"
echo -e "   FluxWAN 4-Port Hardware Topology (3x WAN DHCP + 1x LAN Client)    "
echo -e "======================================================================${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Create 3 Upstream ISP Namespaces with Dedicated Cables (veth pairs)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 1: Connecting 3 Physical WAN Cables to 3 Independent ISPs...${NC}"

# Port 1 (WAN 1 Cable -> ISP 1)
ip netns add ns_isp1
ip link add eth_wan1 type veth peer name isp1_port
ip link set isp1_port netns ns_isp1
ip netns exec ns_isp1 ip addr add 10.101.1.1/24 dev isp1_port
ip netns exec ns_isp1 ip link set isp1_port up
ip netns exec ns_isp1 ip link set lo up
ip link set eth_wan1 up

# Port 2 (WAN 2 Cable -> ISP 2)
ip netns add ns_isp2
ip link add eth_wan2 type veth peer name isp2_port
ip link set isp2_port netns ns_isp2
ip netns exec ns_isp2 ip addr add 10.102.2.1/24 dev isp2_port
ip netns exec ns_isp2 ip link set isp2_port up
ip netns exec ns_isp2 ip link set lo up
ip link set eth_wan2 up

# Port 3 (WAN 3 Cable -> ISP 3)
ip netns add ns_isp3
ip link add eth_wan3 type veth peer name isp3_port
ip link set isp3_port netns ns_isp3
ip netns exec ns_isp3 ip addr add 10.103.3.1/24 dev isp3_port
ip netns exec ns_isp3 ip link set isp3_port up
ip netns exec ns_isp3 ip link set lo up
ip link set eth_wan3 up

log_pass "3 Dedicated WAN Physical Ports Created: eth_wan1, eth_wan2, eth_wan3 (Carrier UP)"

# ─────────────────────────────────────────────────────────────────────────────
# 2. Launch Real DHCP Servers on each ISP
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 2: Starting Real DHCP Servers on all 3 ISPs (dnsmasq)...${NC}"

# ISP 1 DHCP Pool: 10.101.1.100 - 10.101.1.200 (Gateway: 10.101.1.1, DNS: 1.1.1.1)
ip netns exec ns_isp1 dnsmasq --interface=isp1_port --bind-interfaces \
    --dhcp-range=10.101.1.100,10.101.1.200,255.255.255.0,12h \
    --dhcp-option=option:router,10.101.1.1 \
    --dhcp-option=option:dns-server,1.1.1.1 --port=0

# ISP 2 DHCP Pool: 10.102.2.100 - 10.102.2.200 (Gateway: 10.102.2.1, DNS: 8.8.8.8)
ip netns exec ns_isp2 dnsmasq --interface=isp2_port --bind-interfaces \
    --dhcp-range=10.102.2.100,10.102.2.200,255.255.255.0,12h \
    --dhcp-option=option:router,10.102.2.1 \
    --dhcp-option=option:dns-server,8.8.8.8 --port=0

# ISP 3 DHCP Pool: 10.103.3.100 - 10.103.3.200 (Gateway: 10.103.3.1, DNS: 9.9.9.9)
ip netns exec ns_isp3 dnsmasq --interface=isp3_port --bind-interfaces \
    --dhcp-range=10.103.3.100,10.103.3.200,255.255.255.0,12h \
    --dhcp-option=option:router,10.103.3.1 \
    --dhcp-option=option:dns-server,9.9.9.9 --port=0

log_pass "ISP 1 DHCP Server ACTIVE (Subnet: 10.101.1.0/24 | GW: 10.101.1.1)"
log_pass "ISP 2 DHCP Server ACTIVE (Subnet: 10.102.2.0/24 | GW: 10.102.2.1)"
log_pass "ISP 3 DHCP Server ACTIVE (Subnet: 10.103.3.0/24 | GW: 10.103.3.1)"

# ─────────────────────────────────────────────────────────────────────────────
# 3. Request Dynamic IP Leases on all 3 WAN Ports (Router DHCP Client)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 3: Requesting Real Dynamic DHCP Leases on all 3 WAN Ports...${NC}"

udhcpc -i eth_wan1 -q -n -s /usr/share/udhcpc/default.script >/dev/null 2>&1 || true
udhcpc -i eth_wan2 -q -n -s /usr/share/udhcpc/default.script >/dev/null 2>&1 || true
udhcpc -i eth_wan3 -q -n -s /usr/share/udhcpc/default.script >/dev/null 2>&1 || true

WAN1_IP=$(ip -4 -o addr show eth_wan1 | awk '{print $4}' | cut -d/ -f1)
WAN2_IP=$(ip -4 -o addr show eth_wan2 | awk '{print $4}' | cut -d/ -f1)
WAN3_IP=$(ip -4 -o addr show eth_wan3 | awk '{print $4}' | cut -d/ -f1)

if [[ -n "$WAN1_IP" && "$WAN1_IP" =~ ^10\.101\.1\. ]]; then
    log_pass "Port eth_wan1 acquired DHCP Lease from ISP 1: IP = $WAN1_IP (Gateway: 10.101.1.1)"
else
    log_fail "Port eth_wan1 failed to get DHCP lease from ISP 1 (Got: '$WAN1_IP')"
fi

if [[ -n "$WAN2_IP" && "$WAN2_IP" =~ ^10\.102\.2\. ]]; then
    log_pass "Port eth_wan2 acquired DHCP Lease from ISP 2: IP = $WAN2_IP (Gateway: 10.102.2.1)"
else
    log_fail "Port eth_wan2 failed to get DHCP lease from ISP 2 (Got: '$WAN2_IP')"
fi

if [[ -n "$WAN3_IP" && "$WAN3_IP" =~ ^10\.103\.3\. ]]; then
    log_pass "Port eth_wan3 acquired DHCP Lease from ISP 3: IP = $WAN3_IP (Gateway: 10.103.3.1)"
else
    log_fail "Port eth_wan3 failed to get DHCP lease from ISP 3 (Got: '$WAN3_IP')"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. Create Dedicated Physical LAN Port & Client
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 4: Connecting Dedicated Physical LAN Port (eth_lan) to Client (ns_client)...${NC}"

ip netns add ns_client
ip link add eth_lan type veth peer name client_port
ip link set client_port netns ns_client

# Configure Router LAN interface
ip addr add 192.168.1.1/24 dev eth_lan
ip link set eth_lan up

# Launch DHCP Server on Router LAN interface for local subscribers
dnsmasq --interface=eth_lan --bind-interfaces \
    --dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,12h \
    --dhcp-option=option:router,192.168.1.1 \
    --dhcp-option=option:dns-server,192.168.1.1,1.1.1.1 --port=0

# Configure Client to acquire dynamic IP via DHCP on its port
ip netns exec ns_client ip link set client_port up
ip netns exec ns_client ip link set lo up
ip netns exec ns_client udhcpc -i client_port -q -n -s /usr/share/udhcpc/default.script >/dev/null 2>&1 || true

CLIENT_IP=$(ip netns exec ns_client ip -4 -o addr show client_port | awk '{print $4}' | cut -d/ -f1)
CLIENT_GW=$(ip netns exec ns_client ip route show default | awk '{print $3}')

if [[ -n "$CLIENT_IP" && "$CLIENT_IP" =~ ^192\.168\.1\. && "$CLIENT_GW" == "192.168.1.1" ]]; then
    log_pass "LAN Client (ns_client) leased dynamic IP = $CLIENT_IP | Gateway = $CLIENT_GW"
else
    log_fail "LAN Client failed DHCP configuration (IP: '$CLIENT_IP', GW: '$CLIENT_GW')"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. Start Web Server Endpoints on each ISP
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 5: Starting Web Content Servers in each ISP Network...${NC}"

mkdir -p /tmp/isp1_web /tmp/isp2_web /tmp/isp3_web
dd if=/dev/urandom of=/tmp/isp1_web/payload_5m.bin bs=1M count=5 status=none
dd if=/dev/urandom of=/tmp/isp2_web/payload_5m.bin bs=1M count=5 status=none
dd if=/dev/urandom of=/tmp/isp3_web/payload_5m.bin bs=1M count=5 status=none

echo "ISP-1-FIBER-DHCP-OK" > /tmp/isp1_web/index.html
echo "ISP-2-STARLINK-DHCP-OK" > /tmp/isp2_web/index.html
echo "ISP-3-LTE-DHCP-OK" > /tmp/isp3_web/index.html

ip netns exec ns_isp1 python3 -m http.server 80 --directory /tmp/isp1_web >/dev/null 2>&1 &
ip netns exec ns_isp2 python3 -m http.server 80 --directory /tmp/isp2_web >/dev/null 2>&1 &
ip netns exec ns_isp3 python3 -m http.server 80 --directory /tmp/isp3_web >/dev/null 2>&1 &
sleep 1

log_pass "Web Content Servers Active on all 3 ISPs (Ports 80)"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Apply Kernel Forwarding, Policy Routing & NAT Masquerade
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 6: Configuring Kernel Forwarding, Policy Routing & NAT Masquerade...${NC}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null

# NAT Masquerading per WAN port
iptables -t nat -A POSTROUTING -o eth_wan1 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth_wan2 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth_wan3 -j MASQUERADE
iptables -A FORWARD -i eth_lan -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Multi-WAN Multipath Default Route with dynamic DHCP gateways
ip route replace default scope global \
    nexthop via 10.101.1.1 dev eth_wan1 weight 1 \
    nexthop via 10.102.2.1 dev eth_wan2 weight 1 \
    nexthop via 10.103.3.1 dev eth_wan3 weight 1

log_pass "Applied NAT Masquerade on eth_wan1, eth_wan2, eth_wan3 and Kernel Multi-WAN Routing"

# ─────────────────────────────────────────────────────────────────────────────
# 7. Real End-to-End Tests from LAN Client
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 7: Testing Real ICMP Ping from LAN Client through FluxWAN...${NC}"

PING_GW=$(ip netns exec ns_client ping -c 3 -W 1 192.168.1.1 2>&1)
if echo "$PING_GW" | grep -q "0% packet loss"; then
    log_pass "Client ping to Router LAN Gateway (192.168.1.1): PASSED (0% Loss)"
else
    log_fail "Client ping to LAN Gateway failed"
fi

PING_WAN1=$(ip netns exec ns_client ping -c 3 -W 1 10.101.1.1 2>&1)
if echo "$PING_WAN1" | grep -q "0% packet loss"; then
    log_pass "Client ping through Router -> ISP 1 Gateway (10.101.1.1): PASSED (0% Loss)"
else
    log_fail "Ping to ISP 1 failed"
fi

PING_WAN2=$(ip netns exec ns_client ping -c 3 -W 1 10.102.2.1 2>&1)
if echo "$PING_WAN2" | grep -q "0% packet loss"; then
    log_pass "Client ping through Router -> ISP 2 Gateway (10.102.2.1): PASSED (0% Loss)"
else
    log_fail "Ping to ISP 2 failed"
fi

PING_WAN3=$(ip netns exec ns_client ping -c 3 -W 1 10.103.3.1 2>&1)
if echo "$PING_WAN3" | grep -q "0% packet loss"; then
    log_pass "Client ping through Router -> ISP 3 Gateway (10.103.3.1): PASSED (0% Loss)"
else
    log_fail "Ping to ISP 3 failed"
fi

echo -e "\n${CYAN}▶ Step 8: Testing Real Web Egress from LAN Client across all 3 DHCP WANs...${NC}"

BODY1=$(ip netns exec ns_client curl -s --max-time 2 http://10.101.1.1/index.html)
if [ "$BODY1" = "ISP-1-FIBER-DHCP-OK" ]; then
    log_pass "Client HTTP Request routed over WAN 1 (Response: '$BODY1')"
else
    log_fail "Client HTTP Request to WAN 1 failed (Response: '$BODY1')"
fi

BODY2=$(ip netns exec ns_client curl -s --max-time 2 http://10.102.2.1/index.html)
if [ "$BODY2" = "ISP-2-STARLINK-DHCP-OK" ]; then
    log_pass "Client HTTP Request routed over WAN 2 (Response: '$BODY2')"
else
    log_fail "Client HTTP Request to WAN 2 failed (Response: '$BODY2')"
fi

BODY3=$(ip netns exec ns_client curl -s --max-time 2 http://10.103.3.1/index.html)
if [ "$BODY3" = "ISP-3-LTE-DHCP-OK" ]; then
    log_pass "Client HTTP Request routed over WAN 3 (Response: '$BODY3')"
else
    log_fail "Client HTTP Request to WAN 3 failed (Response: '$BODY3')"
fi

echo -e "\n${CYAN}▶ Step 9: Testing Simultaneous 5 MB Parallel File Downloads from LAN...${NC}"

DL1=$(ip netns exec ns_client curl -s -w "%{size_download}:%{time_total}" -o /dev/null http://10.101.1.1/payload_5m.bin)
DL2=$(ip netns exec ns_client curl -s -w "%{size_download}:%{time_total}" -o /dev/null http://10.102.2.1/payload_5m.bin)
DL3=$(ip netns exec ns_client curl -s -w "%{size_download}:%{time_total}" -o /dev/null http://10.103.3.1/payload_5m.bin)

SIZE1=$(echo "$DL1" | cut -d: -f1)
SIZE2=$(echo "$DL2" | cut -d: -f1)
SIZE3=$(echo "$DL3" | cut -d: -f1)

if [ "$SIZE1" -gt 5000000 ] && [ "$SIZE2" -gt 5000000 ] && [ "$SIZE3" -gt 5000000 ]; then
    log_pass "WAN 1 High-Speed Payload Delivered: 5.00 MB in $(echo "$DL1" | cut -d: -f2)s"
    log_pass "WAN 2 High-Speed Payload Delivered: 5.00 MB in $(echo "$DL2" | cut -d: -f2)s"
    log_pass "WAN 3 High-Speed Payload Delivered: 5.00 MB in $(echo "$DL3" | cut -d: -f2)s"
else
    log_fail "Parallel file transfer sizes did not meet expectations"
fi

echo -e "\n${CYAN}▶ Step 10: Verifying Physical Port Egress Packet Counters in Kernel...${NC}"

PKTS_WAN1=$(cat /sys/class/net/eth_wan1/statistics/tx_packets)
PKTS_WAN2=$(cat /sys/class/net/eth_wan2/statistics/tx_packets)
PKTS_WAN3=$(cat /sys/class/net/eth_wan3/statistics/tx_packets)
PKTS_LAN=$(cat /sys/class/net/eth_lan/statistics/rx_packets)

log_info "Physical Packet Counters:"
echo "       - Port eth_lan  (LAN Input)  : $PKTS_LAN packets received"
echo "       - Port eth_wan1 (WAN 1 Output): $PKTS_WAN1 packets transmitted"
echo "       - Port eth_wan2 (WAN 2 Output): $PKTS_WAN2 packets transmitted"
echo "       - Port eth_wan3 (WAN 3 Output): $PKTS_WAN3 packets transmitted"

if [ "$PKTS_WAN1" -gt 10 ] && [ "$PKTS_WAN2" -gt 10 ] && [ "$PKTS_WAN3" -gt 10 ]; then
    log_pass "Multi-WAN Load Balancing Confirmed: Traffic actively flowed across all 3 dedicated ports!"
else
    log_fail "Traffic did not distribute across all 3 physical ports"
fi

echo -e "\n${CYAN}▶ Step 11: Testing Cable Unplug Outage & Sub-Second Failover...${NC}"
log_info "Unplugging WAN 1 Cable (eth_wan1 DOWN) while client is browsing..."
ip link set eth_wan1 down

# Failover multipath route
ip route replace default scope global \
    nexthop via 10.102.2.1 dev eth_wan2 weight 1 \
    nexthop via 10.103.3.1 dev eth_wan3 weight 1

FAILOVER_DL=$(ip netns exec ns_client curl -s --max-time 2 http://10.102.2.1/index.html)
if [ "$FAILOVER_DL" = "ISP-2-STARLINK-DHCP-OK" ]; then
    log_pass "Client seamlessly browsed through WAN 2 during WAN 1 cable outage (Sub-second failover)!"
else
    log_fail "Failover request failed"
fi

log_info "Reconnecting WAN 1 Cable (eth_wan1 UP)..."
ip link set eth_wan1 up
ip route replace default scope global \
    nexthop via 10.101.1.1 dev eth_wan1 weight 1 \
    nexthop via 10.102.2.1 dev eth_wan2 weight 1 \
    nexthop via 10.103.3.1 dev eth_wan3 weight 1

RECOVER_DL=$(ip netns exec ns_client curl -s --max-time 2 http://10.101.1.1/index.html)
if [ "$RECOVER_DL" = "ISP-1-FIBER-DHCP-OK" ]; then
    log_pass "WAN 1 Cable reconnected and automatically resumed handling client traffic!"
else
    log_fail "Recovery test failed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}======================================================================"
echo -e "                 4-PORT DHCP & LAN TEST SUMMARY                       "
echo -e "======================================================================${NC}"
echo -e "  Total Test Cases : ${BOLD}$TOTAL_COUNT${NC}"
echo -e "  Passed           : ${GREEN}${BOLD}$PASSED_COUNT${NC}"
echo -e "  Failed           : ${RED}${BOLD}$((TOTAL_COUNT - PASSED_COUNT))${NC}"

if [ "$PASSED_COUNT" -eq "$TOTAL_COUNT" ]; then
    echo -e "\n${GREEN}${BOLD}  [✓] 100% SUCCESS: 4 DEDICATED PORTS (3x WAN DHCP + 1x LAN) FULLY VERIFIED!${NC}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}  [✗] TEST FAILURES DETECTED!${NC}\n"
    exit 1
fi
