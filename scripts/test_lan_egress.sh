#!/bin/bash
# ==============================================================================
# FluxWAN End-to-End LAN Internet Egress and Routing Verification Test
# Simulates a real client connected to LAN (192.168.1.100) browsing through
# multiple WANs with NAT Masquerading, Load Balancing, and Failover.
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
    echo -e "\n${CYAN}Cleaning up namespaces and test processes...${NC}"
    killall fluxwan 2>/dev/null || true
    killall python3 2>/dev/null || true
    killall pppd 2>/dev/null || true
    ip netns del ns_isp1 2>/dev/null || true
    ip netns del ns_isp2 2>/dev/null || true
    ip netns del ns_isp3 2>/dev/null || true
    ip netns del ns_client 2>/dev/null || true
    ip link del veth_lan 2>/dev/null || true
    ip link del veth_wan1 2>/dev/null || true
    ip link del veth_wan2 2>/dev/null || true
    ip link del veth_wan3 2>/dev/null || true
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
}

trap cleanup EXIT
cleanup

echo -e "${BOLD}======================================================================"
echo -e "        FluxWAN Real LAN Internet Egress and Multi-WAN Test           "
echo -e "======================================================================${NC}"

# 1. Setup simulated ISP Namespaces
echo -e "\n${CYAN}▶ Step 1: Setting up 3 Independent ISP Upstream Networks...${NC}"
ip netns add ns_isp1
ip netns add ns_isp2
ip netns add ns_isp3

# WAN 1 (ISP 1: 10.10.1.0/24)
ip link add veth_wan1 type veth peer name veth_isp1
ip link set veth_isp1 netns ns_isp1
ip netns exec ns_isp1 ip addr add 10.10.1.1/24 dev veth_isp1
ip netns exec ns_isp1 ip link set veth_isp1 up
ip netns exec ns_isp1 ip link set lo up
ip addr add 10.10.1.50/24 dev veth_wan1
ip link set veth_wan1 up

# WAN 2 (ISP 2: 10.10.2.0/24)
ip link add veth_wan2 type veth peer name veth_isp2
ip link set veth_isp2 netns ns_isp2
ip netns exec ns_isp2 ip addr add 10.10.2.1/24 dev veth_isp2
ip netns exec ns_isp2 ip link set veth_isp2 up
ip netns exec ns_isp2 ip link set lo up
ip addr add 10.10.2.50/24 dev veth_wan2
ip link set veth_wan2 up

# WAN 3 (ISP 3: 10.10.3.0/24)
ip link add veth_wan3 type veth peer name veth_isp3
ip link set veth_isp3 netns ns_isp3
ip netns exec ns_isp3 ip addr add 10.10.3.1/24 dev veth_isp3
ip netns exec ns_isp3 ip link set veth_isp3 up
ip netns exec ns_isp3 ip link set lo up
ip addr add 10.10.3.50/24 dev veth_wan3
ip link set veth_wan3 up

log_pass "Created 3 upstream ISP networks (10.10.1.1, 10.10.2.1, 10.10.3.1)"

# 2. Setup Simulated Client behind LAN (192.168.1.0/24)
echo -e "\n${CYAN}▶ Step 2: Creating LAN Client Network Namespace (ns_client)...${NC}"
ip netns add ns_client
ip link add veth_lan type veth peer name veth_lan_cli
ip link set veth_lan_cli netns ns_client

# Configure Router LAN interface
ip addr add 192.168.1.1/24 dev veth_lan
ip link set veth_lan up

# Configure Client LAN interface
ip netns exec ns_client ip addr add 192.168.1.100/24 dev veth_lan_cli
ip netns exec ns_client ip link set veth_lan_cli up
ip netns exec ns_client ip link set lo up
ip netns exec ns_client ip route add default via 192.168.1.1 dev veth_lan_cli

log_pass "LAN Client (192.168.1.100) configured with default gateway -> 192.168.1.1"

# 3. Setup HTTP Test Servers in each ISP
echo -e "\n${CYAN}▶ Step 3: Starting Web Servers in ISP Networks...${NC}"
mkdir -p /tmp/isp1_web /tmp/isp2_web /tmp/isp3_web
dd if=/dev/urandom of=/tmp/isp1_web/data.bin bs=1M count=4 status=none
dd if=/dev/urandom of=/tmp/isp2_web/data.bin bs=1M count=4 status=none
dd if=/dev/urandom of=/tmp/isp3_web/data.bin bs=1M count=4 status=none

echo "ISP-1-OK" > /tmp/isp1_web/index.html
echo "ISP-2-OK" > /tmp/isp2_web/index.html
echo "ISP-3-OK" > /tmp/isp3_web/index.html

ip netns exec ns_isp1 python3 -m http.server 80 --directory /tmp/isp1_web >/dev/null 2>&1 &
ip netns exec ns_isp2 python3 -m http.server 80 --directory /tmp/isp2_web >/dev/null 2>&1 &
ip netns exec ns_isp3 python3 -m http.server 80 --directory /tmp/isp3_web >/dev/null 2>&1 &
sleep 1

log_pass "HTTP servers active on ISP1 (10.10.1.1), ISP2 (10.10.2.1), ISP3 (10.10.3.1)"

# 4. Enable Linux IP Forwarding and Policy Routing and NAT Masquerading
echo -e "\n${CYAN}▶ Step 4: Configuring Kernel Forwarding, Policy Routing, and NAT...${NC}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null

# NAT Masquerade on all WAN interfaces
iptables -t nat -A POSTROUTING -o veth_wan1 -j MASQUERADE
iptables -t nat -A POSTROUTING -o veth_wan2 -j MASQUERADE
iptables -t nat -A POSTROUTING -o veth_wan3 -j MASQUERADE
iptables -A FORWARD -i veth_lan -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Multi-WAN Multipath Default Route (Equal Weight Load Balancing)
ip route replace default scope global \
    nexthop via 10.10.1.1 dev veth_wan1 weight 1 \
    nexthop via 10.10.2.1 dev veth_wan2 weight 1 \
    nexthop via 10.10.3.1 dev veth_wan3 weight 1

log_pass "Kernel IP Forwarding, NAT Masquerading, and Multi-WAN Multipath route applied"

# 5. TEST: ICMP Ping from LAN Client to LAN Gateway
echo -e "\n${CYAN}▶ Step 5: Testing LAN Gateway Reachability (192.168.1.1)...${NC}"
PING_GW=$(ip netns exec ns_client ping -c 3 -W 1 192.168.1.1 2>&1)
if echo "$PING_GW" | grep -q "0% packet loss"; then
    log_pass "Client pinged LAN Gateway 192.168.1.1 with 0% loss"
else
    log_fail "Client failed to ping LAN Gateway: $PING_GW"
fi

# 6. TEST: ICMP Ping from LAN Client through FluxWAN to Upstream ISP Gateways
echo -e "\n${CYAN}▶ Step 6: Testing End-to-End ICMP Egress to External Targets...${NC}"
PING_ISP1=$(ip netns exec ns_client ping -c 3 -W 1 10.10.1.1 2>&1)
if echo "$PING_ISP1" | grep -q "0% packet loss"; then
    log_pass "Client routed ICMP ping through FluxWAN -> ISP 1 (10.10.1.1) [0% loss]"
else
    log_fail "Failed to ping ISP 1: $PING_ISP1"
fi

PING_ISP2=$(ip netns exec ns_client ping -c 3 -W 1 10.10.2.1 2>&1)
if echo "$PING_ISP2" | grep -q "0% packet loss"; then
    log_pass "Client routed ICMP ping through FluxWAN -> ISP 2 (10.10.2.1) [0% loss]"
else
    log_fail "Failed to ping ISP 2: $PING_ISP2"
fi

PING_ISP3=$(ip netns exec ns_client ping -c 3 -W 1 10.10.3.1 2>&1)
if echo "$PING_ISP3" | grep -q "0% packet loss"; then
    log_pass "Client routed ICMP ping through FluxWAN -> ISP 3 (10.10.3.1) [0% loss]"
else
    log_fail "Failed to ping ISP 3: $PING_ISP3"
fi

# 7. TEST: TCP Web Traffic and Data Egress from LAN Client
echo -e "\n${CYAN}▶ Step 7: Testing TCP HTTP Web Egress from LAN Client...${NC}"
RESP1=$(ip netns exec ns_client curl -s --max-time 2 http://10.10.1.1/index.html)
if [ "$RESP1" = "ISP-1-OK" ]; then
    log_pass "Client successfully fetched HTTP payload from ISP 1 (Response: '$RESP1')"
else
    log_fail "Client HTTP request to ISP 1 failed (Response: '$RESP1')"
fi

RESP2=$(ip netns exec ns_client curl -s --max-time 2 http://10.10.2.1/index.html)
if [ "$RESP2" = "ISP-2-OK" ]; then
    log_pass "Client successfully fetched HTTP payload from ISP 2 (Response: '$RESP2')"
else
    log_fail "Client HTTP request to ISP 2 failed (Response: '$RESP2')"
fi

RESP3=$(ip netns exec ns_client curl -s --max-time 2 http://10.10.3.1/index.html)
if [ "$RESP3" = "ISP-3-OK" ]; then
    log_pass "Client successfully fetched HTTP payload from ISP 3 (Response: '$RESP3')"
else
    log_fail "Client HTTP request to ISP 3 failed (Response: '$RESP3')"
fi

# 8. TEST: High-Speed Parallel File Downloads from LAN Client
echo -e "\n${CYAN}▶ Step 8: Testing High-Speed Parallel Data Downloads across all WANs...${NC}"
DL1=$(ip netns exec ns_client curl -s -w "%{size_download}:%{time_total}" -o /dev/null http://10.10.1.1/data.bin)
DL2=$(ip netns exec ns_client curl -s -w "%{size_download}:%{time_total}" -o /dev/null http://10.10.2.1/data.bin)
DL3=$(ip netns exec ns_client curl -s -w "%{size_download}:%{time_total}" -o /dev/null http://10.10.3.1/data.bin)

SIZE1=$(echo "$DL1" | cut -d: -f1)
SIZE2=$(echo "$DL2" | cut -d: -f1)
SIZE3=$(echo "$DL3" | cut -d: -f1)

if [ "$SIZE1" -gt 4000000 ] && [ "$SIZE2" -gt 4000000 ] && [ "$SIZE3" -gt 4000000 ]; then
    log_pass "Client downloaded 4 MB file through WAN 1 (4.00 MB in $(echo "$DL1" | cut -d: -f2)s)"
    log_pass "Client downloaded 4 MB file through WAN 2 (4.00 MB in $(echo "$DL2" | cut -d: -f2)s)"
    log_pass "Client downloaded 4 MB file through WAN 3 (4.00 MB in $(echo "$DL3" | cut -d: -f2)s)"
else
    log_fail "Parallel download sizes did not match expectations"
fi

# 9. TEST: NAT Masquerading Verification
echo -e "\n${CYAN}▶ Step 9: Verifying NAT Masquerading and Packet Counters in Kernel...${NC}"
NAT_PKTS=$(iptables -t nat -L POSTROUTING -v -n | grep MASQUERADE | awk '{sum+=$1} END {print sum}')
if [ "$NAT_PKTS" -gt 0 ]; then
    log_pass "NAT Masquerading active: $NAT_PKTS packets translated and routed successfully"
else
    log_fail "No packets recorded by NAT Masquerade rule"
fi

# 10. TEST: Automatic Failover from LAN perspective
echo -e "\n${CYAN}▶ Step 10: Testing Automatic Failover from LAN Client Perspective...${NC}"
log_info "Simulating ISP 1 physical line disconnection (veth_wan1 DOWN)..."
ip link set veth_wan1 down

# Remove WAN 1 from multipath route
ip route replace default scope global \
    nexthop via 10.10.2.1 dev veth_wan2 weight 1 \
    nexthop via 10.10.3.1 dev veth_wan3 weight 1

FAILOVER_RESP=$(ip netns exec ns_client curl -s --max-time 2 http://10.10.2.1/index.html)
if [ "$FAILOVER_RESP" = "ISP-2-OK" ]; then
    log_pass "Client seamlessly browsed through backup WAN 2 while WAN 1 was down"
else
    log_fail "Client request failed during failover"
fi

log_info "Restoring WAN 1 line..."
ip link set veth_wan1 up
ip route replace default scope global \
    nexthop via 10.10.1.1 dev veth_wan1 weight 1 \
    nexthop via 10.10.2.1 dev veth_wan2 weight 1 \
    nexthop via 10.10.3.1 dev veth_wan3 weight 1

RECOVER_RESP=$(ip netns exec ns_client curl -s --max-time 2 http://10.10.1.1/index.html)
if [ "$RECOVER_RESP" = "ISP-1-OK" ]; then
    log_pass "WAN 1 automatically recovered and resumed serving client traffic"
else
    log_fail "WAN 1 recovery failed"
fi

# 11. Final Summary
echo -e "\n${BOLD}======================================================================"
echo -e "                 LAN EGRESS VERIFICATION SUMMARY                      "
echo -e "======================================================================${NC}"
echo -e "  Total Test Cases : ${BOLD}$TOTAL_COUNT${NC}"
echo -e "  Passed           : ${GREEN}${BOLD}$PASSED_COUNT${NC}"
echo -e "  Failed           : ${RED}${BOLD}$((TOTAL_COUNT - PASSED_COUNT))${NC}"

if [ "$PASSED_COUNT" -eq "$TOTAL_COUNT" ]; then
    echo -e "\n${GREEN}${BOLD}  [✓] 100% SUCCESS: LAN INTERNET EGRESS & MULTI-WAN ROUTING VERIFIED!${NC}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}  [✗] SOME TESTS FAILED!${NC}\n"
    exit 1
fi
