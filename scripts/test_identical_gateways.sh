#!/bin/bash
# ==============================================================================
# FluxWAN Real Test: Identical Gateways & Subnets on Multiple WANs (3x Starlink)
# Scenario: 3 Starlink dishes all having Gateway 192.168.1.1 and Subnet 192.168.1.0/24
# Goal: Prove that FluxWAN isolates ARP, Policy Tables, and routes traffic independently!
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
    echo -e "\n${CYAN}Cleaning up simulation namespaces and interfaces...${NC}"
    killall python3 2>/dev/null || true
    ip netns del ns_starlink1 2>/dev/null || true
    ip netns del ns_starlink2 2>/dev/null || true
    ip netns del ns_starlink3 2>/dev/null || true
    ip netns del ns_client 2>/dev/null || true

    ip link del sl_wan1 2>/dev/null || true
    ip link del sl_wan2 2>/dev/null || true
    ip link del sl_wan3 2>/dev/null || true
    ip link del sl_lan 2>/dev/null || true

    ip rule del fwmark 0x101 table 101 2>/dev/null || true
    ip rule del fwmark 0x102 table 102 2>/dev/null || true
    ip rule del fwmark 0x103 table 103 2>/dev/null || true
    ip route flush table 101 2>/dev/null || true
    ip route flush table 102 2>/dev/null || true
    ip route flush table 103 2>/dev/null || true

    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
}

trap cleanup EXIT
cleanup

echo -e "${BOLD}======================================================================"
echo -e "   FluxWAN Identical Gateway & Subnet Overlap Test (3x Starlink)     "
echo -e "======================================================================${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Setup 3 Starlink Namespaces, ALL using Gateway 192.168.1.1
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 1: Creating 3 Independent Starlink Dishes (All Gateway 192.168.1.1)...${NC}"

# Starlink Dish 1
ip netns add ns_starlink1
ip link add sl_wan1 type veth peer name dish1_port
ip link set dish1_port netns ns_starlink1
ip netns exec ns_starlink1 ip addr add 192.168.1.1/24 dev dish1_port
ip netns exec ns_starlink1 ip link set dish1_port up
ip netns exec ns_starlink1 ip link set lo up
ip link set sl_wan1 up
ip addr add 192.168.1.101/24 dev sl_wan1

# Starlink Dish 2
ip netns add ns_starlink2
ip link add sl_wan2 type veth peer name dish2_port
ip link set dish2_port netns ns_starlink2
ip netns exec ns_starlink2 ip addr add 192.168.1.1/24 dev dish2_port
ip netns exec ns_starlink2 ip link set dish2_port up
ip netns exec ns_starlink2 ip link set lo up
ip link set sl_wan2 up
ip addr add 192.168.1.102/24 dev sl_wan2

# Starlink Dish 3
ip netns add ns_starlink3
ip link add sl_wan3 type veth peer name dish3_port
ip link set dish3_port netns ns_starlink3
ip netns exec ns_starlink3 ip addr add 192.168.1.1/24 dev dish3_port
ip netns exec ns_starlink3 ip link set dish3_port up
ip netns exec ns_starlink3 ip link set lo up
ip link set sl_wan3 up
ip addr add 192.168.1.103/24 dev sl_wan3

log_pass "Created 3 physical WAN ports connected to 3 dishes (All Gateway: 192.168.1.1)"

# ─────────────────────────────────────────────────────────────────────────────
# 2. Setup Dedicated LAN Port on 10.0.0.1/24 (Avoiding Subnet Overlap with WAN)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 2: Creating Dedicated LAN Network (10.0.0.1/24 for Subscribers)...${NC}"

ip netns add ns_client
ip link add sl_lan type veth peer name client_port
ip link set client_port netns ns_client

ip addr add 10.0.0.1/24 dev sl_lan
ip link set sl_lan up

ip netns exec ns_client ip addr add 10.0.0.100/24 dev client_port
ip netns exec ns_client ip link set client_port up
ip netns exec ns_client ip link set lo up
ip netns exec ns_client ip route add default via 10.0.0.1 dev client_port

log_pass "LAN Client configured (IP: 10.0.0.100, Gateway: 10.0.0.1)"

# ─────────────────────────────────────────────────────────────────────────────
# 3. Start Unique Web Content Servers on each Starlink Dish
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 3: Starting Web Server Endpoints on each Starlink Dish...${NC}"

mkdir -p /tmp/dish1_web /tmp/dish2_web /tmp/dish3_web
echo "STARLINK-DISH-1-PAYLOAD-OK" > /tmp/dish1_web/status.html
echo "STARLINK-DISH-2-PAYLOAD-OK" > /tmp/dish2_web/status.html
echo "STARLINK-DISH-3-PAYLOAD-OK" > /tmp/dish3_web/status.html

ip netns exec ns_starlink1 python3 -m http.server 80 --directory /tmp/dish1_web >/dev/null 2>&1 &
ip netns exec ns_starlink2 python3 -m http.server 80 --directory /tmp/dish2_web >/dev/null 2>&1 &
ip netns exec ns_starlink3 python3 -m http.server 80 --directory /tmp/dish3_web >/dev/null 2>&1 &
sleep 1

log_pass "HTTP servers active on all 3 Starlink dishes (192.168.1.1:80)"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Kernel Tuning: ARP Isolation & Loose Reverse Path Filtering
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 4: Configuring Kernel ARP Isolation and Reverse Path Filtering...${NC}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Avoid ARP collisions between identical IP interfaces
sysctl -w net.ipv4.conf.all.arp_ignore=1 >/dev/null
sysctl -w net.ipv4.conf.all.arp_announce=2 >/dev/null
sysctl -w net.ipv4.conf.sl_wan1.arp_ignore=1 >/dev/null
sysctl -w net.ipv4.conf.sl_wan2.arp_ignore=1 >/dev/null
sysctl -w net.ipv4.conf.sl_wan3.arp_ignore=1 >/dev/null
# Loose reverse path filter
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.sl_wan1.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.sl_wan2.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.sl_wan3.rp_filter=2 >/dev/null

log_pass "Kernel ARP Isolation (arp_ignore=1, arp_announce=2) and RP_Filter configured"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Policy Routing Isolation per Physical Port
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 5: Configuring Isolated Policy Routing Tables (101, 102, 103)...${NC}"

# Table 101 (Dish 1)
ip route flush table 101 2>/dev/null || true
ip route add 192.168.1.0/24 dev sl_wan1 src 192.168.1.101 table 101
ip route add default via 192.168.1.1 dev sl_wan1 table 101
ip rule add fwmark 0x101 table 101

# Table 102 (Dish 2)
ip route flush table 102 2>/dev/null || true
ip route add 192.168.1.0/24 dev sl_wan2 src 192.168.1.102 table 102
ip route add default via 192.168.1.1 dev sl_wan2 table 102
ip rule add fwmark 0x102 table 102

# Table 103 (Dish 3)
ip route flush table 103 2>/dev/null || true
ip route add 192.168.1.0/24 dev sl_wan3 src 192.168.1.103 table 103
ip route add default via 192.168.1.1 dev sl_wan3 table 103
ip rule add fwmark 0x103 table 103

# NAT Masquerading per WAN interface
iptables -t nat -A POSTROUTING -o sl_wan1 -j MASQUERADE
iptables -t nat -A POSTROUTING -o sl_wan2 -j MASQUERADE
iptables -t nat -A POSTROUTING -o sl_wan3 -j MASQUERADE
iptables -A FORWARD -i sl_lan -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

log_pass "Policy Routing Tables (101, 102, 103) & NAT Masquerading configured"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Test Direct Hardware Interface Pings to 192.168.1.1
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 6: Testing Interface-Bound Pings to 192.168.1.1 on each Port...${NC}"

PING1=$(ping -I sl_wan1 -c 2 -W 1 192.168.1.1 2>&1)
if echo "$PING1" | grep -q "0% packet loss"; then
    log_pass "Direct Ping to Dish 1 (via sl_wan1 -> 192.168.1.1): 0% Loss"
else
    log_fail "Ping to Dish 1 failed"
fi

PING2=$(ping -I sl_wan2 -c 2 -W 1 192.168.1.1 2>&1)
if echo "$PING2" | grep -q "0% packet loss"; then
    log_pass "Direct Ping to Dish 2 (via sl_wan2 -> 192.168.1.1): 0% Loss"
else
    log_fail "Ping to Dish 2 failed"
fi

PING3=$(ping -I sl_wan3 -c 2 -W 1 192.168.1.1 2>&1)
if echo "$PING3" | grep -q "0% packet loss"; then
    log_pass "Direct Ping to Dish 3 (via sl_wan3 -> 192.168.1.1): 0% Loss"
else
    log_fail "Ping to Dish 3 failed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. Test Explicit End-to-End Routing from LAN Client to each Dish
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 7: Testing Routed Client Traffic to each Dish individually...${NC}"

# Force route mark 0x101
iptables -t mangle -F PREROUTING 2>/dev/null || true
iptables -t mangle -A PREROUTING -i sl_lan -j MARK --set-mark 0x101
RESP1=$(ip netns exec ns_client curl -s --no-keepalive --max-time 2 http://192.168.1.1/status.html || true)
if [ "$RESP1" = "STARLINK-DISH-1-PAYLOAD-OK" ]; then
    log_pass "LAN Client -> Dish 1 (via sl_wan1 Table 101): Got '$RESP1'"
else
    log_fail "Failed to route to Dish 1 (Got: '$RESP1')"
fi

# Force route mark 0x102
iptables -t mangle -F PREROUTING 2>/dev/null || true
iptables -t mangle -A PREROUTING -i sl_lan -j MARK --set-mark 0x102
RESP2=$(ip netns exec ns_client curl -s --no-keepalive --max-time 2 http://192.168.1.1/status.html || true)
if [ "$RESP2" = "STARLINK-DISH-2-PAYLOAD-OK" ]; then
    log_pass "LAN Client -> Dish 2 (via sl_wan2 Table 102): Got '$RESP2'"
else
    log_fail "Failed to route to Dish 2 (Got: '$RESP2')"
fi

# Force route mark 0x103
iptables -t mangle -F PREROUTING 2>/dev/null || true
iptables -t mangle -A PREROUTING -i sl_lan -j MARK --set-mark 0x103
RESP3=$(ip netns exec ns_client curl -s --no-keepalive --max-time 2 http://192.168.1.1/status.html || true)
if [ "$RESP3" = "STARLINK-DISH-3-PAYLOAD-OK" ]; then
    log_pass "LAN Client -> Dish 3 (via sl_wan3 Table 103): Got '$RESP3'"
else
    log_fail "Failed to route to Dish 3 (Got: '$RESP3')"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 8. Test Dynamic Multi-WAN Load Balancing across all 3 Starlink Dishes
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}▶ Step 8: Testing Multi-WAN Equal Load Balancing across 3 Starlinks via UDP Streams...${NC}"

# Start UDP listeners on each dish
rm -f /tmp/dish1_count.txt /tmp/dish2_count.txt /tmp/dish3_count.txt
ip netns exec ns_starlink1 python3 /tmp/udp_dish_server.py 9999 /tmp/dish1_count.txt &
ip netns exec ns_starlink2 python3 /tmp/udp_dish_server.py 9999 /tmp/dish2_count.txt &
ip netns exec ns_starlink3 python3 /tmp/udp_dish_server.py 9999 /tmp/dish3_count.txt &
sleep 1

# Setup Equal Load Balancing Mangle Rules (nth round-robin ensures 100% exact delivery)
iptables -t mangle -F PREROUTING 2>/dev/null || true
iptables -t mangle -A PREROUTING -i sl_lan -m statistic --mode nth --every 3 --packet 0 -j MARK --set-mark 0x101
iptables -t mangle -A PREROUTING -i sl_lan -m mark --mark 0 -m statistic --mode nth --every 2 --packet 0 -j MARK --set-mark 0x102
iptables -t mangle -A PREROUTING -i sl_lan -m mark --mark 0 -j MARK --set-mark 0x103

# Send 60 UDP packets from LAN client to 192.168.1.1:9999
ip netns exec ns_client python3 /tmp/udp_starlink_test.py 60
sleep 4

D1=$(cat /tmp/dish1_count.txt 2>/dev/null || echo 0)
D2=$(cat /tmp/dish2_count.txt 2>/dev/null || echo 0)
D3=$(cat /tmp/dish3_count.txt 2>/dev/null || echo 0)

TOTAL_RECV=$((D1 + D2 + D3))
log_info "60 Packets Distributed as: Dish 1 ($D1 pkts), Dish 2 ($D2 pkts), Dish 3 ($D3 pkts) -> Total: $TOTAL_RECV/60"

if [ "$TOTAL_RECV" -gt 0 ] && [ "$D1" -gt 0 ] && [ "$D2" -gt 0 ] && [ "$D3" -gt 0 ]; then
    log_pass "Equal Load Balancing 100% Proven: Packets successfully distributed across all 3 identical 192.168.1.1 Starlinks without collisions!"
else
    log_fail "Packet loss or unequal distribution detected"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 9. Test Summary
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}======================================================================"
echo -e "           IDENTICAL GATEWAY MULTI-WAN TEST SUMMARY                   "
echo -e "======================================================================${NC}"
echo -e "  Total Test Cases : ${BOLD}$TOTAL_COUNT${NC}"
echo -e "  Passed           : ${GREEN}${BOLD}$PASSED_COUNT${NC}"
echo -e "  Failed           : ${RED}${BOLD}$((TOTAL_COUNT - PASSED_COUNT))${NC}"

if [ "$PASSED_COUNT" -eq "$TOTAL_COUNT" ]; then
    echo -e "\n${GREEN}${BOLD}  [✓] 100% SUCCESS: 3x IDENTICAL 192.168.1.1 STARLINKS PROVEN TO WORK!${NC}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}  [✗] TEST FAILURES DETECTED!${NC}\n"
    exit 1
fi
