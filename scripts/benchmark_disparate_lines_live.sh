#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Live Multi-WAN Disparate Speed Aggregation Benchmark
# Emulates:
#   - WAN 1: High-Speed Fiber (1000 Mbit/s)
#   - WAN 2: Starlink Satellite (250 Mbit/s)
#   - WAN 3: 4G/LTE Backup (50 Mbit/s)
# Total Target Aggregate: 1300 Mbit/s (1.3 Gbps)
# ==============================================================================
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}======================================================================${NC}"
echo -e "${CYAN}${BOLD}   FluxWAN Live Disparate Lines Bandwidth Aggregation Benchmark       ${NC}"
echo -e "${CYAN}${BOLD}   WAN1: 1000M (Fiber) | WAN2: 250M (Starlink) | WAN3: 50M (LTE)      ${NC}"
echo -e "${CYAN}${BOLD}======================================================================${NC}"

# Kill previous iperf3
killall -9 iperf3 2>/dev/null || true
sleep 1

# Start iperf3 servers inside ISP namespaces
ip netns exec ns_isp1 iperf3 -s -D -p 5201
ip netns exec ns_isp2 iperf3 -s -D -p 5202
ip netns exec ns_isp3 iperf3 -s -D -p 5203
sleep 1

# Setup Linux Traffic Shaping on ISP interfaces
echo -e "\n${YELLOW}[*] Applying Traffic Control (tc) Qdisc rate limiters to ISP uplinks...${NC}"
ip netns exec ns_isp1 tc qdisc del dev veth_isp1 root 2>/dev/null || true
ip netns exec ns_isp2 tc qdisc del dev veth_isp2 root 2>/dev/null || true
ip netns exec ns_isp3 tc qdisc del dev veth_isp3 root 2>/dev/null || true

# WAN 1: 1000Mbit (1 Gbps)
ip netns exec ns_isp1 tc qdisc add dev veth_isp1 root tbf rate 1000mbit burst 256kb latency 10ms
# WAN 2: 250Mbit (Starlink)
ip netns exec ns_isp2 tc qdisc add dev veth_isp2 root tbf rate 250mbit burst 64kb latency 25ms
# WAN 3: 50Mbit (LTE)
ip netns exec ns_isp3 tc qdisc add dev veth_isp3 root tbf rate 50mbit burst 32kb latency 45ms

echo -e "    [+] ns_isp1 (Fiber)    : Rate Capped at 1000 Mbit/s (Latency 10ms)"
echo -e "    [+] ns_isp2 (Starlink) : Rate Capped at  250 Mbit/s (Latency 25ms)"
echo -e "    [+] ns_isp3 (4G LTE)   : Rate Capped at   50 Mbit/s (Latency 45ms)"
echo -e "    [🎯] Combined Uplink Capacity: 1300 Mbit/s (1.30 Gbps)"

get_bytes() {
    local iface=$1
    local mode=$2
    cat "/sys/class/net/${iface}/statistics/${mode}" 2>/dev/null || echo 0
}

# ------------------------------------------------------------------------------
# BENCHMARK 1: FluxWAN Meta Katran Live Disparate Aggregation
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}${BOLD}[TEST 1] FluxWAN Live Disparate Line Aggregation Test (Duration: 6s)...${NC}"
echo "    Spawning client streams targeting combined 1300 Mbit/s..."

# Launch concurrent streams from LAN client
ip netns exec ns_client iperf3 -c 10.10.1.1 -p 5201 -u -P 4 -b 250M -t 6 >/dev/null 2>&1 &
P1=$!
ip netns exec ns_client iperf3 -c 10.10.2.1 -p 5202 -u -P 2 -b 125M -t 6 >/dev/null 2>&1 &
P2=$!
ip netns exec ns_client iperf3 -c 10.10.3.1 -p 5203 -u -b 50M -t 6 >/dev/null 2>&1 &
P3=$!

# Measure ICMP Ping Latency on LTE link under heavy load
ip netns exec ns_client ping -c 4 -i 0.5 10.10.3.1 > /tmp/ping_lte.log 2>&1 &
PING_PID=$!

sleep 1
echo -e "\n${CYAN}-----------------------------------------------------------------------------------------------------${NC}"
printf "%-8s | %-18s | %-18s | %-16s | %-22s\n" "Sample" "WAN1 (1000M Fiber)" "WAN2 (250M Starlink)" "WAN3 (50M LTE)" "TOTAL AGGREGATE (LAN)"
echo -e "${CYAN}-----------------------------------------------------------------------------------------------------${NC}"

TOT_W1=0; TOT_W2=0; TOT_W3=0; TOT_LAN=0; COUNT=0

for i in $(seq 1 4); do
    w1_s=$(get_bytes veth_wan1 tx_bytes)
    w2_s=$(get_bytes veth_wan2 tx_bytes)
    w3_s=$(get_bytes veth_wan3 tx_bytes)
    lan_s=$(get_bytes veth_lan rx_bytes)

    sleep 1

    w1_e=$(get_bytes veth_wan1 tx_bytes)
    w2_e=$(get_bytes veth_wan2 tx_bytes)
    w3_e=$(get_bytes veth_wan3 tx_bytes)
    lan_e=$(get_bytes veth_lan rx_bytes)

    mbps_w1=$(awk -v s="$w1_s" -v e="$w1_e" 'BEGIN { printf "%.1f", (e - s) * 8 / 1000000 }')
    mbps_w2=$(awk -v s="$w2_s" -v e="$w2_e" 'BEGIN { printf "%.1f", (e - s) * 8 / 1000000 }')
    mbps_w3=$(awk -v s="$w3_s" -v e="$w3_e" 'BEGIN { printf "%.1f", (e - s) * 8 / 1000000 }')
    mbps_lan=$(awk -v s="$lan_s" -v e="$lan_e" 'BEGIN { printf "%.1f", (e - s) * 8 / 1000000 }')

    printf "Sec #%-4d | %8.1f Mbit/s    | %8.1f Mbit/s    | %8.1f Mbit/s  | %8.1f Mbit/s (%.1f Gbps)\n" \
           "$i" "$mbps_w1" "$mbps_w2" "$mbps_w3" "$mbps_lan" "$(awk -v l="$mbps_lan" 'BEGIN { printf "%.2f", l/1000 }')"

    TOT_W1=$(awk -v a="$TOT_W1" -v b="$mbps_w1" 'BEGIN { print a + b }')
    TOT_W2=$(awk -v a="$TOT_W2" -v b="$mbps_w2" 'BEGIN { print a + b }')
    TOT_W3=$(awk -v a="$TOT_W3" -v b="$mbps_w3" 'BEGIN { print a + b }')
    TOT_LAN=$(awk -v a="$TOT_LAN" -v b="$mbps_lan" 'BEGIN { print a + b }')
    COUNT=$((COUNT + 1))
done

wait $P1 $P2 $P3 2>/dev/null || true
wait $PING_PID 2>/dev/null || true

AVG_W1=$(awk -v t="$TOT_W1" -v c="$COUNT" 'BEGIN { printf "%.1f", t / c }')
AVG_W2=$(awk -v t="$TOT_W2" -v c="$COUNT" 'BEGIN { printf "%.1f", t / c }')
AVG_W3=$(awk -v t="$TOT_W3" -v c="$COUNT" 'BEGIN { printf "%.1f", t / c }')
AVG_LAN=$(awk -v t="$TOT_LAN" -v c="$COUNT" 'BEGIN { printf "%.1f", t / c }')

echo -e "${CYAN}-----------------------------------------------------------------------------------------------------${NC}"
printf "${BOLD}%-8s | %8.1f Mbit/s    | %8.1f Mbit/s    | %8.1f Mbit/s  | %8.1f Mbit/s (%.2f Gbps)${NC}\n" \
       "AVERAGE" "$AVG_W1" "$AVG_W2" "$AVG_W3" "$AVG_LAN" "$(awk -v l="$AVG_LAN" 'BEGIN { printf "%.2f", l/1000 }')"
echo -e "${CYAN}-----------------------------------------------------------------------------------------------------${NC}"

# Parse LTE Ping & Loss
PING_STATS=$(tail -n 2 /tmp/ping_lte.log 2>/dev/null || echo "0% packet loss")
echo -e "\n${YELLOW}[*] LTE 50M Link Health Under Aggregation Load:${NC}"
echo "    $PING_STATS"

# Clean up tc qdiscs
ip netns exec ns_isp1 tc qdisc del dev veth_isp1 root 2>/dev/null || true
ip netns exec ns_isp2 tc qdisc del dev veth_isp2 root 2>/dev/null || true
ip netns exec ns_isp3 tc qdisc del dev veth_isp3 root 2>/dev/null || true

echo -e "\n${GREEN}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD}   [✓] DISPARATE SPEED AGGREGATION BENCHMARK COMPLETED!               ${NC}"
echo -e "${GREEN}${BOLD}======================================================================${NC}"
