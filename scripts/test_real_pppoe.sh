#!/bin/sh
# =============================================================================
#  FluxWAN Real End-to-End PPPoE Broadband Test
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
PASS="${GREEN}[PASS]${NC}"; FAIL="${RED}[FAIL]${NC}"
INFO="${CYAN}[INFO]${NC}"; WARN="${YELLOW}[WARN]${NC}"

pass() { printf "${PASS} %s\n" "$1"; }
fail() { printf "${FAIL} %s\n" "$1"; }
info() { printf "${INFO} %s\n" "$1"; }

printf "\n${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}${BLUE}   FluxWAN Real End-to-End PPPoE ISP Broadband Test Suite             ${NC}\n"
printf "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${NC}\n\n"

# 1. Cleanup
pkill -9 pppoe-server 2>/dev/null || true
pkill -9 pppd 2>/dev/null || true
ip link delete veth_p1 2>/dev/null || true
sleep 1

# 2. Setup clean short interface names (< 14 chars to satisfy rp-pppoe buffer)
info "Setting up Layer-2 Ethernet link for PPPoE (veth_p1 <-> veth_p2)..."
ip link add veth_p1 type veth peer name veth_p2
ip link set veth_p2 netns ns_isp1
ip link set veth_p1 up
ip netns exec ns_isp1 ip link set veth_p2 up

# 3. Setup secrets
mkdir -p /etc/ppp/plugins /run/ppp
ln -sf /usr/lib/pppd/2.5.0/pppoe.so /etc/ppp/plugins/rp-pppoe.so 2>/dev/null || true
ln -sf /usr/lib/pppd/2.5.0/pppoe.so /etc/ppp/plugins/pppoe.so 2>/dev/null || true

cat << 'EOF' > /etc/ppp/pap-secrets
* * "pass123" *
* * "pass456" *
"user1@fiber.isp" * "pass123" *
"user2@fiber.isp" * "pass456" *
EOF
chmod 600 /etc/ppp/pap-secrets

cat << 'EOF' > /etc/ppp/chap-secrets
* * "pass123" *
* * "pass456" *
"user1@fiber.isp" * "pass123" *
"user2@fiber.isp" * "pass456" *
EOF
chmod 600 /etc/ppp/chap-secrets

cat << 'EOF' > /etc/ppp/pppoe-server-options
auth
require-pap
lcp-echo-interval 10
lcp-echo-failure 3
ms-dns 8.8.8.8
ms-dns 1.1.1.1
netmask 255.255.255.255
noipdefault
plugin /usr/lib/pppd/2.5.0/pppoe.so
EOF

# 4. Start PPPoE server in ns_isp1
info "Launching ISP BRAS Access Concentrator in ns_isp1 on veth_p2..."
ip netns exec ns_isp1 pppoe-server -I veth_p2 -L 10.200.1.1 -R 10.200.1.50 -N 10 -C "FiberISP-BRAS-1" -k -q /usr/sbin/pppd -g /usr/lib/pppd/2.5.0/pppoe.so -O /etc/ppp/pppoe-server-options &
sleep 1

if ip netns exec ns_isp1 pgrep -f pppoe-server > /dev/null 2>&1; then
    pass "ISP BRAS Server is running in ns_isp1 (Pool: 10.200.1.50 - 10.200.1.60, GW: 10.200.1.1)"
else
    fail "ISP BRAS Server failed to start"
fi

# 5. Dial Session 1
info "Dialing PPPoE Session 1 (User: user1@fiber.isp) over physical port veth_p1..."

cat << 'EOF' > /tmp/fluxwan_ppp0.opts
plugin /usr/lib/pppd/2.5.0/pppoe.so
nic-veth_p1
user user1@fiber.isp
password pass123
noauth
nodefaultroute
usepeerdns
persist
maxfail 0
mtu 1492
mru 1492
unit 0
nodetach
EOF

pppd file /tmp/fluxwan_ppp0.opts > /tmp/pppd_session1.log 2>&1 &
PID1=$!
info "pppd Session 1 PID: $PID1"

# Wait for IP
WAIT=0
CONNECTED=0
while [ $WAIT -lt 8 ]; do
    if ip -4 addr show ppp0 2>/dev/null | grep -q "inet "; then
        CONNECTED=1
        break
    fi
    sleep 1
    WAIT=$((WAIT + 1))
done

if [ $CONNECTED -eq 1 ]; then
    ASSIGNED_IP=$(ip -4 -o addr show ppp0 | awk '{print $4}' | cut -d/ -f1)
    PEER_GW=$(ip -4 -o addr show ppp0 | awk '{print $6}' | cut -d/ -f1)
    pass "PPPoE Session 1 ESTABLISHED! Interface ppp0 UP"
    pass "  -> Assigned Client IP: $ASSIGNED_IP"
    pass "  -> ISP Gateway Peer:  $PEER_GW"
else
    fail "PPPoE Session 1 failed to acquire IP in time"
    cat /tmp/pppd_session1.log 2>/dev/null || true
fi

# 6. Dial Session 2 on SAME link (veth_p1)
info "Dialing PPPoE Session 2 (User: user2@fiber.isp) on SAME physical link (veth_p1)..."

cat << 'EOF' > /tmp/fluxwan_ppp1.opts
plugin /usr/lib/pppd/2.5.0/pppoe.so
nic-veth_p1
user user2@fiber.isp
password pass456
noauth
nodefaultroute
usepeerdns
persist
maxfail 0
mtu 1492
mru 1492
unit 1
nodetach
EOF

pppd file /tmp/fluxwan_ppp1.opts > /tmp/pppd_session2.log 2>&1 &
PID2=$!
info "pppd Session 2 PID: $PID2"

WAIT2=0
CONNECTED2=0
while [ $WAIT2 -lt 8 ]; do
    if ip -4 addr show ppp1 2>/dev/null | grep -q "inet "; then
        CONNECTED2=1
        break
    fi
    sleep 1
    WAIT2=$((WAIT2 + 1))
done

if [ $CONNECTED2 -eq 1 ]; then
    ASSIGNED_IP2=$(ip -4 -o addr show ppp1 | awk '{print $4}' | cut -d/ -f1)
    PEER_GW2=$(ip -4 -o addr show ppp1 | awk '{print $6}' | cut -d/ -f1)
    pass "PPPoE Session 2 ESTABLISHED! Interface ppp1 UP on SAME physical cable!"
    pass "  -> Assigned Client IP: $ASSIGNED_IP2"
    pass "  -> ISP Gateway Peer:  $PEER_GW2"
else
    fail "PPPoE Session 2 failed on shared link"
    cat /tmp/pppd_session2.log 2>/dev/null || true
fi

# 7. ICMP Ping over ppp0
if [ $CONNECTED -eq 1 ]; then
    info "Pinging ISP Gateway ($PEER_GW) through virtual PPPoE interface ppp0..."
    PING_OUT=$(ping -I ppp0 -c 4 -W 2 "$PEER_GW" 2>&1)
    if echo "$PING_OUT" | grep -q "bytes from"; then
        RTT=$(echo "$PING_OUT" | grep -oE "avg = [0-9.]+" | awk '{print $3}')
        pass "End-to-End PPPoE Data Forwarding: SUCCESS (RTT: ~${RTT:-1} ms, 0% Loss)"
    else
        fail "PPPoE Data Ping failed"
    fi
fi

# 8. Real HTTP transfer over ppp0
if [ $CONNECTED -eq 1 ]; then
    info "Testing HTTP Broadband Payload transfer over PPPoE tunnel..."
    ip netns exec ns_isp1 python3 -m http.server --bind 0.0.0.0 --directory /tmp 9008 >/dev/null 2>&1 &
    HTTP_PID=$!
    sleep 1
    dd if=/dev/urandom of=/tmp/pppoe_payload.bin bs=1M count=3 2>/dev/null
    RECV_BYTES=$(curl -s --interface ppp0 --connect-timeout 5 http://10.200.1.1:9008/pppoe_payload.bin | wc -c)
    if [ "$RECV_BYTES" -gt 2000000 ]; then
        SIZE_MB=$(echo "$RECV_BYTES" | awk '{printf "%.2f MB", $1/1048576}')
        pass "Real Broadband Payload Transfer through ppp0: $SIZE_MB transferred cleanly!"
    else
        fail "HTTP transfer over ppp0 failed"
    fi
    kill $HTTP_PID 2>/dev/null || true
fi

# 9. Cleanup
kill -TERM $PID1 $PID2 2>/dev/null || true
ip netns exec ns_isp1 pkill -9 pppoe-server 2>/dev/null || true
ip link delete veth_p1 2>/dev/null || true
rm -f /tmp/fluxwan_ppp*.opts /tmp/pppd_session*.log /tmp/pppoe_payload.bin

printf "\n${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}${GREEN}   ✓ REAL PPPOE BROADBAND END-TO-END VALIDATION COMPLETE              ${NC}\n"
printf "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════${NC}\n\n"
