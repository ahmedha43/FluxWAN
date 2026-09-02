#!/usr/bin/env bash
# Plug WAN cable back in simulation
WAN_IDX=${1:-2}

echo "======================================================================"
echo "   🔌  SIMULATING CABLE RECONNECT ON WAN $WAN_IDX (veth_wan$WAN_IDX -> UP) "
echo "======================================================================"

ip link set "veth_wan$WAN_IDX" up
ip netns exec "ns_isp$WAN_IDX" ip link set "veth_isp$WAN_IDX" up 2>/dev/null || true
udhcpc -i "veth_wan$WAN_IDX" -n -q -s /usr/share/udhcpc/default.script >/dev/null 2>&1 || true

echo " [✓] Cable Reconnected! WAN $WAN_IDX is now UP and leased via DHCP."
echo " [✓] Check http://localhost:8080 to see automatic Health Recovery!"
