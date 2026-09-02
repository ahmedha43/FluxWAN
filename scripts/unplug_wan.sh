#!/usr/bin/env bash
# Unplug WAN cable simulation
WAN_IDX=${1:-2}

echo "======================================================================"
echo "   ⚠️  SIMULATING CABLE PULL ON WAN $WAN_IDX (veth_wan$WAN_IDX -> DOWN)   "
echo "======================================================================"

ip link set "veth_wan$WAN_IDX" down
ip netns exec "ns_isp$WAN_IDX" ip link set "veth_isp$WAN_IDX" down 2>/dev/null || true

echo " [✓] Cable Unplugged! WAN $WAN_IDX is now DISCONNECTED."
echo " [✓] Check http://localhost:8080 to see instantaneous Failover transition!"
