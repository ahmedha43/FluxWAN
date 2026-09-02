#!/bin/bash
# Continuous Live Traffic Generator for FluxWAN Web UI Real-Time Verification

echo "Starting Continuous Live Traffic Generator across LAN and Multi-WAN..."

# Start web servers in ISP namespaces if not already active
ip netns exec ns_isp1 python3 -m http.server 80 --directory /tmp/isp1_web >/dev/null 2>&1 &
ip netns exec ns_isp2 python3 -m http.server 80 --directory /tmp/isp2_web >/dev/null 2>&1 &
ip netns exec ns_isp3 python3 -m http.server 80 --directory /tmp/isp3_web >/dev/null 2>&1 &

# Loop generating real client downloads through LAN to trigger live Bandwidth counters
while true; do
    # Fetch from WAN 1, WAN 2, WAN 3 in parallel
    ip netns exec ns_client curl -s --max-time 1 -o /dev/null http://10.10.1.1/data.bin 2>/dev/null &
    ip netns exec ns_client curl -s --max-time 1 -o /dev/null http://10.10.2.1/data.bin 2>/dev/null &
    ip netns exec ns_client curl -s --max-time 1 -o /dev/null http://10.10.3.1/data.bin 2>/dev/null &
    sleep 0.2
done
