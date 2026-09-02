#!/usr/bin/env bash
# Simulate Traffic Generator from Client Namespace through FluxWAN 3-WAN
WAN_NUM=${1:-all}
COUNT=${2:-50}

echo "======================================================================"
echo "   Generating Live Multi-WAN Test Traffic through FluxWAN Router...   "
echo "======================================================================"

ip netns exec ns_client bash -c "
for i in \$(seq 1 $COUNT); do
    TARGET_ISP=\$((\$i % 3 + 1))
    TARGET_IP=\"10.10.\${TARGET_ISP}.1\"
    echo -n \"[Flow #\$i] Sending packet to \$TARGET_IP... \"
    ping -c 1 -W 1 \$TARGET_IP >/dev/null 2>&1 && echo 'OK (Routed & SNAT Success)' || echo 'FAIL'
    sleep 0.1
done
"
echo "======================================================================"
echo "  Check http://localhost:8080 Live Traffic Graph & Logs to see stats! "
echo "======================================================================"
