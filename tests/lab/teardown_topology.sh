#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Real Network Lab — Teardown & Clean Up Script
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo " [FluxWAN LAB] Tearing down Real Network Lab Namespaces & Interfaces"
echo "======================================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (sudo)." >&2
    exit 1
fi

# Kill any running background servers/probes
pkill -f "fluxwan tests/lab/fluxwan_lab_config.json" || true
pkill -f "iperf3 -s" || true
pkill -f "python3 -m http.server" || true
pkill -f "tcpdump -i" || true

# Delete all created namespaces
for ns in ns-lan ns-router ns-isp1 ns-isp2 ns-isp3 ns-internet; do
    if ip netns list | grep -qw "$ns"; then
        echo "[*] Deleting namespace: $ns"
        ip netns del "$ns" || true
    fi
done

# Clean up temp files
rm -f tests/lab/*.pcap tests/lab/*.log tests/lab/fluxwan_lab_config.json || true

echo "[✓] Real Network Lab teardown complete. Environment clean."
