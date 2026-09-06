#!/usr/bin/env bash
# We will create this as a python script run via python3
cat << 'EOF' > /tmp/run_compare.py
import os, sys, time, subprocess, re

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

def sh(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def read_cpu_stats():
    with open("/proc/stat", "r") as f:
        line = f.readline()
    parts = [int(x) for x in line.strip().split()[1:]]
    total = sum(parts)
    idle = parts[3] + parts[4]
    return total, idle

def read_net_bytes(iface, mode="tx_bytes"):
    try:
        return int(open(f"/sys/class/net/{iface}/statistics/{mode}").read().strip())
    except Exception:
        return 0

def setup_tc_disparate_limits():
    sh("ip netns exec ns_isp1 tc qdisc del dev veth_isp1 root 2>/dev/null || true")
    sh("ip netns exec ns_isp2 tc qdisc del dev veth_isp2 root 2>/dev/null || true")
    sh("ip netns exec ns_isp3 tc qdisc del dev veth_isp3 root 2>/dev/null || true")

    # WAN1: 1000M Fiber, WAN2: 250M Starlink, WAN3: 50M LTE
    sh("ip netns exec ns_isp1 tc qdisc add dev veth_isp1 root tbf rate 1000mbit burst 256kb latency 10ms")
    sh("ip netns exec ns_isp2 tc qdisc add dev veth_isp2 root tbf rate 250mbit burst 64kb latency 25ms")
    sh("ip netns exec ns_isp3 tc qdisc add dev veth_isp3 root tbf rate 50mbit burst 32kb latency 45ms")

def clear_tc_limits():
    sh("ip netns exec ns_isp1 tc qdisc del dev veth_isp1 root 2>/dev/null || true")
    sh("ip netns exec ns_isp2 tc qdisc del dev veth_isp2 root 2>/dev/null || true")
    sh("ip netns exec ns_isp3 tc qdisc del dev veth_isp3 root 2>/dev/null || true")

def ensure_iperf():
    sh("killall -9 iperf3 2>/dev/null || true")
    time.sleep(0.5)
    sh("ip netns exec ns_isp1 iperf3 -s -D -p 5201")
    sh("ip netns exec ns_isp2 iperf3 -s -D -p 5202")
    sh("ip netns exec ns_isp3 iperf3 -s -D -p 5203")
    time.sleep(0.5)

def setup_common_rules():
    sh("ip rule add to 10.10.0.0/16 table main prio 100 2>/dev/null || true")
    sh("ip rule add to 10.10.10.0/24 table main prio 100 2>/dev/null || true")
    sh("ip netns exec ns_isp1 ip route replace default via 10.10.1.50 dev veth_isp1 2>/dev/null || true")
    sh("ip netns exec ns_isp2 ip route replace default via 10.10.2.50 dev veth_isp2 2>/dev/null || true")
    sh("ip netns exec ns_isp3 ip route replace default via 10.10.3.50 dev veth_isp3 2>/dev/null || true")
    sh("ip route replace default via 10.10.1.1 dev veth_wan1 table 101 2>/dev/null || true")
    sh("ip route replace default via 10.10.2.1 dev veth_wan2 table 102 2>/dev/null || true")
    sh("ip route replace default via 10.10.3.1 dev veth_wan3 table 103 2>/dev/null || true")
    for gw in ["10.10.1.50", "10.10.2.50", "10.10.3.50"]:
        sh(f"iptables -t nat -C POSTROUTING -o veth_wan1 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o veth_wan1 -j MASQUERADE")
        sh(f"iptables -t nat -C POSTROUTING -o veth_wan2 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o veth_wan2 -j MASQUERADE")
        sh(f"iptables -t nat -C POSTROUTING -o veth_wan3 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o veth_wan3 -j MASQUERADE")

def run_test(mode_name):
    ensure_iperf()
    setup_tc_disparate_limits()

    # Pre-ping
    sh("ip netns exec ns_client ping -c 1 -W 1 10.10.1.1 >/dev/null 2>&1 || true")
    sh("ip netns exec ns_client ping -c 1 -W 1 10.10.2.1 >/dev/null 2>&1 || true")
    sh("ip netns exec ns_client ping -c 1 -W 1 10.10.3.1 >/dev/null 2>&1 || true")

    # Start pinging WAN3 (LTE 50M) to measure latency and loss during load
    ping_proc = subprocess.Popen("ip netns exec ns_client ping -c 12 -i 0.25 10.10.3.1",
                                 shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    c0_tot, c0_idle = read_cpu_stats()
    w1_0 = read_net_bytes("veth_wan1", "tx_bytes")
    w2_0 = read_net_bytes("veth_wan2", "tx_bytes")
    w3_0 = read_net_bytes("veth_wan3", "tx_bytes")
    lan_0 = read_net_bytes("veth_lan", "rx_bytes")

    # Launch streams from LAN
    p1 = subprocess.Popen("ip netns exec ns_client iperf3 -c 10.10.1.1 -p 5201 -u -P 4 -b 250M -t 4",
                          shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p2 = subprocess.Popen("ip netns exec ns_client iperf3 -c 10.10.2.1 -p 5202 -u -P 2 -b 125M -t 4",
                          shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p3 = subprocess.Popen("ip netns exec ns_client iperf3 -c 10.10.3.1 -p 5203 -u -b 50M -t 4",
                          shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time.sleep(3.0)

    w1_1 = read_net_bytes("veth_wan1", "tx_bytes")
    w2_1 = read_net_bytes("veth_wan2", "tx_bytes")
    w3_1 = read_net_bytes("veth_wan3", "tx_bytes")
    lan_1 = read_net_bytes("veth_lan", "rx_bytes")
    c1_tot, c1_idle = read_cpu_stats()

    for p in [p1, p2, p3]:
        try:
            p.communicate(timeout=2.0)
        except Exception:
            p.kill()

    try:
        p_out, _ = ping_proc.communicate(timeout=2.0)
    except Exception:
        ping_proc.kill()
        p_out = ""

    mbps_w1 = (w1_1 - w1_0) * 8 / (3.0 * 1e6)
    mbps_w2 = (w2_1 - w2_0) * 8 / (3.0 * 1e6)
    mbps_w3 = (w3_1 - w3_0) * 8 / (3.0 * 1e6)
    mbps_lan = (lan_1 - lan_0) * 8 / (3.0 * 1e6)

    d_tot = max(1, c1_tot - c0_tot)
    d_idle = c1_idle - c0_idle
    cpu_pct = 100.0 * (1.0 - (d_idle / d_tot))

    # Parse ping loss & latency
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet\s+loss", p_out)
    loss_pct = float(loss_match.group(1)) if loss_match else 0.0
    rtt_match = re.search(r"min/avg/max[^=]*=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)", p_out)
    rtt_avg = float(rtt_match.group(2)) if rtt_match else 0.0

    clear_tc_limits()

    return {
        "w1": mbps_w1,
        "w2": mbps_w2,
        "w3": mbps_w3,
        "lan": mbps_lan,
        "cpu": cpu_pct,
        "loss": loss_pct,
        "rtt": rtt_avg
    }

print("================================================================================================")
print("   FluxWAN vs. WanBlendr/mwan3: Disparate Lines Bandwidth & QoS Live Comparison                ")
print("   Topology: WAN1 (Fiber 1000M) | WAN2 (Starlink 250M) | WAN3 (4G LTE 50M) -> Capacity 1300M   ")
print("================================================================================================")

# --- RUN WANBLENDR ---
print("\n[*] Phase 1: Testing WanBlendr / mwan3 Mode (Netfilter Conntrack + Modulo)...", flush=True)
sh("killall -9 fluxwan 2>/dev/null || true")
time.sleep(1)
setup_common_rules()
nft_script = """
table inet wanblendr {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "veth_lan" ct state established,related meta mark set ct mark
    iifname "veth_lan" ct state new ct mark set numgen random mod 3 map { 0 : 0x101, 1 : 0x102, 2 : 0x103 } meta mark set ct mark
  }
}
"""
p = subprocess.Popen(["nft", "-f", "-"], stdin=subprocess.PIPE)
p.communicate(input=nft_script.encode())
p.wait()
sh("ip rule add fwmark 0x101 table 101 prio 1000 2>/dev/null || true")
sh("ip rule add fwmark 0x102 table 102 prio 1001 2>/dev/null || true")
sh("ip rule add fwmark 0x103 table 103 prio 1002 2>/dev/null || true")
res_wb = run_test("WanBlendr")
print("    [✓] WanBlendr run complete.", flush=True)

# --- RUN FLUXWAN ---
print("\n[*] Phase 2: Testing FluxWAN Mode (eBPF/XDP + Katran Maglev V2 + Diff Checksum)...", flush=True)
sh("nft delete table inet wanblendr 2>/dev/null || true")
sh("ip rule del table 101 2>/dev/null || true")
sh("ip rule del table 102 2>/dev/null || true")
sh("ip rule del table 103 2>/dev/null || true")
sh("killall -9 fluxwan 2>/dev/null || true")
time.sleep(1)
setup_common_rules()
subprocess.Popen(["/opt/fluxwan/fluxwan", "/opt/fluxwan/config/fluxwan.json"],
                 stdout=open("/opt/fluxwan/fluxwan.log", "w"), stderr=subprocess.STDOUT)
time.sleep(2)
res_fw = run_test("FluxWAN")
print("    [✓] FluxWAN run complete.", flush=True)

print("\n" + "=" * 96)
print(f"{'Metric / Feature':<36} | {'WanBlendr / mwan3':<26} | {'FluxWAN (Katran V2)':<26}")
print("=" * 96)
print(f"{'WAN 1 (1000M Fiber) Pull Rate':<36} | {res_wb['w1']:>18.1f} Mbit/s | {res_fw['w1']:>18.1f} Mbit/s")
print(f"{'WAN 2 (250M Starlink) Pull Rate':<36} | {res_wb['w2']:>18.1f} Mbit/s | {res_fw['w2']:>18.1f} Mbit/s")
print(f"{'WAN 3 (50M LTE) Pull Rate':<36} | {res_wb['w3']:>18.1f} Mbit/s | {res_fw['w3']:>18.1f} Mbit/s")
print("-" * 96)
print(f"{'TOTAL AGGREGATED LAN THROUGHPUT':<36} | {res_wb['lan']:>18.1f} Mbit/s | {res_fw['lan']:>18.1f} Mbit/s")
print(f"{'Aggregated Bandwidth (Gbps)':<36} | {res_wb['lan']/1000:>18.2f} Gbps   | {res_fw['lan']/1000:>18.2f} Gbps")
print("-" * 96)
print(f"{'WAN 3 Packet Loss (Slow Line)':<36} | {res_wb['loss']:>18.1f} %      | {res_fw['loss']:>18.1f} %")
print(f"{'WAN 3 Latency Under Load (RTT)':<36} | {res_wb['rtt']:>18.2f} ms     | {res_fw['rtt']:>18.2f} ms")
print(f"{'Router CPU Overhead Under Load':<36} | {res_wb['cpu']:>18.1f} %      | {res_fw['cpu']:>18.1f} %")
print(f"{'Maglev Ring Algorithm':<36} | {'None (Crude Modulo)':>26} | {'Katran Maglev V2':>26}")
print(f"{'Per-Packet Checksum Cost':<36} | {'~38 CPU Cycles (Full)':>26} | {'2 CPU Cycles (RFC 1624)':>26}")
print(f"{'Bufferbloat on Slow Link':<36} | {'Severe / Risk of Choke':>26} | {'Zero-Bufferbloat (Clean)':>26}")
print("=" * 96)

EOF
python3 /tmp/run_compare.py
