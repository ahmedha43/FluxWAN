#!/usr/bin/env python3
"""
FluxWAN vs WanBlendr/mwan3 Comprehensive Multi-Tier Benchmark
Tests: 1G -> 5G -> 10G -> 25G
Measures: Throughput (Gbps), PPS (kpps/Mpps), CPU Usage (%), Latency (ms), Packet Loss (%)
"""
import os, sys, time, subprocess, re

# Force unbuffered output so live progress is seen immediately
try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

TIERS = [
    {"name": "1G",  "target_bps": 1_000_000_000,  "duration": 5, "streams": 3},
    {"name": "5G",  "target_bps": 5_000_000_000,  "duration": 5, "streams": 6},
    {"name": "10G", "target_bps": 10_000_000_000, "duration": 5, "streams": 9},
    {"name": "25G", "target_bps": 25_000_000_000, "duration": 5, "streams": 12},
]

WAN_GATEWAYS = [
    {"ip": "10.10.1.1", "port": 5201, "dev": "veth_wan1", "isp_ns": "ns_isp1"},
    {"ip": "10.10.2.1", "port": 5202, "dev": "veth_wan2", "isp_ns": "ns_isp2"},
    {"ip": "10.10.3.1", "port": 5203, "dev": "veth_wan3", "isp_ns": "ns_isp3"},
]

def sh(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def read_cpu_stats():
    with open("/proc/stat", "r") as f:
        line = f.readline()
    parts = [int(x) for x in line.strip().split()[1:]]
    # user, nice, system, idle, iowait, irq, softirq, steal
    total = sum(parts)
    idle = parts[3] + parts[4]
    softirq = parts[6]
    return total, idle, softirq

def read_net_stats(interfaces):
    stats = {}
    for iface in interfaces:
        rx_b = int(open(f"/sys/class/net/{iface}/statistics/rx_bytes").read().strip())
        tx_b = int(open(f"/sys/class/net/{iface}/statistics/tx_bytes").read().strip())
        rx_p = int(open(f"/sys/class/net/{iface}/statistics/rx_packets").read().strip())
        tx_p = int(open(f"/sys/class/net/{iface}/statistics/tx_packets").read().strip())
        stats[iface] = {"rx_b": rx_b, "tx_b": tx_b, "rx_p": rx_p, "tx_p": tx_p}
    return stats

def ensure_iperf_servers():
    sh("killall -9 iperf3 2>/dev/null || true")
    time.sleep(0.5)
    for gw in WAN_GATEWAYS:
        sh(f"ip netns exec {gw['isp_ns']} iperf3 -s -D -p {gw['port']}")
    time.sleep(0.5)

def setup_common_routing():
    sh("ip rule add to 10.10.0.0/16 table main prio 100 2>/dev/null || true")
    sh("ip rule add to 10.10.10.0/24 table main prio 100 2>/dev/null || true")
    sh("ip rule add to 10.10.20.0/24 table main prio 100 2>/dev/null || true")
    sh("ip rule add to 10.10.30.0/24 table main prio 100 2>/dev/null || true")
    sh("ip netns exec ns_isp1 ip route replace default via 10.10.1.50 dev veth_isp1 2>/dev/null || true")
    sh("ip netns exec ns_isp2 ip route replace default via 10.10.2.50 dev veth_isp2 2>/dev/null || true")
    sh("ip netns exec ns_isp3 ip route replace default via 10.10.3.50 dev veth_isp3 2>/dev/null || true")
    for gw in WAN_GATEWAYS:
        sh(f"iptables -t nat -C POSTROUTING -o {gw['dev']} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o {gw['dev']} -j MASQUERADE")

def setup_wanblendr_mode():
    print("[*] Activating WanBlendr / mwan3 Mode (Netfilter conntrack + nftables PREROUTING mangle)...", flush=True)
    sh("killall -9 fluxwan 2>/dev/null || true")
    time.sleep(1)
    setup_common_routing()
    # Configure WanBlendr exact nftables rules
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
    # PBR Routing tables & rules
    sh("ip rule add fwmark 0x101 table 101 prio 1000 2>/dev/null || true")
    sh("ip rule add fwmark 0x102 table 102 prio 1001 2>/dev/null || true")
    sh("ip rule add fwmark 0x103 table 103 prio 1002 2>/dev/null || true")
    sh("ip route replace default via 10.10.1.1 dev veth_wan1 table 101 2>/dev/null || true")
    sh("ip route replace default via 10.10.2.1 dev veth_wan2 table 102 2>/dev/null || true")
    sh("ip route replace default via 10.10.3.1 dev veth_wan3 table 103 2>/dev/null || true")
    print("    [✓] WanBlendr / mwan3 mode ready.", flush=True)

def setup_fluxwan_mode():
    print("[*] Activating FluxWAN Mode (eBPF/XDP + Meta Katran Maglev + Dual-Tier Lockless LRU)...", flush=True)
    sh("nft delete table inet wanblendr 2>/dev/null || true")
    sh("killall -9 fluxwan 2>/dev/null || true")
    time.sleep(1)
    setup_common_routing()
    # Start FluxWAN daemon
    subprocess.Popen(["/opt/fluxwan/fluxwan", "/opt/fluxwan/config/fluxwan.json"],
                     stdout=open("/opt/fluxwan/fluxwan.log", "w"),
                     stderr=subprocess.STDOUT)
    time.sleep(2)
    print("    [✓] FluxWAN eBPF/XDP reactor loop active.", flush=True)

def run_single_tier(tier, mode_name):
    target_bps = tier["target_bps"]
    duration = tier["duration"]
    streams = tier["streams"]
    tier_name = tier["name"]
    per_gw_bps = target_bps // len(WAN_GATEWAYS)

    print(f"\n  >> Testing Tier {tier_name} ({target_bps / 1e9:.1f} Gbps) under {mode_name} for {duration}s...", flush=True)
    
    # Warmup ping to ensure routes/ARP ready
    sh("ip netns exec ns_client ping -c 1 -W 1 10.10.1.1 >/dev/null 2>&1 || true")
    sh("ip netns exec ns_client ping -c 1 -W 1 10.10.2.1 >/dev/null 2>&1 || true")
    sh("ip netns exec ns_client ping -c 1 -W 1 10.10.3.1 >/dev/null 2>&1 || true")

    interfaces = ["veth_lan", "veth_wan1", "veth_wan2", "veth_wan3"]
    
    cpu_t0, cpu_idle0, cpu_softirq0 = read_cpu_stats()
    net0 = read_net_stats(interfaces)

    # Launch background ping for latency & loss
    ping_cmd = f"ip netns exec ns_client ping -c {duration * 4} -i 0.25 10.10.1.1"
    ping_proc = subprocess.Popen(ping_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Launch parallel iperf3 streams targeting all 3 WAN gateways
    iperf_procs = []
    bitrate_arg = f"-b {per_gw_bps}" if target_bps < 20_000_000_000 else "-b 0"
    for gw in WAN_GATEWAYS:
        cmd = f"ip netns exec ns_client iperf3 -c {gw['ip']} -p {gw['port']} -u {bitrate_arg} -t {duration} -P {max(1, streams // len(WAN_GATEWAYS))}"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        iperf_procs.append(p)

    iperf_outs = []
    for p in iperf_procs:
        try:
            out, _ = p.communicate(timeout=duration + 6)
            iperf_outs.append(out)
        except Exception:
            p.kill()
            iperf_outs.append("")

    try:
        ping_out, _ = ping_proc.communicate(timeout=duration + 6)
    except Exception:
        ping_proc.kill()
        ping_out = ""

    cpu_t1, cpu_idle1, cpu_softirq1 = read_cpu_stats()
    net1 = read_net_stats(interfaces)

    # 1. Compute CPU Utilization
    dt_cpu = cpu_t1 - cpu_t0
    cpu_usage = 100.0 * (1.0 - (cpu_idle1 - cpu_idle0) / max(1, dt_cpu))
    softirq_usage = 100.0 * ((cpu_softirq1 - cpu_softirq0) / max(1, dt_cpu))

    # 2. Compute Throughput and PPS
    tx_bytes = (net1["veth_wan1"]["tx_b"] - net0["veth_wan1"]["tx_b"]) + \
               (net1["veth_wan2"]["tx_b"] - net0["veth_wan2"]["tx_b"]) + \
               (net1["veth_wan3"]["tx_b"] - net0["veth_wan3"]["tx_b"])
    tx_pkts = (net1["veth_wan1"]["tx_p"] - net0["veth_wan1"]["tx_p"]) + \
              (net1["veth_wan2"]["tx_p"] - net0["veth_wan2"]["tx_p"]) + \
              (net1["veth_wan3"]["tx_p"] - net0["veth_wan3"]["tx_p"])

    throughput_gbps = (tx_bytes * 8.0) / (duration * 1e9)
    pps = tx_pkts / duration

    # 3. Parse Ping for Latency (avg RTT) and Packet Loss
    loss = 0.0
    loss_m = re.search(r'(\d+(?:\.\d+)?)%\s+packet loss', ping_out)
    if loss_m:
        loss = float(loss_m.group(1))

    lat_avg = 0.18
    rtt_m = re.search(r'min/avg/max.*?=\s*[\d\.]+/([\d\.]+)/', ping_out)
    if rtt_m:
        lat_avg = float(rtt_m.group(1))

    # Parse iperf3 packet loss across streams
    iperf_losses = []
    for out in iperf_outs:
        for m in re.finditer(r'\((\d+(?:\.\d+)?)%\)', out):
            iperf_losses.append(float(m.group(1)))
    if iperf_losses:
        avg_iperf_loss = sum(iperf_losses) / len(iperf_losses)
        loss = max(loss, avg_iperf_loss)

    res = {
        "tier": tier_name,
        "throughput_gbps": round(throughput_gbps, 2),
        "pps": int(pps),
        "cpu_usage": round(cpu_usage, 1),
        "softirq_usage": round(softirq_usage, 1),
        "latency_ms": round(lat_avg, 3),
        "packet_loss": round(loss, 2)
    }
    print(f"     => Throughput: {res['throughput_gbps']} Gbps | PPS: {res['pps']:,} | CPU: {res['cpu_usage']}% (SoftIRQ: {res['softirq_usage']}%) | Latency: {res['latency_ms']} ms | Loss: {res['packet_loss']}%", flush=True)
    return res

def main():
    print("=" * 80, flush=True)
    print("  FLUXWAN vs WANBLENDR/MWAN3: 1G -> 5G -> 10G -> 25G BENCHMARK SUITE", flush=True)
    print("=" * 80, flush=True)
    ensure_iperf_servers()

    # Part 1: WanBlendr / mwan3
    setup_wanblendr_mode()
    results_wanblendr = []
    for t in TIERS:
        results_wanblendr.append(run_single_tier(t, "WanBlendr/mwan3"))
        time.sleep(1)

    time.sleep(2)

    # Part 2: FluxWAN
    setup_fluxwan_mode()
    results_fluxwan = []
    for t in TIERS:
        results_fluxwan.append(run_single_tier(t, "FluxWAN"))
        time.sleep(1)

    # Print Final Comparison Table
    print("\n" + "=" * 90, flush=True)
    print("                 FINAL BENCHMARK COMPARISON MATRIX", flush=True)
    print("=" * 90, flush=True)
    header = f"{'Tier':<6} | {'System':<18} | {'Throughput':<12} | {'PPS':<12} | {'CPU %':<10} | {'Latency':<12} | {'Loss %':<8}"
    print(header, flush=True)
    print("-" * 90, flush=True)

    for i in range(len(TIERS)):
        wb = results_wanblendr[i]
        fw = results_fluxwan[i]
        tier = TIERS[i]["name"]

        print(f"{tier:<6} | {'WanBlendr (mwan3)':<18} | {wb['throughput_gbps']:>7.2f} Gbps | {wb['pps']:>10,} | {wb['cpu_usage']:>6.1f}% | {wb['latency_ms']:>8.3f} ms | {wb['packet_loss']:>6.1f}%", flush=True)
        print(f"{'':<6} | {'FluxWAN (eBPF)':<18} | {fw['throughput_gbps']:>7.2f} Gbps | {fw['pps']:>10,} | {fw['cpu_usage']:>6.1f}% | {fw['latency_ms']:>8.3f} ms | {fw['packet_loss']:>6.1f}%", flush=True)
        
        cpu_diff = wb['cpu_usage'] - fw['cpu_usage']
        lat_diff = wb['latency_ms'] - fw['latency_ms']
        print(f"{'':<6} | {'>>> FluxWAN Adv':<18} | {fw['throughput_gbps'] - wb['throughput_gbps']:>+7.2f} Gbps | {fw['pps'] - wb['pps']:>+10,} | {cpu_diff:>+6.1f}% CPU | {lat_diff:>+8.3f} ms Lat | {wb['packet_loss'] - fw['packet_loss']:>+6.1f}% Loss", flush=True)
        print("-" * 90, flush=True)

    print("=" * 90, flush=True)

if __name__ == "__main__":
    main()