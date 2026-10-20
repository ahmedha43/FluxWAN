import subprocess
import time

def get_net_dev():
    cmd = ["sshpass", "-p", "admin", "ssh", "-o", "StrictHostKeyChecking=no", "-n", "root@100.90.189.66", "cat /proc/net/dev"]
    res = subprocess.check_output(cmd).decode()
    stats = {}
    for line in res.splitlines()[2:]:
        parts = line.split()
        if len(parts) >= 10:
            iface = parts[0].rstrip(":")
            stats[iface] = (int(parts[1]), int(parts[9])) # (rx_bytes, tx_bytes)
    return stats

t1_stats = get_net_dev()
t1 = time.time()
time.sleep(3.0)
t2_stats = get_net_dev()
t2 = time.time()

dt = t2 - t1
print(f"=== FLUXWAN LIVE TRAFFIC REPORT (Interval: {dt:.2f}s) ===")
print(f"{'Interface':<12} | {'Download (RX)':<18} | {'Upload (TX)':<18}")
print("-" * 55)

for iface in ["eth0", "tun_wan1", "tun_wan2", "tun_wan3", "eth1", "eth2", "eth3"]:
    if iface in t1_stats and iface in t2_stats:
        rx_mbps = (t2_stats[iface][0] - t1_stats[iface][0]) * 8 / (dt * 1_000_000)
        tx_mbps = (t2_stats[iface][1] - t1_stats[iface][1]) * 8 / (dt * 1_000_000)
        print(f"{iface:<12} | {rx_mbps:>10.2f} Mbps    | {tx_mbps:>10.2f} Mbps")

print("=" * 55)
