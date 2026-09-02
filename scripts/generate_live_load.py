#!/usr/bin/env python3
"""
FluxWAN Multi-WAN Traffic Generator & Load Simulator
Generates continuous balanced traffic across all 3 WANs to visualize live throughput in the Web UI.
"""
import socket
import time
import threading
import os

RUNNING = True

def flood_wan(target_ip, port, duration=60):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'X' * 1400  # Standard MTU payload
    end_time = time.time() + duration
    while RUNNING and time.time() < end_time:
        try:
            sock.sendto(payload, (target_ip, port))
            time.sleep(0.002)  # ~5.6 Mbps per thread
        except Exception:
            break
    sock.close()

def main():
    print("======================================================================")
    print("   Starting High-Speed Multi-WAN Traffic Generator across 3 WANs...  ")
    print("======================================================================")
    
    # 3 Simulated ISP Gateways
    targets = [
        ("10.10.1.1", 5001),  # WAN 1 (Fiber)
        ("10.10.2.1", 5002),  # WAN 2 (Starlink)
        ("10.10.3.1", 5003),  # WAN 3 (LTE)
    ]
    
    threads = []
    # Launch parallel worker threads per WAN according to configured weights (100 : 50 : 75)
    thread_counts = [4, 2, 3]  # 4 threads for WAN1, 2 for WAN2, 3 for WAN3
    
    for idx, (ip, port) in enumerate(targets):
        count = thread_counts[idx]
        print(f" [+] Launching {count} active flow workers towards {ip} (WAN {idx+1})...")
        for t_idx in range(count):
            t = threading.Thread(target=flood_wan, args=(ip, port + t_idx, 120))
            t.daemon = True
            t.start()
            threads.append(t)
            
    print("\n [✓] Traffic Generator is actively streaming data across all 3 WANs!")
    print(" [✓] Refresh or watch http://localhost:8080 to see live bandwidth graphs!\n")
    
    for t in threads:
        t.join()

if __name__ == '__main__':
    main()
