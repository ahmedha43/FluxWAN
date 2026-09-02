import socket, time, os, sys

def pump_traffic(duration_sec=30, target_mbps=25):
    # Bind to raw or UDP socket and pump data through veth_lan
    print(f"Pumping {target_mbps} Mbps traffic through LAN for {duration_sec} seconds...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Target 192.168.1.1 on LAN interface
    payload = b'X' * 1400  # 1400 bytes MTU-friendly payload
    
    start_time = time.time()
    packets_sent = 0
    bytes_sent = 0
    
    # Send packets in bursts
    burst_size = 50
    sleep_time = (burst_size * len(payload) * 8) / (target_mbps * 1_000_000)
    
    while time.time() - start_time < duration_sec:
        for _ in range(burst_size):
            try:
                sock.sendto(payload, ('192.168.1.1', 9999))
                sock.sendto(payload, ('10.10.1.50', 9999))
                sock.sendto(payload, ('10.10.2.50', 9999))
                sock.sendto(payload, ('10.10.3.50', 9999))
                bytes_sent += len(payload) * 4
                packets_sent += 4
            except Exception as e:
                pass
        time.sleep(max(0.001, sleep_time))
    
    sock.close()
    mb_sent = bytes_sent / (1024 * 1024)
    print(f"Completed: Sent {packets_sent} packets ({mb_sent:.2f} MB)")

if __name__ == '__main__':
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    pump_traffic(duration_sec=dur, target_mbps=30)
