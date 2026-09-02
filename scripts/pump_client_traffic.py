import socket, time, sys

def pump(duration=900):
    print(f"Pumping 100% Routed External Internet Traffic across 4 WANs (WAN1, WAN2, WAN3, WAN4) for {duration} seconds...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'FluxWAN-4-WAN-Routed-Traffic-' * 46  # ~1334 bytes
    
    start = time.time()
    count = 0
    # 4 Dedicated WAN Destinations
    targets = [
        ('10.10.1.1', 80),    # WAN 1
        ('10.10.2.1', 80),    # WAN 2
        ('10.10.3.1', 80),    # WAN 3
        ('172.17.0.1', 80)    # WAN 4 (eth0)
    ]
    
    while time.time() - start < duration:
        for _ in range(25):
            for t in targets:
                try:
                    s.sendto(payload, t)
                    count += 1
                except:
                    pass
        time.sleep(0.005)
    s.close()
    print(f"Done. Sent {count} packets.")

if __name__ == '__main__':
    d = int(sys.argv[1]) if len(sys.argv) > 1 else 900
    pump(d)
