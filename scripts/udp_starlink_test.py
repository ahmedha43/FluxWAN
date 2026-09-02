import socket, time, sys

def test_load_balance(total=60):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('10.0.0.100', 0))
    for i in range(total):
        s.sendto(b'STARLINK-TEST-PKT', ('192.168.1.1', 9999))
        time.sleep(0.002)
    s.close()
    print(f"Sent {total} UDP test packets.")

if __name__ == '__main__':
    t = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    test_load_balance(t)
