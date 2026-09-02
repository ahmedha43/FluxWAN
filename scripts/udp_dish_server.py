import socket, sys

def run_server(port=9999, out_file="/tmp/dish_count.txt"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', port))
    s.settimeout(8.0)
    count = 0
    while True:
        try:
            data, addr = s.recvfrom(1024)
            count += 1
            with open(out_file, 'w') as f:
                f.write(str(count))
        except socket.timeout:
            break
    s.close()

if __name__ == '__main__':
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    f = sys.argv[2] if len(sys.argv) > 2 else "/tmp/dish_count.txt"
    run_server(p, f)
