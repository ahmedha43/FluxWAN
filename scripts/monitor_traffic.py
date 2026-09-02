import urllib.request, json, time

# Login
req = urllib.request.Request('http://127.0.0.1:8080/api/v1/login', data=json.dumps({'username':'admin','password':'admin'}).encode(), headers={'Content-Type':'application/json'})
res = urllib.request.urlopen(req)
token = json.loads(res.read().decode())['token']

def get_stats():
    req = urllib.request.Request('http://127.0.0.1:8080/api/v1/interfaces', headers={'X-Auth-Token': token})
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode())
    return {i['name']: i for i in data['interfaces']}

prev = get_stats()
print("=" * 72)
print(f"{'Time':<10} | {'Interface':<12} | {'Rx (Mbps)':<11} | {'Tx (Mbps)':<11} | {'Total Data':<12}")
print("=" * 72)

for iteration in range(5):
    time.sleep(2.0)
    curr = get_stats()
    now_str = time.strftime('%H:%M:%S')
    for ifname in ['veth_lan', 'veth_wan1', 'veth_wan2', 'veth_wan3', 'eth0']:
        if ifname in curr and ifname in prev:
            p = prev[ifname]
            c = curr[ifname]
            dt = 2.0
            rx_diff = max(0, c['rx_bytes'] - p['rx_bytes'])
            tx_diff = max(0, c['tx_bytes'] - p['tx_bytes'])
            rx_mbps = (rx_diff * 8) / (dt * 1000000)
            tx_mbps = (tx_diff * 8) / (dt * 1000000)
            total_mb = (c['rx_bytes'] + c['tx_bytes']) / (1024 * 1024)
            print(f"{now_str:<10} | {ifname:<12} | {rx_mbps:>9.2f} M | {tx_mbps:>9.2f} M | {total_mb:>9.2f} MB")
    print("-" * 72)
    prev = curr
