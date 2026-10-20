import urllib.request
import json

req = urllib.request.Request('http://100.90.189.66:8080/api/v1/status', headers={'X-Auth-Token': 'flux_token_abc123'})
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    print("=== FLUXWAN LIVE WAN HEALTH & WEIGHTS ===")
    for w in data.get('wans', []):
        wid = w.get('id')
        lbl = w.get('label')
        st = w.get('state')
        rtt = w.get('rtt_ms')
        loss = w.get('packet_loss')
        d_wt = w.get('dynamic_weight')
        c_wt = w.get('config_weight')
        p_lat = w.get('proxy_latency_ms')
        p_conn = w.get('proxy_connected')
        print(f"WAN {wid} ({lbl}): State={st}, RTT={rtt}ms, Loss={loss}%, DynamicWeight={d_wt}/{c_wt}, ProxyConn={p_conn}, ProxyPing={p_lat}ms")
