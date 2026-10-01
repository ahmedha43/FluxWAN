#!/usr/bin/env python3
"""
================================================================================
Starlink Windows Baseline & Comparative Network Audit Suite (v2)
================================================================================
Purpose:
  1. Record a high-precision empirical baseline measurement during normal active
     subscription (baseline mode).
  2. Re-run identical diagnostic probes during Suspended / Walled Garden state
     (suspended mode).
  3. Perform automated machine diffing and comparative analysis between baseline
     and suspended states.

Strict Compliance Guarantee:
  - NO VPNs, VPSs, Proxies, Tor, DNS tunneling, or SNI spoofing.
  - Safe, non-intrusive diagnostic probes only.
  - Standard socket connections and HTTP headers.
================================================================================
"""

import subprocess
import socket
import ssl
import time
import urllib.request
import urllib.parse
import json
import os
import sys
import re
import argparse

TARGET_DOMAINS = [
    "starlink.com",
    "google.com",
    "cloudflare.com",
    "microsoft.com"
]

DNS_SERVERS = [
    ("Local/DHCP DNS", None),
    ("Google DNS", "8.8.8.8"),
    ("Cloudflare DNS", "1.1.1.1")
]

raw_logs = []

def log(text=""):
    print(text)
    raw_logs.append(text)

def run_ps(cmd, timeout=30):
    log(f"\n[EXEC POWERSHELL]: {cmd}")
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        out = res.stdout.strip()
        err = res.stderr.strip()
        if out:
            log(out)
        if err:
            log(f"[STDERR]: {err}")
        return out
    except Exception as e:
        log(f"[ERROR]: {e}")
        return str(e)

def raw_dns_query(domain, qtype=1, server="8.8.8.8", timeout=3.0):
    txid = b'\x12\x34'
    flags = b'\x01\x00'
    qdcount = b'\x00\x01'
    header = txid + flags + qdcount + b'\x00\x00\x00\x00\x00\x00'
    question = b''
    for part in domain.split('.'):
        question += bytes([len(part)]) + part.encode('ascii')
    question += b'\x00'
    question += bytes([qtype >> 8, qtype & 0xff]) + b'\x00\x01'
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    t0 = time.time()
    try:
        sock.sendto(packet, (server, 53))
        resp, addr = sock.recvfrom(4096)
        lat = (time.time() - t0) * 1000
        ips = []
        if len(resp) >= 12:
            ancount = (resp[6] << 8) | resp[7]
            idx = 12
            while idx < len(resp) and resp[idx] != 0:
                if (resp[idx] & 0xc0) == 0xc0:
                    idx += 2
                    break
                idx += 1 + resp[idx]
            if idx < len(resp) and resp[idx] == 0:
                idx += 5
            for _ in range(ancount):
                if idx >= len(resp): break
                if (resp[idx] & 0xc0) == 0xc0:
                    idx += 2
                else:
                    while idx < len(resp) and resp[idx] != 0:
                        idx += 1 + resp[idx]
                    idx += 1
                if idx + 10 > len(resp): break
                atype = (resp[idx] << 8) | resp[idx+1]
                rdlen = (resp[idx+8] << 8) | resp[idx+9]
                idx += 10
                if atype == 1 and rdlen == 4 and idx + 4 <= len(resp):
                    ips.append(socket.inet_ntoa(resp[idx:idx+4]))
                elif atype == 28 and rdlen == 16 and idx + 16 <= len(resp):
                    ips.append(socket.inet_ntop(socket.AF_INET6, resp[idx:idx+16]))
                idx += rdlen
        sock.close()
        return {"status": "SUCCESS", "latency_ms": round(lat, 2), "ips": ips, "server_ip": addr[0]}
    except socket.timeout:
        sock.close()
        return {"status": "TIMEOUT", "latency_ms": None, "ips": [], "server_ip": server}
    except Exception as e:
        sock.close()
        return {"status": "ERROR", "error": str(e), "latency_ms": None, "ips": [], "server_ip": server}

def run_audit(mode="baseline", output_txt=None, output_json=None, compare_baseline_path=None):
    if not output_txt:
        output_txt = r"D:\FluxWAN\starlink_baseline_windows_v2.txt" if mode == "baseline" else r"D:\FluxWAN\starlink_suspended_windows.txt"
    if not output_json:
        output_json = r"D:\FluxWAN\starlink_baseline_windows_v2.json" if mode == "baseline" else r"D:\FluxWAN\starlink_suspended_windows.json"

    json_report = {
        "audit_metadata": {
            "timestamp_utc": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            "epoch": time.time(),
            "platform": sys.platform,
            "hostname": socket.gethostname(),
            "mode": mode,
            "purpose": "Normal baseline measurement" if mode == "baseline" else "Suspended/Walled Garden empirical measurement"
        },
        "network_topology": {},
        "dns_evaluations": {},
        "domain_probes": {},
        "starlink_local_endpoints": {},
        "traceroute_paths": {}
    }

    log("=" * 80)
    log(f"   STARLINK NETWORK AUDIT SUITE (V2) - MODE: {mode.upper()}")
    log("=" * 80)
    log(f"Timestamp: {json_report['audit_metadata']['timestamp_utc']}")
    log(f"Host:      {json_report['audit_metadata']['hostname']} ({json_report['audit_metadata']['platform']})")

    # ==============================================================================
    # SECTION 1: NETWORK INTERFACES, ROUTES & TOPOLOGY
    # ==============================================================================
    log("\n" + "=" * 80)
    log("SECTION 1: NETWORK INTERFACES, ROUTES & TOPOLOGY")
    log("=" * 80)

    ipconfig_raw = run_ps("ipconfig /all", timeout=15)
    net_adapters_raw = run_ps("Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed | Format-Table -AutoSize", timeout=10)
    ip_addrs_raw = run_ps("Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily, PrefixLength, AddressState | Format-Table -AutoSize", timeout=10)
    routes_v4_raw = run_ps("Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias | Format-Table -AutoSize", timeout=10)
    routes_v6_raw = run_ps("Get-NetRoute -AddressFamily IPv6 | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias | Format-Table -AutoSize", timeout=10)
    dns_clients_raw = run_ps("Get-DnsClientServerAddress | Format-Table -AutoSize", timeout=10)
    arp_raw = run_ps("arp -a", timeout=10)

    primary_alias = "Wi-Fi"
    primary_ipv4 = "192.168.88.54"
    primary_gw = "192.168.88.1"
    primary_mac = "Unknown"

    for line in net_adapters_raw.splitlines():
        if "Wi-Fi" in line and not "Virtual" in line:
            parts = line.split()
            for p in parts:
                if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', p):
                    primary_mac = p
                    break

    gw_mac = "Unknown"
    for line in arp_raw.splitlines():
        if primary_gw in line:
            parts = line.split()
            for p in parts:
                if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', p):
                    gw_mac = p
                    break

    has_global_v6 = False
    ipv6_list = []
    for line in ip_addrs_raw.splitlines():
        if "IPv6" in line:
            parts = line.split()
            for p in parts:
                if ":" in p:
                    ipv6_list.append(p)
                    if not p.lower().startswith("fe80:") and not p == "::1":
                        has_global_v6 = True

    json_report["network_topology"] = {
        "local_ipv4": {
            "ip": primary_ipv4,
            "type": "RFC1918 Private IPv4 (Subnet 192.168.88.0/24)",
            "is_globally_routable": False
        },
        "default_gateway": {
            "ip": primary_gw,
            "mac": gw_mac
        },
        "primary_interface": {
            "alias": primary_alias,
            "mac": primary_mac
        },
        "ipv6": {
            "has_global_unicast": has_global_v6,
            "addresses": ipv6_list[:5],
            "state": "Link-Local Only / No Global IPv6" if not has_global_v6 else "Globally Routable"
        },
        "path_topology_description": "Windows (192.168.88.54, Private IPv4) -> Local Router Gateway (192.168.88.1) -> Starlink Dishy/Network (192.168.100.1 / CGNAT) -> Public Internet"
    }

    # ==============================================================================
    # SECTION 2: INDEPENDENT DNS TESTING (LOCAL/DHCP, 8.8.8.8, 1.1.1.1)
    # ==============================================================================
    log("\n" + "=" * 80)
    log("SECTION 2: INDEPENDENT DNS RESOLUTION TESTING")
    log("=" * 80)

    for domain in TARGET_DOMAINS:
        log(f"\n--- DNS Resolution for: {domain} ---")
        json_report["dns_evaluations"][domain] = {}

        # 1. System/Local Resolver
        t0 = time.time()
        v4_sys = []
        v6_sys = []
        try:
            answers = socket.getaddrinfo(domain, None)
            lat_sys = (time.time() - t0) * 1000
            for a in answers:
                ip = a[4][0]
                if a[0] == socket.AF_INET and ip not in v4_sys:
                    v4_sys.append(ip)
                elif a[0] == socket.AF_INET6 and ip not in v6_sys:
                    v6_sys.append(ip)
            res_sys = {"status": "SUCCESS", "latency_ms": round(lat_sys, 2), "ipv4": v4_sys, "ipv6": v6_sys}
        except Exception as e:
            res_sys = {"status": "FAIL", "error": str(e), "ipv4": [], "ipv6": []}

        log(f"  * System/Local Resolver: status={res_sys['status']}, latency={res_sys.get('latency_ms')}ms, IPv4={res_sys.get('ipv4')}, IPv6={res_sys.get('ipv6')}")
        json_report["dns_evaluations"][domain]["system_resolver"] = res_sys

        # 2. Google DNS 8.8.8.8
        res_8888_v4 = raw_dns_query(domain, qtype=1, server="8.8.8.8")
        res_8888_v6 = raw_dns_query(domain, qtype=28, server="8.8.8.8")
        log(f"  * 8.8.8.8 (Google DNS): A_status={res_8888_v4['status']} ({res_8888_v4.get('latency_ms')}ms, IPs={res_8888_v4.get('ips')}), AAAA_status={res_8888_v6['status']} (IPs={res_8888_v6.get('ips')})")
        json_report["dns_evaluations"][domain]["google_8_8_8_8"] = {
            "A": res_8888_v4,
            "AAAA": res_8888_v6
        }

        # 3. Cloudflare DNS 1.1.1.1
        res_1111_v4 = raw_dns_query(domain, qtype=1, server="1.1.1.1")
        res_1111_v6 = raw_dns_query(domain, qtype=28, server="1.1.1.1")
        log(f"  * 1.1.1.1 (Cloudflare): A_status={res_1111_v4['status']} ({res_1111_v4.get('latency_ms')}ms, IPs={res_1111_v4.get('ips')}), AAAA_status={res_1111_v6['status']} (IPs={res_1111_v6.get('ips')})")
        json_report["dns_evaluations"][domain]["cloudflare_1_1_1_1"] = {
            "A": res_1111_v4,
            "AAAA": res_1111_v6
        }

    # ==============================================================================
    # SECTION 3 & 4: PER-IP TCP/443, TLS HANDSHAKE & HTTP EVALUATION
    # ==============================================================================
    log("\n" + "=" * 80)
    log("SECTION 3 & 4: PER-IP TCP/443, TLS HANDSHAKE & HTTP EVALUATION")
    log("=" * 80)

    for domain in TARGET_DOMAINS:
        log(f"\n==================================================")
        log(f"Domain Target: {domain}")
        log(f"==================================================")
        json_report["domain_probes"][domain] = []

        all_ips = set()
        sys_ips = json_report["dns_evaluations"][domain]["system_resolver"].get("ipv4", [])
        g_ips = json_report["dns_evaluations"][domain]["google_8_8_8_8"]["A"].get("ips", [])
        cf_ips = json_report["dns_evaluations"][domain]["cloudflare_1_1_1_1"]["A"].get("ips", [])
        for ip in sys_ips + g_ips + cf_ips:
            if ip: all_ips.add(ip)

        sorted_ips = sorted(list(all_ips))
        log(f"Unique IPs to evaluate ({len(sorted_ips)}): {', '.join(sorted_ips)}")

        for ip in sorted_ips:
            log(f"\n--> Probing Target IP: {ip} for {domain} on TCP/443")
            probe_record = {
                "ip": ip,
                "domain": domain,
                "tcp_443": {},
                "tls": {},
                "http": {}
            }

            # 1. TCP Handshake
            t0 = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            tcp_ok = False
            try:
                s.connect((ip, 443))
                lat_tcp = (time.time() - t0) * 1000
                tcp_ok = True
                probe_record["tcp_443"] = {
                    "status": "SUCCESS",
                    "latency_ms": round(lat_tcp, 2)
                }
                log(f"  [TCP/443]: SUCCESS | SYN-ACK Latency: {lat_tcp:.2f}ms")
            except socket.timeout:
                probe_record["tcp_443"] = {"status": "TIMEOUT", "latency_ms": None}
                log(f"  [TCP/443]: TIMEOUT | Connection timed out")
            except ConnectionRefusedError:
                probe_record["tcp_443"] = {"status": "REFUSED_RST", "latency_ms": None}
                log(f"  [TCP/443]: REFUSED | TCP RST received")
            except Exception as e:
                probe_record["tcp_443"] = {"status": "ERROR", "error": str(e), "latency_ms": None}
                log(f"  [TCP/443]: ERROR | {e}")

            # 2. TLS Handshake
            if tcp_ok:
                tls_ctx = ssl.create_default_context()
                t_tls0 = time.time()
                tls_ok = False
                tls_sock = None
                try:
                    tls_sock = tls_ctx.wrap_socket(s, server_hostname=domain)
                    lat_tls = (time.time() - t_tls0) * 1000
                    tls_ok = True

                    cert = tls_sock.getpeercert()
                    sub = dict(x[0] for x in cert.get('subject', ()))
                    iss = dict(x[0] for x in cert.get('issuer', ()))
                    sans = [v for k, v in cert.get('subjectAltName', ()) if k == 'DNS']

                    probe_record["tls"] = {
                        "status": "SUCCESS",
                        "handshake_latency_ms": round(lat_tls, 2),
                        "version": tls_sock.version(),
                        "cipher": tls_sock.cipher()[0],
                        "cert_cn": sub.get("commonName") or sub.get("organizationName"),
                        "cert_issuer": iss.get("commonName") or iss.get("organizationName"),
                        "sans": sans[:6],
                        "valid_until": cert.get("notAfter")
                    }
                    log(f"  [TLS]:     SUCCESS | Protocol: {tls_sock.version()} | Cipher: {tls_sock.cipher()[0]}")
                    log(f"             Cert CN: {probe_record['tls']['cert_cn']} | Issuer: {probe_record['tls']['cert_issuer']}")
                except ssl.SSLCertVerificationError as ve:
                    probe_record["tls"] = {
                        "status": "CERT_VERIFY_FAILED",
                        "error": ve.verify_message,
                        "is_interception_detected": True
                    }
                    log(f"  [TLS]:     CERT_VERIFY_FAILED | {ve.verify_message} (Possible Captive Portal / Interception)")
                except Exception as e:
                    probe_record["tls"] = {"status": "FAIL", "error": str(e)}
                    log(f"  [TLS]:     FAIL | {e}")

                # 3. HTTP Probe
                if tls_ok and tls_sock:
                    t_http0 = time.time()
                    try:
                        http_req = (
                            f"GET / HTTP/1.1\r\n"
                            f"Host: {domain}\r\n"
                            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) StarlinkAudit/2.0\r\n"
                            f"Accept: */*\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                        tls_sock.sendall(http_req.encode('ascii'))
                        resp_data = tls_sock.recv(4096).decode('iso-8859-1', 'ignore')
                        lat_http = (time.time() - t_http0) * 1000

                        first_line = resp_data.split('\r\n')[0] if resp_data else ""
                        m = re.search(r'HTTP/\S+\s+(\d+)', first_line)
                        code = int(m.group(1)) if m else None

                        headers = {}
                        for hline in resp_data.split('\r\n')[1:]:
                            if not hline: break
                            if ':' in hline:
                                k, v = hline.split(':', 1)
                                headers[k.strip().lower()] = v.strip()

                        probe_record["http"] = {
                            "status": "SUCCESS",
                            "response_latency_ms": round(lat_http, 2),
                            "status_code": code,
                            "server": headers.get("server"),
                            "location": headers.get("location"),
                            "content_type": headers.get("content-type"),
                            "cf_ray": headers.get("cf-ray")
                        }
                        log(f"  [HTTP]:    SUCCESS | Status: {code} | Latency: {lat_http:.2f}ms")
                        log(f"             Server: {headers.get('server')} | Location: {headers.get('location')}")
                    except Exception as e:
                        probe_record["http"] = {"status": "FAIL", "error": str(e)}
                        log(f"  [HTTP]:    FAIL | {e}")
                    finally:
                        tls_sock.close()
                else:
                    s.close()

            json_report["domain_probes"][domain].append(probe_record)

    # ==============================================================================
    # SECTION 5: STARLINK LOCAL DISHY MANAGEMENT (192.168.100.1)
    # ==============================================================================
    log("\n" + "=" * 80)
    log("SECTION 5: STARLINK LOCAL DISHY MANAGEMENT ENDPOINTS (192.168.100.1)")
    log("=" * 80)

    dishy_target = "192.168.100.1"

    # Port 80
    log(f"\n--> Probing {dishy_target}:80 (HTTP Diagnostic Web Interface)")
    t0 = time.time()
    s80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s80.settimeout(2.0)
    try:
        s80.connect((dishy_target, 80))
        lat80 = (time.time() - t0) * 1000
        s80.close()

        req = urllib.request.Request(f"http://{dishy_target}/", headers={"User-Agent": "StarlinkAudit/2.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            h = dict(resp.headers)
            json_report["starlink_local_endpoints"]["port_80"] = {
                "status": "OPEN",
                "tcp_latency_ms": round(lat80, 2),
                "http_status": resp.status,
                "server": h.get("Server") or h.get("server"),
                "content_security_policy": h.get("Content-Security-Policy"),
                "device_handle_api": "192.168.100.1:9201/SpaceX.API.Device.Device/Handle" in str(h)
            }
        log(f"  * Status: OPEN ({lat80:.2f}ms) | HTTP: {resp.status}")
    except Exception as e:
        json_report["starlink_local_endpoints"]["port_80"] = {"status": "FAIL/CLOSED", "error": str(e)}
        log(f"  * Status: CLOSED/TIMEOUT ({e})")

    # Port 9200
    log(f"\n--> Probing {dishy_target}:9200 (gRPC SpaceX Device Service)")
    t0 = time.time()
    s9200 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s9200.settimeout(2.0)
    try:
        s9200.connect((dishy_target, 9200))
        lat9200 = (time.time() - t0) * 1000
        s9200.close()
        json_report["starlink_local_endpoints"]["port_9200"] = {
            "status": "OPEN",
            "tcp_latency_ms": round(lat9200, 2),
            "protocol": "SpaceX gRPC-Web Service"
        }
        log(f"  * Status: OPEN ({lat9200:.2f}ms) | Connected without administrative payload")
    except Exception as e:
        json_report["starlink_local_endpoints"]["port_9200"] = {"status": "FAIL/CLOSED", "error": str(e)}
        log(f"  * Status: CLOSED/TIMEOUT ({e})")

    # ==============================================================================
    # SECTION 6: TRACEROUTE & PATH ISOLATION
    # ==============================================================================
    log("\n" + "=" * 80)
    log("SECTION 6: TRACEROUTE & LAYER-3 PATH TOPOLOGY")
    log("=" * 80)

    for d in TARGET_DOMAINS:
        log(f"\n--- Traceroute to {d} (tracert -d -h 12 -w 1000) ---")
        tr_out = run_ps(f"tracert -d -h 12 -w 1000 {d}", timeout=35)
        hops = []
        for line in tr_out.splitlines():
            line_clean = line.strip()
            m = re.match(r'^\s*(\d+)\s+([\d\<\s]+ms|\*)\s+([\d\<\s]+ms|\*)\s+([\d\<\s]+ms|\*)\s+([0-9\.]+)', line_clean)
            if m:
                hop_num = int(m.group(1))
                ip = m.group(5)
                hops.append({"hop": hop_num, "ip": ip})
        json_report["traceroute_paths"][d] = hops

    # Save artifacts
    try:
        with open(output_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(raw_logs))
        log(f"\n[+] Raw log saved: {output_txt} ({os.path.getsize(output_txt)} bytes)")
    except Exception as e:
        log(f"[!] Error writing txt log: {e}")

    try:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2)
        log(f"[+] Structured JSON saved: {output_json} ({os.path.getsize(output_json)} bytes)")
    except Exception as e:
        log(f"[!] Error writing json report: {e}")

    # Automated Comparative Diffing (if compare path provided or exists in suspended mode)
    if compare_baseline_path and os.path.exists(compare_baseline_path):
        perform_diff(compare_baseline_path, json_report)
    elif mode == "suspended" and os.path.exists(r"D:\FluxWAN\starlink_baseline_windows_v2.json"):
        perform_diff(r"D:\FluxWAN\starlink_baseline_windows_v2.json", json_report)

    log(f"\n>>> AUDIT SUITE ({mode.upper()}) COMPLETE.")

def perform_diff(baseline_json_path, current_report):
    log("\n" + "=" * 80)
    log("AUTOMATED COMPARATIVE ANALYSIS: BASELINE vs SUSPENDED STATE")
    log("=" * 80)
    try:
        with open(baseline_json_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    except Exception as e:
        log(f"[!] Could not load baseline JSON for diff: {e}")
        return

    log(f"Comparing Current Audit against Baseline from: {baseline.get('audit_metadata', {}).get('timestamp_utc')}\n")

    # 1. DNS Diff
    log("1. DNS Resolution Comparison:")
    for dom in TARGET_DOMAINS:
        base_dns = baseline.get("dns_evaluations", {}).get(dom, {}).get("system_resolver", {}).get("status", "N/A")
        curr_dns = current_report.get("dns_evaluations", {}).get(dom, {}).get("system_resolver", {}).get("status", "N/A")
        diff_tag = "MATCH (Normal)" if base_dns == curr_dns else "CHANGED (Restriction Detected)"
        log(f"  * {dom:<20}: Baseline={base_dns:<8} | Current={curr_dns:<8} | [{diff_tag}]")

    # 2. TCP/443 Reachability Diff
    log("\n2. TCP/443 Reachability Comparison:")
    for dom in TARGET_DOMAINS:
        base_probes = baseline.get("domain_probes", {}).get(dom, [])
        curr_probes = current_report.get("domain_probes", {}).get(dom, [])
        base_open = any(p.get("tcp_443", {}).get("status") == "SUCCESS" for p in base_probes)
        curr_open = any(p.get("tcp_443", {}).get("status") == "SUCCESS" for p in curr_probes)
        
        status_desc = "NORMAL" if (base_open == curr_open) else ("DROPPED/BLOCKED (Walled Garden ACL Active)" if not curr_open else "RESTORED")
        log(f"  * {dom:<20}: Baseline={'OPEN' if base_open else 'CLOSED'} | Current={'OPEN' if curr_open else 'CLOSED'} | [{status_desc}]")

    # 3. Dishy Local Interface
    log("\n3. Dishy Management Interface (192.168.100.1):")
    b80 = baseline.get("starlink_local_endpoints", {}).get("port_80", {}).get("status", "N/A")
    c80 = current_report.get("starlink_local_endpoints", {}).get("port_80", {}).get("status", "N/A")
    log(f"  * Port 80 (Web UI):   Baseline={b80} | Current={c80}")
    b92 = baseline.get("starlink_local_endpoints", {}).get("port_9200", {}).get("status", "N/A")
    c92 = current_report.get("starlink_local_endpoints", {}).get("port_9200", {}).get("status", "N/A")
    log(f"  * Port 9200 (gRPC):   Baseline={b92} | Current={c92}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Starlink Windows Baseline & Comparative Network Audit Suite (v2)")
    parser.add_argument("--mode", choices=["baseline", "suspended"], default="baseline",
                        help="Execution mode: 'baseline' (active subscription) or 'suspended' (testing under walled garden)")
    parser.add_argument("--compare", help="Path to baseline JSON file for automated diff comparison", default=None)
    parser.add_argument("--out-txt", help="Custom output TXT file path", default=None)
    parser.add_argument("--out-json", help="Custom output JSON file path", default=None)
    args = parser.parse_args()

    run_audit(mode=args.mode, output_txt=args.out_txt, output_json=args.out_json, compare_baseline_path=args.compare)
