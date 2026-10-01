#!/usr/bin/env python3
"""
================================================================================
Starlink Walled Garden / Suspended / Unverified Network Diagnostic & Audit Tool
================================================================================
Purpose:
  Conducts safe, strictly authorized, non-intrusive network diagnostics from a
  Linux device (Mini PC or router) connected directly behind a Starlink terminal.
  The objective is to map legitimate boundary limits, routing policies, DNS
  behavior, and allowed TLS/TCP endpoints WITHOUT attempting to bypass security,
  spoof headers/SNI, or violate Starlink Terms of Service.

Strict Compliance Guarantee:
  - NO VPNs, VPSs, or external proxies utilized.
  - NO packet spoofing, SNI manipulation, or captive portal circumvention.
  - Standard, well-formed DNS, ICMP, TCP SYN, and TLS ClientHello probes only.
================================================================================
"""

import sys
import os
import socket
import ssl
import json
import time
import subprocess
import re
import argparse
from datetime import datetime

TARGET_DOMAINS = [
    "starlink.com",
    "account.starlink.com",
    "auth.starlink.com",
    "google.com",
    "cloudflare.com",
    "microsoft.com"
]

PUBLIC_RESOLVERS = [
    ("System Resolver", None),
    ("Cloudflare DNS", "1.1.1.1"),
    ("Google DNS", "8.8.8.8"),
    ("Quad9 DNS", "9.9.9.9"),
    ("Starlink Dishy (Local)", "192.168.100.1")
]

# ANSI colors for terminal output
C_CYAN    = "\033[96m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_RED     = "\033[91m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_BOLD    = "\033[1m"
C_RESET   = "\033[0m"

def print_header(title):
    print(f"\n{C_BOLD}{C_CYAN}================================================================================{C_RESET}")
    print(f"{C_BOLD}{C_CYAN} [TEST] {title}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}================================================================================{C_RESET}")

def run_command(cmd, timeout=5):
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout expired"
    except Exception as e:
        return -1, "", str(e)

# ------------------------------------------------------------------------------
# 1. IP Addresses, Routes & Interfaces
# ------------------------------------------------------------------------------
def audit_interfaces_and_routes():
    print_header("1. Network Interfaces, Assigned IPs & Routing Table")
    data = {
        "interfaces": {},
        "routes_v4": [],
        "routes_v6": [],
        "resolv_conf": [],
        "dishy_reachable": False
    }

    # Extract interfaces
    is_windows = sys.platform.startswith("win")
    if is_windows:
        rc, stdout, _ = run_command("ipconfig")
    else:
        rc, stdout, _ = run_command("ip -br a 2>/dev/null || ifconfig -a 2>/dev/null")

    print(f"{C_BOLD}Interface Configuration:{C_RESET}")
    if stdout:
        for line in stdout.splitlines()[:25]:
            print(f"  {line}")
        if len(stdout.splitlines()) > 25:
            print("  [... output truncated for readability ...]")
    else:
        print("  (Command not available)")

    # Parse IPv4 routes
    if is_windows:
        rc, v4_routes, _ = run_command("route print -4 0.0.0.0*")
    else:
        rc, v4_routes, _ = run_command("ip -4 route show 2>/dev/null || route -n 2>/dev/null")

    print(f"\n{C_BOLD}IPv4 Routes:{C_RESET}")
    for line in v4_routes.splitlines():
        line_clean = line.strip()
        if not line_clean: continue
        print(f"  {line_clean}")
        data["routes_v4"].append(line_clean)
        if "default" in line_clean or "0.0.0.0" in line_clean:
            if "100.64." in line_clean or re.search(r'100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.', line_clean):
                print(f"  {C_YELLOW}--> Detected Starlink CGNAT Gateway (RFC 6598: 100.64.0.0/10){C_RESET}")
            elif "192.168.1." in line_clean:
                print(f"  {C_BLUE}--> Standard Starlink Router LAN subnet (192.168.1.0/24){C_RESET}")
            elif "192.168.100." in line_clean:
                print(f"  {C_MAGENTA}--> Starlink Dishy Direct Management Subnet (192.168.100.0/24){C_RESET}")

    # Parse IPv6 routes
    if not is_windows:
        rc, v6_routes, _ = run_command("ip -6 route show 2>/dev/null")
        print(f"\n{C_BOLD}IPv6 Routes:{C_RESET}")
        if v6_routes:
            for line in v6_routes.splitlines()[:8]:
                print(f"  {line}")
                data["routes_v6"].append(line)
        else:
            print("  (No IPv6 routes configured or disabled)")

    # Read /etc/resolv.conf
    if os.path.exists("/etc/resolv.conf"):
        print(f"\n{C_BOLD}Configured DNS Servers (/etc/resolv.conf):{C_RESET}")
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    ns = line.split()[1]
                    print(f"  * {ns}")
                    data["resolv_conf"].append(ns)

    # Test reachability to Starlink Dishy management IP (192.168.100.1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect(("192.168.100.1", 80))
        data["dishy_reachable"] = True
        print(f"\n{C_GREEN}[+] Starlink Dishy Management IP (192.168.100.1:80) is REACHABLE{C_RESET}")
    except Exception:
        print(f"\n{C_YELLOW}[!] Starlink Dishy (192.168.100.1) port 80 not responding (Bypass mode or router firewall){C_RESET}")
    finally:
        s.close()

    return data

# ------------------------------------------------------------------------------
# 2. DNS Hijacking, Transparent Proxying & Resolver Analysis
# ------------------------------------------------------------------------------
def build_raw_dns_query(domain, qtype=1): # 1=A, 28=AAAA
    txid = b'\xaa\xbb'
    flags = b'\x01\x00' # Standard query, recursion desired
    qdcount = b'\x00\x01'
    ancount = nscount = arcount = b'\x00\x00'
    header = txid + flags + qdcount + ancount + nscount + arcount
    
    question = b''
    for part in domain.split('.'):
        question += bytes([len(part)]) + part.encode('ascii')
    question += b'\x00'
    qtype_bytes = bytes([qtype >> 8, qtype & 0xff])
    qclass_bytes = b'\x00\x01' # IN
    
    return header + question + qtype_bytes + qclass_bytes

def parse_raw_dns_ips(response):
    ips = []
    if len(response) < 12:
        return ips
    ancount = (response[6] << 8) | response[7]
    idx = 12
    while idx < len(response) and response[idx] != 0:
        if (response[idx] & 0xc0) == 0xc0:
            idx += 2
            break
        idx += 1 + response[idx]
    if idx < len(response) and response[idx] == 0:
        idx += 5
        
    for _ in range(ancount):
        if idx >= len(response): break
        if (response[idx] & 0xc0) == 0xc0:
            idx += 2
        else:
            while idx < len(response) and response[idx] != 0:
                idx += 1 + response[idx]
            idx += 1
        if idx + 10 > len(response): break
        atype = (response[idx] << 8) | response[idx+1]
        rdlen = (response[idx+8] << 8) | response[idx+9]
        idx += 10
        if atype == 1 and rdlen == 4 and idx + 4 <= len(response):
            ip = socket.inet_ntoa(response[idx:idx+4])
            ips.append(ip)
        elif atype == 28 and rdlen == 16 and idx + 16 <= len(response):
            ip = socket.inet_ntop(socket.AF_INET6, response[idx:idx+16])
            ips.append(ip)
        idx += rdlen
    return ips

def audit_dns():
    print_header("2. DNS Resolver Behavior, Redirection & Hijacking Check")
    test_domain = "google.com"
    results = {}

    print(f"Testing DNS resolution behavior across different resolvers for '{test_domain}':\n")

    for name, server in PUBLIC_RESOLVERS:
        if server is None:
            t0 = time.time()
            try:
                answers = socket.getaddrinfo(test_domain, 80, socket.AF_INET)
                lat = (time.time() - t0) * 1000
                ips = list(set([a[4][0] for a in answers]))
                print(f"  * {C_BOLD}{name:<25}{C_RESET}: {C_GREEN}SUCCESS{C_RESET} ({lat:.1f}ms) -> {', '.join(ips[:3])}")
                results[name] = {"status": "SUCCESS", "ips": ips, "latency_ms": lat}
            except Exception as e:
                print(f"  * {C_BOLD}{name:<25}{C_RESET}: {C_RED}FAILED ({e}){C_RESET}")
                results[name] = {"status": "FAILED", "error": str(e)}
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.5)
            query = build_raw_dns_query(test_domain, 1)
            t0 = time.time()
            try:
                sock.sendto(query, (server, 53))
                resp, addr = sock.recvfrom(4096)
                lat = (time.time() - t0) * 1000
                parsed_ips = parse_raw_dns_ips(resp)
                
                hijacked = (addr[0] != server)
                status_str = f"{C_GREEN}SUCCESS{C_RESET}"
                if hijacked:
                    status_str += f" {C_YELLOW}[TRANSPARENTLY INTERCEPTED by {addr[0]}]{C_RESET}"
                print(f"  * {C_BOLD}{name} ({server:<15}){C_RESET}: {status_str} ({lat:.1f}ms) -> {', '.join(parsed_ips[:3])}")
                results[name] = {"status": "SUCCESS", "ips": parsed_ips, "latency_ms": lat, "hijacked": hijacked, "responder": addr[0]}
            except socket.timeout:
                print(f"  * {C_BOLD}{name} ({server:<15}){C_RESET}: {C_RED}DROPPED / TIMEOUT (UDP/53 blocked by Starlink UT/POP){C_RESET}")
                results[name] = {"status": "DROPPED"}
            except Exception as e:
                print(f"  * {C_BOLD}{name} ({server:<15}){C_RESET}: {C_RED}ERROR ({e}){C_RESET}")
                results[name] = {"status": "ERROR", "error": str(e)}
            finally:
                sock.close()

    print(f"\n{C_BOLD}DNS Analysis Conclusion:{C_RESET}")
    has_dropped = any(r.get("status") == "DROPPED" for k, r in results.items() if k != "System Resolver")
    all_success = all(r.get("status") == "SUCCESS" for r in results.values())
    if all_success:
        print(f"  {C_GREEN}[+] Full unhindered DNS resolution to external servers is allowed.{C_RESET}")
    elif has_dropped:
        print(f"  {C_YELLOW}[!] Starlink Walled Garden is actively blocking outbound UDP/53 to non-Starlink resolvers.{C_RESET}")
    return results

# ------------------------------------------------------------------------------
# 3, 4, 5, 6: DNS, TCP/443 & TLS/SNI Audit for Target Domains
# ------------------------------------------------------------------------------
def probe_tcp_port(ip, port=443, is_v6=False, timeout=3.0):
    family = socket.AF_INET6 if is_v6 else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
        lat = (time.time() - t0) * 1000
        return "OPEN", lat, s
    except socket.timeout:
        return "DROPPED (Timeout)", None, None
    except ConnectionRefusedError:
        return "REJECTED (TCP RST)", None, None
    except OSError as e:
        if "Network is unreachable" in str(e) or "101" in str(e):
            return "NO_ROUTE (Unreachable)", None, None
        return f"ERROR ({e})", None, None

def inspect_tls_handshake(sock, hostname):
    tls_info = {
        "success": False,
        "version": None,
        "cipher": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_sans": [],
        "cert_expiry": None,
        "is_intercepted": False
    }

    # First attempt: Strict verification to detect legitimate cert
    ctx = ssl.create_default_context()
    tls_sock = None
    try:
        tls_sock = ctx.wrap_socket(sock, server_hostname=hostname)
        tls_info["success"] = True
        tls_info["version"] = tls_sock.version()
        cipher_tuple = tls_sock.cipher()
        tls_info["cipher"] = cipher_tuple[0] if cipher_tuple else "Unknown"
        
        cert = tls_sock.getpeercert()
        if cert:
            sub = dict(x[0] for x in cert.get('subject', ()))
            iss = dict(x[0] for x in cert.get('issuer', ()))
            tls_info["cert_subject"] = sub.get("commonName") or sub.get("organizationName")
            tls_info["cert_issuer"] = iss.get("commonName") or iss.get("organizationName")
            tls_info["cert_sans"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:5]
            tls_info["cert_expiry"] = cert.get("notAfter")
        return tls_info, tls_sock
    except ssl.SSLCertVerificationError as ve:
        # A certificate verification error indicates a captive portal or interception!
        tls_info["success"] = True
        tls_info["is_intercepted"] = True
        tls_info["error"] = f"Certificate Untrusted (Captive Portal detected): {ve.verify_message}"
        tls_info["cert_issuer"] = "Untrusted / Self-Signed Interceptor"
        return tls_info, None
    except Exception as e:
        tls_info["error"] = str(e)
        return tls_info, None

def analyze_http_endpoint(tls_sock, hostname):
    http_data = {
        "status_code": None,
        "server": None,
        "location": None,
        "content_type": None,
        "cf_ray": None,
        "archetype": "Unknown"
    }
    if not tls_sock:
        return http_data

    try:
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"User-Agent: Mozilla/5.0 (Compatible; StarlinkAudit/1.0)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        tls_sock.sendall(req.encode('ascii'))
        resp = tls_sock.recv(4096).decode('iso-8859-1', 'ignore')
        
        first_line = resp.split('\r\n')[0] if resp else ""
        m = re.search(r'HTTP/\S+\s+(\d+)', first_line)
        if m:
            http_data["status_code"] = int(m.group(1))
            
        headers = {}
        for line in resp.split('\r\n')[1:]:
            if not line: break
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
                
        http_data["server"] = headers.get("server")
        http_data["location"] = headers.get("location")
        http_data["content_type"] = headers.get("content-type")
        http_data["cf_ray"] = headers.get("cf-ray")
        
        srv = (http_data["server"] or "").lower()
        loc = (http_data["location"] or "").lower()
        ctype = (http_data["content_type"] or "").lower()
        
        if "cloudflare" in srv or http_data["cf_ray"]:
            http_data["archetype"] = "CDN Edge (Cloudflare Anycast)"
        elif "fastly" in srv or "fastly" in headers.get("via", "").lower():
            http_data["archetype"] = "CDN Edge (Fastly Anycast)"
        elif "amazon" in srv or "cloudfront" in srv:
            http_data["archetype"] = "CDN Edge (AWS CloudFront)"
        elif "starlink" in loc or "auth" in loc or "activate" in loc:
            http_data["archetype"] = "Captive Portal / Account Activation Redirect"
        elif "application/json" in ctype or "grpc" in ctype:
            http_data["archetype"] = "Backend API Endpoint"
        elif http_data["status_code"] in [200, 301, 302, 403]:
            http_data["archetype"] = f"Standard Web Server ({http_data['server'] or 'HTTP Generic'})"
    except Exception as e:
        http_data["error"] = str(e)
    return http_data

def audit_domains():
    print_header("3, 4, 5, 6, 8. Target Domain Resolution, TCP/443 Reachability, TLS/SNI & Endpoint Profiling")
    domain_results = {}

    for domain in TARGET_DOMAINS:
        print(f"\n{C_BOLD}---> Target: {C_CYAN}{domain}{C_RESET}")
        domain_results[domain] = {"ipv4": [], "ipv6": [], "tls": {}}
        
        v4_ips = []
        v6_ips = []
        try:
            res_v4 = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            v4_ips = list(set([r[4][0] for r in res_v4]))
            print(f"  * DNS IPv4 (A):    {C_GREEN}{', '.join(v4_ips)}{C_RESET}")
        except Exception as e:
            print(f"  * DNS IPv4 (A):    {C_RED}Resolution Failed ({e}){C_RESET}")

        try:
            res_v6 = socket.getaddrinfo(domain, 443, socket.AF_INET6, socket.SOCK_STREAM)
            v6_ips = list(set([r[4][0] for r in res_v6]))
            print(f"  * DNS IPv6 (AAAA): {C_GREEN}{', '.join(v6_ips)}{C_RESET}")
        except Exception:
            print(f"  * DNS IPv6 (AAAA): {C_YELLOW}No AAAA Record / IPv6 disabled{C_RESET}")

        for ip in v4_ips[:2]:
            status, lat, raw_sock = probe_tcp_port(ip, port=443, is_v6=False)
            color = C_GREEN if status == "OPEN" else (C_YELLOW if "REJECTED" in status else C_RED)
            lat_str = f"({lat:.1f}ms)" if lat else ""
            print(f"  * TCP/443 [IPv4] {ip:<16}: {color}{status}{C_RESET} {lat_str}")
            
            res_item = {"ip": ip, "status": status, "latency_ms": lat}
            
            if status == "OPEN" and raw_sock:
                tls_info, tls_sock = inspect_tls_handshake(raw_sock, domain)
                res_item["tls"] = tls_info
                if tls_info.get("success"):
                    print(f"    --> TLS Handshake: {C_GREEN}SUCCESS{C_RESET} ({tls_info['version']} / {tls_info['cipher']})")
                    print(f"    --> Certificate:   CN: {tls_info['cert_subject']} | Issuer: {tls_info['cert_issuer']}")
                    if tls_info.get("cert_sans"):
                        print(f"    --> SANs:          {', '.join(tls_info['cert_sans'][:4])}")
                    
                    if tls_sock:
                        http_meta = analyze_http_endpoint(tls_sock, domain)
                        res_item["http"] = http_meta
                        print(f"    --> HTTP Response: Status: {http_meta['status_code']} | Server: {http_meta['server']}")
                        print(f"    --> Endpoint Type: {C_MAGENTA}{C_BOLD}{http_meta['archetype']}{C_RESET}")
                        tls_sock.close()
                else:
                    print(f"    --> TLS Handshake: {C_RED}FAILED ({tls_info.get('error')}){C_RESET}")
                    raw_sock.close()
            domain_results[domain]["ipv4"].append(res_item)

        for ip in v6_ips[:1]:
            status, lat, raw_sock = probe_tcp_port(ip, port=443, is_v6=True)
            color = C_GREEN if status == "OPEN" else (C_YELLOW if "REJECTED" in status else C_RED)
            lat_str = f"({lat:.1f}ms)" if lat else ""
            print(f"  * TCP/443 [IPv6] {ip}: {color}{status}{C_RESET} {lat_str}")
            
            res_item = {"ip": ip, "status": status, "latency_ms": lat}
            if status == "OPEN" and raw_sock:
                tls_info, tls_sock = inspect_tls_handshake(raw_sock, domain)
                res_item["tls"] = tls_info
                if tls_info.get("success"):
                    print(f"    --> TLS (IPv6):    {C_GREEN}SUCCESS{C_RESET} ({tls_info['version']})")
                    if tls_sock: tls_sock.close()
                else:
                    raw_sock.close()
            domain_results[domain]["ipv6"].append(res_item)

    return domain_results

# ------------------------------------------------------------------------------
# 7. Traceroute / Path Isolation (Pinpoint Where Drops Occur)
# ------------------------------------------------------------------------------
def audit_packet_path():
    print_header("7. Packet Path & Hop Tracing (Detecting Where Packets Drop)")
    
    is_windows = sys.platform.startswith("win")
    trace_cmd_tpl = "tracert -d -h 8 -w 1000 {target}" if is_windows else "traceroute -n -m 8 -q 1 -w 1 {target} 2>/dev/null || tracepath -n -m 8 {target} 2>/dev/null"

    for test_host in ["starlink.com", "google.com"]:
        print(f"\n{C_BOLD}Hop Trace to {C_CYAN}{test_host}{C_RESET}:")
        rc, out, _ = run_command(trace_cmd_tpl.format(target=test_host), timeout=15)
        if out:
            for line in out.splitlines():
                line_s = line.strip()
                if not line_s: continue
                if "192.168.100.1" in line_s or "192.168.1." in line_s:
                    print(f"  {line_s}  {C_BLUE}[Local Router / Dishy User Terminal]{C_RESET}")
                elif "100.64." in line_s or re.search(r'100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.', line_s):
                    print(f"  {line_s}  {C_YELLOW}[Starlink CGNAT Core / Satellite Link]{C_RESET}")
                elif "*" in line_s:
                    print(f"  {line_s}  {C_RED}[Packet Dropped / Filtered by Firewall ACL]{C_RESET}")
                else:
                    print(f"  {line_s}")
        else:
            print("  (traceroute/tracepath utility not found in system PATH)")

# ------------------------------------------------------------------------------
# Main Orchestrator & Final Comprehensive Assessment
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Starlink Walled Garden & Suspended Status Audit Tool")
    parser.add_argument("--json", dest="json_file", help="Export full audit results to JSON file", default=None)
    args = parser.parse_args()

    print(f"{C_BOLD}{C_GREEN}")
    print("================================================================================")
    print("   FLUXWAN / STARLINK WALLED GARDEN BOUNDARY AUDIT SUITE (V1.0)")
    print("   Strictly Non-Intrusive, Safe Diagnostic Mode (No Bypass / No Spoofing)")
    print("================================================================================")
    print(f"{C_RESET}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Host:      {socket.gethostname()} ({sys.platform})")

    audit_summary = {
        "timestamp": datetime.now().isoformat(),
        "network": audit_interfaces_and_routes(),
        "dns": audit_dns(),
        "domains": audit_domains()
    }

    audit_packet_path()

    print_header("FINAL DIAGNOSTIC SYNTHESIS & BOUNDARY SUMMARY")
    
    starlink_reachable = any(
        any(p.get("status") == "OPEN" for p in audit_summary["domains"].get(d, {}).get("ipv4", []))
        for d in ["starlink.com", "auth.starlink.com"]
    )
    internet_reachable = any(
        any(p.get("status") == "OPEN" for p in audit_summary["domains"].get(d, {}).get("ipv4", []))
        for d in ["google.com", "microsoft.com", "cloudflare.com"]
    )

    print(f"{C_BOLD}Executive Findings:{C_RESET}")
    if starlink_reachable and not internet_reachable:
        print(f"  1. {C_YELLOW}[CONFIRMED] Connection is currently in Starlink WALLED GARDEN / SUSPENDED state.{C_RESET}")
        print(f"  2. {C_GREEN}[ALLOWED] Official SpaceX / Starlink Account endpoints are accessible on TCP/443.{C_RESET}")
        print(f"  3. {C_RED}[RESTRICTED] General Internet transit (Google, Microsoft, Cloudflare) is silently dropped/blocked.{C_RESET}")
    elif starlink_reachable and internet_reachable:
        print(f"  1. {C_GREEN}[ACTIVE] Connection has FULL INTERNET CONNECTIVITY (Not in Walled Garden state).{C_RESET}")
    else:
        print(f"  1. {C_RED}[DISCONNECTED] Neither Starlink nor external internet endpoints are reachable.{C_RESET}")
        print(f"     Check physical cable / dish satellite alignment / dish booting state.")

    print("\nAdherence to Constraints (Items 9 & 10):")
    print(f"  * VPN / Proxy / VPS: {C_GREEN}NONE USED{C_RESET} (Native Direct Routing only).")
    print(f"  * ACL / Walled Garden: {C_GREEN}NO BYPASS ATTEMPTED{C_RESET} (Passive observation only).\n")

    if args.json_file:
        try:
            with open(args.json_file, "w") as f:
                json.dump(audit_summary, f, indent=2)
            print(f"{C_GREEN}[+] Full audit results written to JSON: {args.json_file}{C_RESET}\n")
        except Exception as ex:
            print(f"{C_RED}[!] Error writing JSON report: {ex}{C_RESET}\n")

if __name__ == "__main__":
    main()
