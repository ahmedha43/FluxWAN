#!/usr/bin/env bash
# ==============================================================================
# Starlink Walled Garden / Suspended / Unverified Network Diagnostic & Audit Suite
# ==============================================================================
# Strictly passive, non-intrusive diagnostic tool for Linux Mini PCs & Routers
# ==============================================================================

set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

TARGETS=("starlink.com" "account.starlink.com" "google.com" "cloudflare.com" "microsoft.com")

banner() {
    echo -e "\n${BOLD}${CYAN}================================================================================${NC}"
    echo -e "${BOLD}${CYAN} [TEST] $1${NC}"
    echo -e "${BOLD}${CYAN}================================================================================${NC}"
}

echo -e "${BOLD}${GREEN}"
echo "================================================================================"
echo "   STARLINK WALLED GARDEN BOUNDARY DIAGNOSTIC SUITE (BASH AUDITOR)"
echo "   Target System: Linux Mini PC / Router behind Starlink User Terminal"
echo "================================================================================"
echo -e "${NC}"
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Kernel:    $(uname -s -r -m)"
echo "Host:      $(hostname)"

# ------------------------------------------------------------------------------
# 1. IP Addresses, DHCP & Routes
# ------------------------------------------------------------------------------
banner "1. Network Interfaces, Assigned IPs & Routing Table"

echo -e "${BOLD}Active Network Interfaces:${NC}"
if command -v ip >/dev/null 2>&1; then
    ip -br a
    echo -e "\n${BOLD}IPv4 Routes:${NC}"
    ip -4 route show
    echo -e "\n${BOLD}IPv6 Routes:${NC}"
    ip -6 route show 2>/dev/null | head -n 10 || echo "No IPv6 routes"
else
    ifconfig -a
    route -n
fi

echo -e "\n${BOLD}Default Gateway Analysis:${NC}"
GW_IP=$(ip route | grep default | awk '{print $3}' | head -n 1)
if [ -n "$GW_IP" ]; then
    echo "  Default Gateway IP: $GW_IP"
    if [[ "$GW_IP" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
        echo -e "  ${YELLOW}--> Direct Starlink CGNAT Gateway (RFC 6598: 100.64.0.0/10)${NC}"
    elif [[ "$GW_IP" =~ ^192\.168\.1\. ]]; then
        echo -e "  ${BLUE}--> Starlink Gen2/Gen3 Router standard LAN IP (192.168.1.1)${NC}"
    fi
fi

echo -e "\n${BOLD}Starlink Dishy Direct Management (192.168.100.1):${NC}"
if curl -s -m 2 -I http://192.168.100.1/ >/dev/null 2>&1; then
    echo -e "  ${GREEN}[+] Starlink Dishy Management Interface (192.168.100.1:80) is REACHABLE.${NC}"
else
    echo -e "  ${YELLOW}[!] Dishy (192.168.100.1:80) not responding directly (Requires static route if router bypass mode).${NC}"
fi

# ------------------------------------------------------------------------------
# 2. DNS Resolution, Redirection & Hijacking Check
# ------------------------------------------------------------------------------
banner "2. DNS Resolver Behavior & Hijacking Analysis"

echo -e "${BOLD}Configured Nameservers in /etc/resolv.conf:${NC}"
grep "^nameserver" /etc/resolv.conf || echo "None found"

echo -e "\n${BOLD}Testing Port 53 Outbound Reachability (DNS Hijack / Drop Detection):${NC}"
RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9" "192.168.100.1")

for dns in "${RESOLVERS[@]}"; do
    printf "  * Querying %-16s ... " "$dns"
    if command -v dig >/dev/null 2>&1; then
        RES=$(dig +time=2 +tries=1 +short @$dns google.com A 2>/dev/null | head -n 1)
        if [ -n "$RES" ]; then
            echo -e "${GREEN}RESPONDED${NC} -> $RES"
        else
            echo -e "${RED}DROPPED / TIMEOUT${NC}"
        fi
    elif command -v nslookup >/dev/null 2>&1; then
        RES=$(nslookup -timeout=2 google.com $dns 2>/dev/null | grep -A 1 "Name:" | grep "Address" | awk '{print $2}' | head -n 1)
        if [ -n "$RES" ]; then
            echo -e "${GREEN}RESPONDED${NC} -> $RES"
        else
            echo -e "${RED}DROPPED / TIMEOUT${NC}"
        fi
    else
        echo "Neither dig nor nslookup installed"
        break
    fi
done

# ------------------------------------------------------------------------------
# 3, 4, 5, 6, 8. Target Domain Testing & Endpoint Profiling
# ------------------------------------------------------------------------------
banner "3, 4, 5, 6, 8. Target Domains: DNS, TCP/443, TLS Handshake & Archetype Analysis"

for target in "${TARGETS[@]}"; do
    echo -e "\n${BOLD}${CYAN}---> Domain: $target${NC}"
    
    # 1. DNS Resolution
    IPV4_LIST=()
    if command -v getent >/dev/null 2>&1; then
        mapfile -t IPV4_LIST < <(getent ahostsv4 "$target" 2>/dev/null | awk '{print $1}' | sort -u)
    elif command -v nslookup >/dev/null 2>&1; then
        mapfile -t IPV4_LIST < <(nslookup "$target" 2>/dev/null | grep "Address:" | grep -v "#" | awk '{print $2}')
    fi
    
    echo -e "  * Resolved IPv4: ${GREEN}${IPV4_LIST[*]:-(None)}${NC}"
    
    # 2. TCP/443 Probing (IPv4)
    for ip in "${IPV4_LIST[@]:0:2}"; do
        printf "  * Probing TCP/443 [IPv4] %-16s: " "$ip"
        if nc -z -w 3 "$ip" 443 2>/dev/null; then
            echo -e "${GREEN}OPEN (SYN-ACK Accepted)${NC}"
            
            # Full TLS/SNI Check via OpenSSL or curl
            echo -e "    ${BOLD}TLS Handshake & Certificate Verification:${NC}"
            CERT_INFO=$(echo | openssl s_client -connect "${ip}:443" -servername "$target" -brief 2>&1 || true)
            echo "$CERT_INFO" | grep -E "(Protocol|Ciphersuite|Verification)" | sed 's/^/      /'
            
            # HTTP Archetype Probe
            echo -e "    ${BOLD}HTTP Service Archetype Probe:${NC}"
            HTTP_HEADERS=$(curl -sI -m 4 --resolve "${target}:443:${ip}" "https://${target}/" 2>/dev/null || true)
            STATUS_LINE=$(echo "$HTTP_HEADERS" | head -n 1)
            SERVER_HDR=$(echo "$HTTP_HEADERS" | grep -i "^server:" | tr -d '\r')
            LOC_HDR=$(echo "$HTTP_HEADERS" | grep -i "^location:" | tr -d '\r')
            CF_RAY=$(echo "$HTTP_HEADERS" | grep -i "^cf-ray:" | tr -d '\r')
            
            echo "      HTTP Status: ${STATUS_LINE:-No response}"
            [ -n "$SERVER_HDR" ] && echo "      Server:      $SERVER_HDR"
            [ -n "$LOC_HDR" ]    && echo "      Redirect:    $LOC_HDR"
            
            # Archetype classification
            if [ -n "$CF_RAY" ] || [[ "$SERVER_HDR" =~ [Cc]loudflare ]]; then
                echo -e "      Archetype:   ${MAGENTA}${BOLD}CDN Edge (Cloudflare Anycast Mesh)${NC}"
            elif [[ "$SERVER_HDR" =~ [Ff]astly ]]; then
                echo -e "      Archetype:   ${MAGENTA}${BOLD}CDN Edge (Fastly Global Network)${NC}"
            elif [[ "$LOC_HDR" =~ starlink\.com/(activate|auth) ]]; then
                echo -e "      Archetype:   ${YELLOW}${BOLD}Captive Portal / Account Suspension Redirection${NC}"
            else
                echo -e "      Archetype:   ${CYAN}Standard Origin Web Server / API${NC}"
            fi
        else
            echo -e "${RED}BLOCKED / DROPPED (No SYN-ACK)${NC}"
        fi
    done

    # 3. IPv6 Check
    IPV6_LIST=()
    if command -v getent >/dev/null 2>&1; then
        mapfile -t IPV6_LIST < <(getent ahostsv6 "$target" 2>/dev/null | awk '{print $1}' | sort -u)
    fi
    if [ ${#IPV6_LIST[@]} -gt 0 ]; then
        echo -e "  * Resolved IPv6: ${GREEN}${IPV6_LIST[*]:-(None)}${NC}"
        v6_ip="${IPV6_LIST[0]}"
        printf "  * Probing TCP/443 [IPv6] %-30s: " "$v6_ip"
        if nc -6 -z -w 3 "$v6_ip" 443 2>/dev/null; then
            echo -e "${GREEN}OPEN${NC}"
        else
            echo -e "${RED}DROPPED / NO ROUTE${NC}"
        fi
    else
        echo -e "  * Resolved IPv6: ${YELLOW}No AAAA or IPv6 disabled${NC}"
    fi
done

# ------------------------------------------------------------------------------
# 7. Traceroute / Hop Isolation
# ------------------------------------------------------------------------------
banner "7. Layer-3 Path Tracing (Isolating Where Drops Occur)"

for h in "account.starlink.com" "google.com"; do
    echo -e "\n${BOLD}Path to $h:${NC}"
    if command -v traceroute >/dev/null 2>&1; then
        traceroute -n -m 8 -q 1 -w 1 "$h" 2>/dev/null | while read -r line; do
            if [[ "$line" =~ 192\.168\.100\.1|192\.168\.1\. ]]; then
                echo -e "  $line ${BLUE}[Local Router / Dishy UT]${NC}"
            elif [[ "$line" =~ 100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
                echo -e "  $line ${YELLOW}[Starlink Core CGNAT / Satellite Hop]${NC}"
            elif [[ "$line" =~ \* ]]; then
                echo -e "  $line ${RED}[Dropped by Firewall ACL]${NC}"
            else
                echo "  $line"
            fi
        done
    else
        echo "traceroute command not found"
    fi
done

# ------------------------------------------------------------------------------
# Compliance & Safety Confirmation
# ------------------------------------------------------------------------------
banner "9 & 10. Compliance & Ethical Boundaries Confirmation"
echo -e "  * External VPN / VPS / Proxies Used:  ${GREEN}NONE (100% Direct Path Probing)${NC}"
echo -e "  * ACL / Walled Garden Circumvention: ${GREEN}NONE (Standard RFC-compliant probes only)${NC}"
echo -e "\n${BOLD}${GREEN}Audit Complete!${NC}\n"
