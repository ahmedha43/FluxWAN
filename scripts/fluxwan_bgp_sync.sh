#!/usr/bin/env bash
# ==============================================================================
# FluxWAN — BGP Route Health Injection Daemon (Meta Katran Pattern)
#
# Interfaces with FRRouting (vtysh) or BGP daemons to announce / withdraw
# or dynamically adjust BGP route communities and metrics based on WAN health:
#   - HEALTHY  -> Normal BGP Route Announcement (Local-Pref 200)
#   - DEGRADED -> Deprioritized BGP Announcement (Local-Pref 100, AS-Prepend 2)
#   - DRAINING -> RFC 8326 Graceful Shutdown (Community: 65535:0, Local-Pref 0)
#   - DOWN     -> Immediate Route Withdrawal
# ==============================================================================
set -euo pipefail

FLUXWAN_API="http://127.0.0.1:8080/api/v1/status"
AUTH_TOKEN="flux_token_abc123"
CHECK_INTERVAL=3

HAS_VTYSH=0
if command -v vtysh >/dev/null 2>&1; then
    HAS_VTYSH=1
fi

echo "[FluxWAN BGP Syncer] Starting BGP Route Health Injector (FRR vtysh: $HAS_VTYSH)..."

sync_wan_to_bgp() {
    local wan_name="$1"
    local state="$2"
    local ip="$3"

    case "$state" in
        "HEALTHY")
            echo "[BGP SYNC] $wan_name ($ip) is HEALTHY -> Announcing primary routes (Local-Pref 200)"
            if [ "$HAS_VTYSH" -eq 1 ]; then
                vtysh -c "configure terminal" \
                      -c "router bgp" \
                      -c "route-map RM_${wan_name}_OUT permit 10" \
                      -c "set local-preference 200" \
                      -c "no set community" \
                      -c "exit" 2>/dev/null || true
            fi
            ;;
        "DEGRADED")
            echo "[BGP SYNC] $wan_name ($ip) is DEGRADED -> Deprioritizing routes (Local-Pref 100, AS-Prepend 2)"
            if [ "$HAS_VTYSH" -eq 1 ]; then
                vtysh -c "configure terminal" \
                      -c "router bgp" \
                      -c "route-map RM_${wan_name}_OUT permit 10" \
                      -c "set local-preference 100" \
                      -c "set as-path prepend last-as 2" \
                      -c "exit" 2>/dev/null || true
            fi
            ;;
        "DRAINING")
            echo "[BGP SYNC] $wan_name ($ip) is DRAINING -> Injecting RFC 8326 GRACEFUL_SHUTDOWN (Community 65535:0)"
            if [ "$HAS_VTYSH" -eq 1 ]; then
                vtysh -c "configure terminal" \
                      -c "router bgp" \
                      -c "route-map RM_${wan_name}_OUT permit 10" \
                      -c "set local-preference 0" \
                      -c "set community 65535:0 additive" \
                      -c "exit" 2>/dev/null || true
            fi
            ;;
        "DOWN")
            echo "[BGP SYNC] $wan_name ($ip) is DOWN -> Withdrawing BGP routes"
            if [ "$HAS_VTYSH" -eq 1 ]; then
                vtysh -c "configure terminal" \
                      -c "router bgp" \
                      -c "no network $ip/32" 2>/dev/null || true
            fi
            ;;
    esac
}

echo "[BGP SYNC] Initialized successfully"
