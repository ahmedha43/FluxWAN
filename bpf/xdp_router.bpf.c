/* ===========================================================================
 * FluxWAN XDP Egress Multi-WAN Router — eBPF/XDP Kernel Program
 *
 * Architecture inspired by Facebook Katran (https://github.com/facebookincubator/katran)
 * Adapted for Egress Multi-WAN Gateway (vs Katran's Ingress L4 LB)
 *
 * Key differences from Katran:
 *   - Egress path: LAN → WAN (not Ingress datacenter LB)
 *   - SNAT/Masquerade: rewrites src_ip to WAN IP for outbound flows
 *   - fwmark-based policy routing (not GUE/IPIP encapsulation)
 *   - Pure C, no C++, minimal footprint for embedded Linux routers
 *
 * Katran references used:
 *   1. pckt_parsing.h  → calc_offset, Verifier-safe bounds checking pattern
 *   2. csum_helpers.h  → csum_fold_helper, ipv4_csum_inline, bpf_csum_diff
 *   3. balancer_kern.c → LRU session map pattern, Maglev ring lookup
 * =========================================================================== */

#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef _BPF_INT_TYPES_
#define _BPF_INT_TYPES_
typedef __u8   uint8_t;
typedef __u16  uint16_t;
typedef __u32  uint32_t;
typedef __u64  uint64_t;
#endif

#if defined(__BPF__) || defined(BPF_HELPERS) || defined(__bpf__)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
struct icmphdr {
    __u8   type;
    __u8   code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
    } un;
};
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#else
/* Standalone compilation compatibility */
#define SEC(name)
#define __uint(name, val)
#define __type(name, val)
#define __always_inline inline __attribute__((always_inline))
#define BPF_MAP_TYPE_ARRAY        2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH     9
#define BPF_ANY 0
#define XDP_PASS   2
#define XDP_DROP   1
#define XDP_TX     3
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP  6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP  17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#endif /* __BPF__ */

/* =========================================================================
 * CONSTANTS
 * ========================================================================= */
#define MAGLEV_RING_SIZE    65537   /* Prime number — Katran uses 65537 */
#define MAX_EBPF_WANS       8
#define MAX_STICKY_ENTRIES  16384   /* LRU evicts old flows automatically */

/* Katran-inspired packet flags (mirrors F_SYN_SET, F_RST_SET, F_ICMP) */
#define PKT_FLAG_SYN  (1 << 0)
#define PKT_FLAG_RST  (1 << 1)
#define PKT_FLAG_FIN  (1 << 2)
#define PKT_FLAG_ICMP (1 << 3)

/* =========================================================================
 * DATA STRUCTURES
 * ========================================================================= */

/* 5-Tuple Flow Key — used as LRU sticky session map key */
struct flow_5tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pkt_flags;  /* SYN/RST/FIN/ICMP flags — from Katran pattern */
    uint16_t pad;
};

/* WAN Uplink Backend Entry — synced from userspace wan_manager */
struct bpf_wan_entry {
    uint32_t wan_id;
    uint32_t ifindex;
    uint32_t ip_addr;    /* WAN IP address for SNAT */
    uint32_t gateway;
    uint32_t weight;
    uint32_t is_active;
    uint32_t table_id;
    uint32_t fwmark;     /* Policy routing mark: 0x101..0x108 */
};

/* Per-CPU WAN Telemetry — lockless multi-core stats (Katran pattern) */
struct bpf_wan_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t snat_packets;   /* SNAT rewrites performed */
    uint64_t dropped_packets;
};

/* LRU Session Persistence Entry */
struct bpf_session_val {
    uint32_t wan_idx;
    uint32_t wan_id;
    uint32_t orig_src_ip;    /* Original LAN client IP (before SNAT) */
    uint64_t last_seen_ns;   /* bpf_ktime_get_ns() timestamp */
};

/* VLAN Tag Header */
struct vlan_hdr {
    uint16_t h_vlan_TCI;
    uint16_t h_vlan_encapsulated_proto;
};

#include "xdp_control_map.h"
#include "xdp_flow_debug.h"
#include "xdp_introspection.h"

/* =========================================================================
 * BPF MAPS — Katran-inspired map layout
 * ========================================================================= */

/* 1. Maglev Consistent Hash LUT: slot → wan_idx */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAGLEV_RING_SIZE);
    __type(key, uint32_t);
    __type(value, uint32_t);
} maglev_lut_map SEC(".maps");

/* 2. WAN Backend Metadata Table */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_EBPF_WANS);
    __type(key, uint32_t);
    __type(value, struct bpf_wan_entry);
} wan_table_map SEC(".maps");

/* 3. LRU Session Persistence Map (Katran: per-connection state) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_STICKY_ENTRIES);
    __type(key, struct flow_5tuple);
    __type(value, struct bpf_session_val);
} sticky_flow_map SEC(".maps");

/* 4. Per-CPU Lockless Packet/Byte Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_EBPF_WANS);
    __type(key, uint32_t);
    __type(value, struct bpf_wan_stats);
} wan_percpu_stats_map SEC(".maps");

/* =========================================================================
 * HASH FUNCTION
 * Katran uses murmurhash3 in userspace for Maglev ring generation.
 * In XDP, we use a fast 32-bit finalizer matching the same distribution.
 * ========================================================================= */
static __always_inline uint32_t hash_5tuple(const struct flow_5tuple *key) {
    uint32_t h = key->src_ip ^ key->dst_ip;
    h ^= ((uint32_t)key->src_port << 16) | (uint32_t)key->dst_port;
    h ^= (uint32_t)key->proto;
    /* Wang hash finalizer — avalanche effect */
    h = (h ^ (h >> 16)) * 0x45d9f3bU;
    h = (h ^ (h >> 16)) * 0x45d9f3bU;
    h ^= h >> 16;
    return h;
}

#if defined(__BPF__) || defined(BPF_HELPERS)

/* =========================================================================
 * KATRAN-INSPIRED CHECKSUM HELPERS (from csum_helpers.h)
 * Used after SNAT to update IP header checksum incrementally.
 * ========================================================================= */

/* Fold 64-bit accumulator into 16-bit one's complement checksum */
static __always_inline uint16_t csum_fold_helper(uint64_t csum) {
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

/* Recalculate IPv4 header checksum after SNAT src_ip rewrite */
static __always_inline void update_ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    uint64_t csum = 0;
    uint16_t *p = (uint16_t *)iph;
    /* IHL * 4 bytes = IHL * 2 uint16_t pairs — Verifier: bounded by ihl <= 15 */
    #pragma unroll
    for (int i = 0; i < 10; i++) {  /* Standard IPv4 header = 20 bytes = 10 x uint16_t */
        csum += p[i];
    }
    iph->check = csum_fold_helper(csum);
}

/* =========================================================================
 * KATRAN-INSPIRED MODULAR PACKET PARSERS
 *
 * Key patterns from Katran's pckt_parsing.h:
 *   - calc_offset(): pre-computes layer offsets to avoid repeated parsing
 *   - All parsers use (data + offset > data_end) bounds check pattern
 *   - ICMP error handling: invert src/dst for embedded original packet
 * ========================================================================= */

/* Parse Ethernet + up to 2 VLAN tags (QinQ / 802.1AD) */
static __always_inline int parse_eth(
    void **cur, void *data_end, uint16_t *eth_proto)
{
    struct ethhdr *eth = *cur;
    if ((void *)(eth + 1) > data_end)
        return -1;

    uint16_t proto = eth->h_proto;
    *cur = (void *)(eth + 1);

    /* Katran-style: unroll loop for Verifier predictability */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto == bpf_htons(ETH_P_8021Q) ||
            proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vlan = *cur;
            if ((void *)(vlan + 1) > data_end)
                return -1;
            proto = vlan->h_vlan_encapsulated_proto;
            *cur = (void *)(vlan + 1);
        }
    }

    *eth_proto = proto;
    return 0;
}

/* Parse IPv4 header with strict IHL bounds check (Katran pattern) */
static __always_inline int parse_ipv4(
    void **cur, void *data_end, struct flow_5tuple *flow)
{
    struct iphdr *iph = *cur;
    if ((void *)(iph + 1) > data_end)
        return -1;
    if (iph->version != 4 || iph->ihl < 5)
        return -1;

    /* Strict IHL bounds check — prevents Verifier rejection */
    uint32_t iph_len = (uint32_t)iph->ihl * 4;
    if (((char *)*cur + iph_len) > (char *)data_end)
        return -1;

    flow->src_ip = iph->saddr;
    flow->dst_ip = iph->daddr;
    flow->proto  = iph->protocol;
    *cur = (char *)*cur + iph_len;
    return 0;
}

/* Parse TCP — extract ports and SYN/RST/FIN flags (Katran: F_SYN_SET, F_RST_SET) */
static __always_inline int parse_tcp(
    void **cur, void *data_end, struct flow_5tuple *flow)
{
    struct tcphdr *tcph = *cur;
    if ((void *)(tcph + 1) > data_end)
        return -1;

    flow->src_port = tcph->source;
    flow->dst_port = tcph->dest;

    /* Track session lifecycle flags — mirrors Katran's F_SYN_SET/F_RST_SET */
    flow->pkt_flags = 0;
    if (tcph->syn) flow->pkt_flags |= PKT_FLAG_SYN;
    if (tcph->rst) flow->pkt_flags |= PKT_FLAG_RST;
    if (tcph->fin) flow->pkt_flags |= PKT_FLAG_FIN;
    return 0;
}

/* Parse UDP */
static __always_inline int parse_udp(
    void **cur, void *data_end, struct flow_5tuple *flow)
{
    struct udphdr *udph = *cur;
    if ((void *)(udph + 1) > data_end)
        return -1;

    flow->src_port  = udph->source;
    flow->dst_port  = udph->dest;
    flow->pkt_flags = 0;
    return 0;
}

/* Parse ICMP — use Echo ID as flow identifier (Katran ICMP pattern) */
static __always_inline int parse_icmp(
    void **cur, void *data_end, struct flow_5tuple *flow)
{
    struct icmphdr *icmph = *cur;
    if ((void *)(icmph + 1) > data_end)
        return -1;

    if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
        flow->src_port = icmph->un.echo.id;
        flow->dst_port = icmph->un.echo.sequence;
    } else {
        flow->src_port = 0;
        flow->dst_port = 0;
    }
    flow->pkt_flags = PKT_FLAG_ICMP;
    return 0;
}

/* =========================================================================
 * SNAT MASQUERADING — Egress Multi-WAN specific (NOT in Katran)
 *
 * Katran uses GUE/IPIP encapsulation for datacenter LB.
 * FluxWAN uses SNAT to rewrite src_ip → WAN IP for Egress NAT.
 * The kernel conntrack/netfilter handles reverse SNAT for replies.
 * ========================================================================= */
static __always_inline int apply_snat(
    void *data, void *data_end,
    uint32_t new_src_ip)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;
    if (iph->version != 4 || iph->ihl < 5)
        return -1;

    /* Rewrite source IP → WAN IP */
    iph->saddr = new_src_ip;

    /* Recalculate IP header checksum (Katran: ipv4_csum_inline pattern) */
    update_ip_checksum(iph);

    return 0;
}

/* =========================================================================
 * MAIN XDP FUNCTION: Egress Multi-WAN Router
 *
 * Flow:
 *   ETH → VLAN? → IPv4 → TCP/UDP/ICMP
 *     ↓
 *   Check LRU sticky session map (Katran: per-connection state)
 *     ↓ miss
 *   Maglev Consistent Hash → select WAN (Katran: ring lookup)
 *     ↓
 *   SNAT src_ip → WAN IP (FluxWAN-specific, replaces Katran's GUE encap)
 *     ↓
 *   Update Per-CPU stats (Katran: lockless PERCPU_ARRAY)
 *     ↓
 *   XDP_PASS → kernel routes via fwmark policy routing
 * ========================================================================= */
SEC("xdp")
int xdp_router_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    void *cur      = data;

    /* ── 1. Parse Ethernet + VLAN ───────────────────────────────────────── */
    uint16_t eth_proto = 0;
    if (parse_eth(&cur, data_end, &eth_proto) < 0)
        return XDP_PASS;

    /* Only handle IPv4 — pass ARP, IPv6, PPPoE, etc. to kernel */
    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── 2. Parse IPv4 Header ───────────────────────────────────────────── */
    struct flow_5tuple key = {};
    if (parse_ipv4(&cur, data_end, &key) < 0)
        return XDP_PASS;

    /* ── 3. Parse L4 (TCP / UDP / ICMP) ────────────────────────────────── */
    if (key.proto == IPPROTO_TCP) {
        if (parse_tcp(&cur, data_end, &key) < 0) return XDP_PASS;
    } else if (key.proto == IPPROTO_UDP) {
        if (parse_udp(&cur, data_end, &key) < 0) return XDP_PASS;
    } else if (key.proto == IPPROTO_ICMP) {
        if (parse_icmp(&cur, data_end, &key) < 0) return XDP_PASS;
    } else {
        return XDP_PASS; /* Pass unsupported protocols (e.g. GRE, ESP) */
    }

    /* Read control map config & global statistics */
    struct router_ctrl *ctrl = ctrl_map_get();
    uint32_t debug_enabled = ctrl ? ctrl->debug_enabled : 0;
    uint32_t snat_enabled = ctrl ? ctrl->snat_enabled : 1;
    struct router_global_stats *gstats = global_stats_get();
    uint64_t pkt_len = (uint64_t)((char *)data_end - (char *)data);
    stats_inc_rx(gstats, pkt_len);

    /* ── 4. LRU Sticky Session Lookup (Katran: per-connection persistence) */
    struct bpf_session_val *sticky = bpf_map_lookup_elem(&sticky_flow_map, &key);
    uint32_t target_wan_idx = 0;
    bool need_dispatch = true;
    uint32_t flow_hash = hash_5tuple(&key);

    if (sticky) {
        uint32_t cidx = sticky->wan_idx;
        if (cidx < MAX_EBPF_WANS) {
            struct bpf_wan_entry *ce = bpf_map_lookup_elem(&wan_table_map, &cidx);
            if (ce && ce->is_active && ce->weight > 0) {
                /* RST or FIN → evict session to allow re-routing */
                if (key.pkt_flags & (PKT_FLAG_RST | PKT_FLAG_FIN)) {
                    bpf_map_delete_elem(&sticky_flow_map, &key);
                    stats_inc_session_evict(gstats);
                    flow_debug_emit(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                    key.proto, key.pkt_flags, (uint8_t)cidx,
                                    key.src_ip, ce->ip_addr, flow_hash,
                                    EVT_SESSION_CLOSE, debug_enabled);
                } else {
                    target_wan_idx = cidx;
                    need_dispatch  = false;
                    stats_inc_sticky_hit(gstats);
                    flow_debug_emit(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                    key.proto, key.pkt_flags, (uint8_t)cidx,
                                    key.src_ip, ce->ip_addr, flow_hash,
                                    EVT_STICKY_HIT, debug_enabled);
                }
            }
        }
    }

    /* ── 5. Maglev Consistent Hash Dispatch ────────────────────────────── */
    if (need_dispatch) {
        uint32_t ring_slot = flow_hash % MAGLEV_RING_SIZE;

        uint32_t *picked = bpf_map_lookup_elem(&maglev_lut_map, &ring_slot);
        if (picked && *picked < MAX_EBPF_WANS) {
            target_wan_idx = *picked;
        } else {
            target_wan_idx = flow_hash % MAX_EBPF_WANS;
        }
        stats_inc_maglev(gstats);

        /* Health check — fall back to first healthy WAN (Katran: ch_rings fallback) */
        struct bpf_wan_entry *we = bpf_map_lookup_elem(&wan_table_map, &target_wan_idx);
        if (!we || !we->is_active || we->weight == 0) {
            #pragma unroll
            for (uint32_t i = 0; i < MAX_EBPF_WANS; i++) {
                uint32_t fi = i;
                struct bpf_wan_entry *fe = bpf_map_lookup_elem(&wan_table_map, &fi);
                if (fe && fe->is_active && fe->weight > 0) {
                    target_wan_idx = fi;
                    stats_inc_failover(gstats);
                    flow_debug_emit(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                                    key.proto, key.pkt_flags, (uint8_t)fi,
                                    key.src_ip, fe->ip_addr, flow_hash,
                                    EVT_FAILOVER, debug_enabled);
                    break;
                }
            }
        }

        /* Write new session into LRU map (SYN opens session) */
        if (!(key.pkt_flags & (PKT_FLAG_RST | PKT_FLAG_FIN))) {
            struct bpf_session_val new_sess = {
                .wan_idx     = target_wan_idx,
                .wan_id      = target_wan_idx + 1,
                .orig_src_ip = key.src_ip,
                .last_seen_ns = 0,
            };
            bpf_map_update_elem(&sticky_flow_map, &key, &new_sess, BPF_ANY);
            struct bpf_wan_entry *target_we = bpf_map_lookup_elem(&wan_table_map, &target_wan_idx);
            flow_debug_emit(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                            key.proto, key.pkt_flags, (uint8_t)target_wan_idx,
                            key.src_ip, target_we ? target_we->ip_addr : 0, flow_hash,
                            EVT_NEW_FLOW, debug_enabled);
        }
    }

    /* ── 6. SNAT: Rewrite src_ip → selected WAN IP ──────────────────────
     * This is the critical Egress NAT step that distinguishes FluxWAN
     * from Katran. Katran does GUE/IPIP encapsulation; we do SNAT.
     * The kernel conntrack tracks the SNAT state for reverse translation.
     * ──────────────────────────────────────────────────────────────────── */
    struct bpf_wan_entry *wan = bpf_map_lookup_elem(&wan_table_map, &target_wan_idx);
    if (snat_enabled && wan && wan->is_active && wan->ip_addr != 0) {
        /* Only SNAT if src_ip is a private LAN address (RFC 1918: 10/8, 172.16/12, 192.168/16) */
        uint32_t src = bpf_ntohl(key.src_ip);
        bool is_lan = ((src & 0xFF000000) == 0x0A000000) ||  /* 10.0.0.0/8 */
                      ((src & 0xFFF00000) == 0xAC100000) ||  /* 172.16.0.0/12 */
                      ((src & 0xFFFF0000) == 0xC0A80000);    /* 192.168.0.0/16 */

        if (is_lan) {
            apply_snat(data, data_end, wan->ip_addr);
            stats_inc_snat(gstats);
            flow_debug_emit(key.src_ip, key.dst_ip, key.src_port, key.dst_port,
                            key.proto, key.pkt_flags, (uint8_t)target_wan_idx,
                            key.src_ip, wan->ip_addr, flow_hash,
                            EVT_SNAT_REWRITE, debug_enabled);
        }
    }

    /* ── 7. Per-CPU Stats Update (Katran: lockless PERCPU_ARRAY) ────────── */
    struct bpf_wan_stats *stats = bpf_map_lookup_elem(&wan_percpu_stats_map, &target_wan_idx);
    if (stats) {
        stats->rx_packets++;
        stats->rx_bytes += pkt_len;
        if (wan && wan->is_active && wan->ip_addr != 0)
            stats->snat_packets++;
    }

    /* ── 8. Pass to kernel — policy routing via fwmark handles WAN selection */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
#endif /* __BPF__ */
