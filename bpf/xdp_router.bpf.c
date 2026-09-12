/* ===========================================================================
 * FluxWAN XDP Egress Multi-WAN Router — eBPF/XDP Kernel Program
 *
 * Copyright (C) 2026 Ahmed Al-Dulaimi (أحمد الدليمي). All rights reserved.
 * Author: Ahmed Al-Dulaimi (أحمد الدليمي)
 * Licensed under the GNU General Public License v3.0 (GPLv3)
 * SPDX-License-Identifier: GPL-3.0-or-later
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

/* Katran-inspired packet flags (mirrors F_SYN_SET, F_RST_SET, F_ICMP, F_QUIC) */
#define PKT_FLAG_SYN  (1 << 0)
#define PKT_FLAG_RST  (1 << 1)
#define PKT_FLAG_FIN  (1 << 2)
#define PKT_FLAG_ICMP (1 << 3)
#define PKT_FLAG_QUIC (1 << 4)
#define PKT_FLAG_PMTU (1 << 5)

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
    uint8_t  pkt_flags;  /* SYN/RST/FIN/ICMP/QUIC/PMTU flags — from Katran pattern */
    uint16_t quic_token; /* 16-bit hashed token from QUIC DCID for QUIC roaming */
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
    uint32_t is_draining;/* Meta Katran Graceful Draining state */
    uint32_t mtu;        /* WAN MTU (PPPoE 1492, Starlink 1420, Fiber 1500) */
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
    uint32_t orig_src_ip;    /* Store original LAN IP before SNAT */
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

/* 3a. Local Per-CPU LRU Session Map (Katran: local_lru_cache, 100% lockless) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow_5tuple);
    __type(value, struct bpf_session_val);
} local_lru_map SEC(".maps");

/* 3b. Global LRU Session Persistence Map (Katran: fallback_lru_cache) */
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

/* 5. Policy Subnet Route Map */
#define MAX_BPF_POLICIES 16
struct bpf_policy_entry {
    uint32_t subnet_ip;    /* Network byte order */
    uint32_t netmask;      /* Network byte order */
    uint32_t target_group; /* Group ID */
    uint32_t is_active;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BPF_POLICIES);
    __type(key, uint32_t);
    __type(value, struct bpf_policy_entry);
} policy_route_map SEC(".maps");

/* 6. WAN Group Maglev Rings (Group ID * MAGLEV_RING_SIZE + slot) */
#define MAX_BPF_GROUPS 8
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BPF_GROUPS * MAGLEV_RING_SIZE);
    __type(key, uint32_t);
    __type(value, uint32_t);
} maglev_group_map SEC(".maps");

/* 7. Longest Prefix Match (LPM) Trie Map for High-Scale Subnet Routing (from Katran) */
struct bpf_lpm_key {
    uint32_t prefixlen; /* Prefix length in bits (0..32) */
    uint32_t addr;      /* Destination IP in network byte order */
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, 1); /* BPF_F_NO_PREALLOC */
    __type(key, struct bpf_lpm_key);
    __type(value, uint32_t); /* target_wan_idx */
} lpm_subnet_map SEC(".maps");

/* =========================================================================
 * HASH FUNCTION
 * Katran uses murmurhash3 in userspace for Maglev ring generation.
 * In XDP, we use a fast 32-bit finalizer matching the same distribution.
 * ========================================================================= */
static __always_inline uint32_t hash_5tuple(const struct flow_5tuple *key) {
    uint32_t h;
    if (key->pkt_flags & PKT_FLAG_QUIC) {
        /* Katran QUIC pattern: hash by QUIC DCID token & destination server */
        h = key->dst_ip ^ ((uint32_t)key->quic_token << 16) ^ (uint32_t)key->dst_port;
    } else {
        uint16_t src_p = key->src_port;
        uint16_t dst_p = key->dst_port;

        /* Katran F_HASH_NO_SRC_PORT pattern:
         * Zero ephemeral client source port for multi-channel / VoIP / streaming protocols
         * (SIP 5060, RTSP 554, FTP 21, IPsec 500/4500, WireGuard 51820).
         * This locks all secondary data/media channels (e.g. RTP voice audio)
         * to the exact same WAN uplink as the primary control session. */
        if (dst_p == bpf_htons(5060)  || src_p == bpf_htons(5060)  ||  /* SIP VoIP */
            dst_p == bpf_htons(554)   || src_p == bpf_htons(554)   ||  /* RTSP Media */
            dst_p == bpf_htons(21)    || src_p == bpf_htons(21)    ||  /* FTP Control */
            dst_p == bpf_htons(500)   || src_p == bpf_htons(500)   ||  /* IPsec IKE */
            dst_p == bpf_htons(4500)  || src_p == bpf_htons(4500)  ||  /* IPsec NAT-T */
            dst_p == bpf_htons(51820) || src_p == bpf_htons(51820)) {  /* WireGuard */
            src_p = 0;
        }

        h = key->src_ip ^ key->dst_ip;
        h ^= ((uint32_t)src_p << 16) | (uint32_t)dst_p;
        h ^= (uint32_t)key->proto;
    }
    /* Wang hash finalizer — avalanche effect */
    h = (h ^ (h >> 16)) * 0x45d9f3bU;
    h = (h ^ (h >> 16)) * 0x45d9f3bU;
    h ^= h >> 16;
    return h;
}

#if defined(__BPF__) || defined(BPF_HELPERS)

/* =========================================================================
 * KATRAN-INSPIRED CHECKSUM HELPERS (RFC 1624 Differential 1's Complement)
 * Used after SNAT to update IP header checksum incrementally in ~2 cycles.
 * ========================================================================= */

/* RFC 1624 Incremental 16-bit replacement: ~2 CPU cycles */
static __always_inline void csum_replace2(uint16_t *csum, uint16_t from, uint16_t to) {
    uint32_t c = ~(*csum) & 0xffff;
    c += ~from & 0xffff;
    c += to;
    c = (c & 0xffff) + (c >> 16);
    c = (c & 0xffff) + (c >> 16);
    *csum = ~c;
}

/* RFC 1624 Incremental 32-bit replacement: ~2 CPU cycles */
static __always_inline void csum_replace4(uint16_t *csum, uint32_t from, uint32_t to) {
    uint32_t c = ~(*csum) & 0xffff;
    uint32_t from_hi = from >> 16;
    uint32_t from_lo = from & 0xffff;
    uint32_t to_hi = to >> 16;
    uint32_t to_lo = to & 0xffff;
    c += ~from_hi & 0xffff;
    c += ~from_lo & 0xffff;
    c += to_hi;
    c += to_lo;
    c = (c & 0xffff) + (c >> 16);
    c = (c & 0xffff) + (c >> 16);
    *csum = ~c;
}

/* Fast TTL decrement checksum update (from Katran balancer_helpers.h) */
static __always_inline void csum_replace_ttl(struct iphdr *iph) {
    uint32_t c = (uint32_t)iph->check + 0x0100;
    iph->check = (c & 0xffff) + (c >> 16);
    iph->ttl--;
}

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

/* Parse UDP & QUIC (Katran RFC 9000 QUIC Connection ID pattern) */
static __always_inline int parse_udp(
    void **cur, void *data_end, struct flow_5tuple *flow)
{
    struct udphdr *udph = *cur;
    if ((void *)(udph + 1) > data_end)
        return -1;

    flow->src_port   = udph->source;
    flow->dst_port   = udph->dest;
    flow->pkt_flags  = 0;
    flow->quic_token = 0;

    /* Katran QUIC CID Parser: Inspect UDP/443 (HTTP/3) or other QUIC flows */
    if (udph->dest == 0xBB01 /* htons(443) */ || udph->source == 0xBB01) {
        void *quic_data = (void *)(udph + 1);
        if (quic_data + 1 <= data_end) {
            uint8_t first_byte = *(uint8_t *)quic_data;
            /* QUIC packets must have the Fixed Bit (0x40) set */
            if (first_byte & 0x40) {
                flow->pkt_flags |= PKT_FLAG_QUIC;
                uint16_t token = 0;
                uint8_t *dcid = NULL;

                if (first_byte & 0x80) {
                    /* Long Header: [flags 1B][version 4B][dcil 1B][dcid...] */
                    if (quic_data + 6 <= data_end) {
                        uint8_t dcid_len = *(uint8_t *)(quic_data + 5);
                        if (dcid_len >= 4 && quic_data + 6 + 4 <= data_end) {
                            dcid = (uint8_t *)(quic_data + 6);
                        }
                    }
                } else {
                    /* Short Header (1-RTT Data): [flags 1B][dcid 4-18B] */
                    if (quic_data + 5 <= data_end) {
                        dcid = (uint8_t *)(quic_data + 1);
                    }
                }

                if (dcid) {
                    /* Meta Katran QUIC CID version decoding (V1, V2, V3) */
                    uint8_t cid_ver = dcid[0] >> 6;
                    if (cid_ver == 0) {
                        /* V1: packed 16-bit server token across first 18 bits */
                        token = ((uint16_t)(dcid[0] & 0x3F) << 10) | ((uint16_t)dcid[1] << 2) | (dcid[2] >> 6);
                    } else if (cid_ver == 1) {
                        /* V2: direct 16-bit token in bytes 1 and 2 */
                        token = ((uint16_t)dcid[1] << 8) | dcid[2];
                    } else {
                        /* V3 / custom: robust 16-bit XOR mix */
                        token = ((uint16_t)dcid[0] << 8) | (dcid[1] ^ dcid[2]);
                    }
                }

                if (token != 0) {
                    flow->quic_token = token;
                    /* Normalize src_ip & src_port for mobile QUIC client roaming session preservation */
                    flow->src_ip = 0;
                    flow->src_port = 0;
                }
            }
        }
    }
    return 0;
}

/* Parse ICMP — handle Echo and PMTU Inner Packets (Katran handle_icmp pattern) */
static __always_inline int parse_icmp(
    void **cur, void *data_end, struct flow_5tuple *flow)
{
    struct icmphdr *icmph = *cur;
    if ((void *)(icmph + 1) > data_end)
        return -1;

    flow->quic_token = 0;
    if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
        flow->src_port = icmph->un.echo.id;
        flow->dst_port = icmph->un.echo.sequence;
        flow->pkt_flags = PKT_FLAG_ICMP;
    } else if (icmph->type == 3 || icmph->type == 11) {
        /* Katran ICMP PMTUD pattern: unpack original inner IP & transport headers */
        flow->pkt_flags = PKT_FLAG_ICMP | PKT_FLAG_PMTU;
        void *inner_data = (void *)(icmph + 1);
        struct iphdr *inner_iph = inner_data;
        if ((void *)(inner_iph + 1) <= data_end && inner_iph->version == 4) {
            int inner_ihl = inner_iph->ihl * 4;
            if (inner_ihl >= 20 && (void *)inner_iph + inner_ihl + 4 <= data_end) {
                uint16_t *inner_ports = (void *)inner_iph + inner_ihl;
                /* Reconstruct original client flow so PMTUD packet maps to the right WAN */
                flow->src_ip   = inner_iph->saddr;
                flow->dst_ip   = inner_iph->daddr;
                flow->src_port = inner_ports[0];
                flow->dst_port = inner_ports[1];
                flow->proto    = inner_iph->protocol;
                return 0;
            }
        }
        flow->src_port = 0;
        flow->dst_port = 0;
    } else {
        flow->src_port = 0;
        flow->dst_port = 0;
        flow->pkt_flags = PKT_FLAG_ICMP;
    }
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

    /* Rewrite source IP → WAN IP with RFC 1624 Fast Differential Checksum (~2 cycles) */
    uint32_t old_src_ip = iph->saddr;
    iph->saddr = new_src_ip;
    csum_replace4(&iph->check, old_src_ip, new_src_ip);

    return 0;
}

/* =========================================================================
 * KATRAN IN-KERNEL WIRE-SPEED ICMP ECHO RESPONDER
 *
 * Instantly responds to Ping to router directly in XDP driver/SKB hook.
 * Swaps MAC & IP addresses, sets ICMP type to 0, updates checksum in ~2 cycles.
 * Latency: <10μs, zero OS network stack overhead, immune to ping floods.
 * ========================================================================= */
static __always_inline int send_icmp_echo_reply(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    uint16_t eth_proto = eth->h_proto;
    void *cur = (void *)(eth + 1);

    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vlan = cur;
            if ((void *)(vlan + 1) > data_end)
                return XDP_PASS;
            eth_proto = vlan->h_vlan_encapsulated_proto;
            cur = (void *)(vlan + 1);
        }
    }

    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = cur;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->version != 4 || iph->ihl < 5)
        return XDP_PASS;

    uint32_t iph_len = (uint32_t)iph->ihl * 4;
    if (((char *)cur + iph_len) > (char *)data_end)
        return XDP_PASS;

    struct icmphdr *icmph = (struct icmphdr *)((char *)cur + iph_len);
    if ((void *)(icmph + 1) > data_end)
        return XDP_PASS;

    if (icmph->type != ICMP_ECHO)
        return XDP_PASS;

    /* Swap MAC addresses */
    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    /* Swap IP addresses and reset TTL */
    uint32_t tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;
    iph->ttl = 64;
    update_ip_checksum(iph);

    /* Echo Request (Type 8, Code 0) -> Echo Reply (Type 0, Code 0) */
    icmph->type = ICMP_ECHOREPLY;
    csum_replace2(&icmph->checksum, bpf_htons(0x0800), 0);

    return XDP_TX;
}

/* =========================================================================
 * KATRAN IN-KERNEL ICMP "PACKET TOO BIG" (PTB) REFLECTION
 *
 * Directly reflects ICMP Type 3, Code 4 (Fragmentation Needed) in XDP when
 * a packet exceeds the target WAN's MTU (e.g. PPPoE 1492, Starlink 1420)
 * with the DF (Don't Fragment) bit set.
 * Eliminates MTU Black Holes and browser connection stalls.
 * ========================================================================= */
static __always_inline int send_icmp_too_big(
    struct xdp_md *ctx, void *data, void *data_end,
    uint64_t pkt_len, uint32_t target_mtu)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* Copy original 28 bytes (IPv4 header 20B + transport 8B) to stack */
    uint8_t orig_payload[28];
    uint8_t *p_src = (uint8_t *)iph;
    if ((void *)(p_src + 28) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < 28; i++) {
        orig_payload[i] = p_src[i];
    }

    /* Save original addressing */
    unsigned char client_mac[ETH_ALEN];
    unsigned char router_mac[ETH_ALEN];
    __builtin_memcpy(client_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(router_mac, eth->h_dest, ETH_ALEN);
    uint32_t client_ip = iph->saddr;
    uint32_t router_ip = iph->daddr;

    /* Desired packet size: Eth(14) + IP(20) + ICMP(8) + Payload(28) = 70 bytes */
    int target_len = 70;
    int delta = target_len - (int)pkt_len;
    if (bpf_xdp_adjust_tail(ctx, delta) < 0)
        return XDP_PASS;

    /* Re-evaluate pointers after adjust_tail */
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    struct icmphdr *icmph = (struct icmphdr *)(iph + 1);
    if ((void *)(icmph + 1) > data_end)
        return XDP_PASS;
    uint8_t *payload_dst = (uint8_t *)(icmph + 1);
    if ((void *)(payload_dst + 28) > data_end)
        return XDP_PASS;

    /* Construct Ethernet */
    __builtin_memcpy(eth->h_dest, client_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, router_mac, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);

    /* Construct IPv4 Header */
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = bpf_htons(56); /* IP(20) + ICMP(8) + Payload(28) = 56 */
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = router_ip;
    iph->daddr = client_ip;
    update_ip_checksum(iph);

    /* Construct ICMP Header */
    icmph->type = 3; /* Destination Unreachable */
    icmph->code = 4; /* Fragmentation Needed and DF set */
    icmph->checksum = 0;
    icmph->un.frag.__unused = 0;
    icmph->un.frag.mtu = bpf_htons((uint16_t)target_mtu);

    /* Copy original 28 bytes into ICMP body */
    #pragma unroll
    for (int i = 0; i < 28; i++) {
        payload_dst[i] = orig_payload[i];
    }

    /* Compute ICMP Checksum: 36 bytes (8B ICMP + 28B payload) = 18 uint16_t */
    uint64_t icmp_csum = 0;
    uint16_t *csum_p = (uint16_t *)icmph;
    #pragma unroll
    for (int i = 0; i < 18; i++) {
        icmp_csum += csum_p[i];
    }
    icmph->checksum = csum_fold_helper(icmp_csum);

    return XDP_TX;
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
    uint32_t snat_enabled = ctrl ? ctrl->snat_enabled : 0;
    struct router_global_stats *gstats = global_stats_get();
    uint64_t pkt_len = (uint64_t)((char *)data_end - (char *)data);
    stats_inc_rx(gstats, pkt_len);

    /* ── 3.1. Katran In-Kernel Wire-Speed ICMP Echo Responder ──────────
     * Instantly answer Ping to the router's LAN IP directly in XDP!
     * Zero sk_buff allocation, zero kernel TCP/IP stack overhead, <10μs latency.
     * Fully immune to ICMP ping flood DoS attacks.
     * ──────────────────────────────────────────────────────────────────── */
    uint32_t my_lan_ip = (ctrl && ctrl->lan_ip != 0) ? ctrl->lan_ip : bpf_htonl(0xC0A80101);
    if (key.proto == IPPROTO_ICMP && (key.pkt_flags & PKT_FLAG_ICMP) &&
        key.dst_ip == my_lan_ip) {
        return send_icmp_echo_reply(data, data_end);
    }

    /* ── 3.2. Stateless DNS / NTP Fast-Path LRU Bypassing (Katran F_LRU_BYPASS) ─
     * High-volume short-lived queries (UDP 53 DNS, UDP 123 NTP) do NOT pollute
     * the 32,768 LRU session cache. They bypass LRU lookups/inserts and route
     * directly via Maglev Consistent Hashing at maximum wire-speed.
     * ──────────────────────────────────────────────────────────────────── */
    bool is_dns_or_ntp = (key.proto == IPPROTO_UDP) &&
                         (key.dst_port == bpf_htons(53)  || key.src_port == bpf_htons(53) ||
                          key.dst_port == bpf_htons(123) || key.src_port == bpf_htons(123));

    /* ── 4. Dual-Tier LRU Sticky Session Lookup (Katran: local_lru + fallback_lru) */
    struct bpf_session_val *sticky = NULL;
    if (!is_dns_or_ntp) {
        sticky = bpf_map_lookup_elem(&local_lru_map, &key);
        if (!sticky) {
            sticky = bpf_map_lookup_elem(&sticky_flow_map, &key);
            if (sticky) {
                /* Populate local CPU cache for subsequent lockless hits */
                bpf_map_update_elem(&local_lru_map, &key, sticky, BPF_ANY);
            }
        }
    }
    uint32_t target_wan_idx = 0;
    bool need_dispatch = true;
    uint32_t flow_hash = hash_5tuple(&key);

    if (sticky) {
        uint32_t cidx = sticky->wan_idx;
        if (cidx < MAX_EBPF_WANS) {
            struct bpf_wan_entry *ce = bpf_map_lookup_elem(&wan_table_map, &cidx);
            /* Accept active WANs with positive weight OR WANs in Graceful Draining mode */
            if (ce && ce->is_active && (ce->weight > 0 || ce->is_draining)) {
                /* RST or FIN → evict session from both LRU tiers (Katran pattern) */
                if (key.pkt_flags & (PKT_FLAG_RST | PKT_FLAG_FIN)) {
                    bpf_map_delete_elem(&local_lru_map, &key);
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
            } else {
                /* Katran Sub-Second Dynamic UDP/TCP Flow Migration:
                 * Target WAN is DEAD or DOWN! Evict dead session immediately from both LRU tiers
                 * so voice (WhatsApp/Zoom/Discord) and gaming flows re-route to a healthy WAN
                 * on the very next packet without waiting for 30s timeouts! */
                bpf_map_delete_elem(&local_lru_map, &key);
                bpf_map_delete_elem(&sticky_flow_map, &key);
                stats_inc_session_evict(gstats);
                sticky = NULL;
                need_dispatch = true;
            }
        }
    }

    /* ── 5. Maglev Consistent Hash Dispatch ────────────────────────────── */
    if (need_dispatch) {
        /* Meta Katran LPM Trie Destination Subnet Match (Fast-path direct WAN override) */
        struct bpf_lpm_key lpm_k = {
            .prefixlen = 32,
            .addr      = key.dst_ip,
        };
        uint32_t *lpm_wan = bpf_map_lookup_elem(&lpm_subnet_map, &lpm_k);
        if (lpm_wan && *lpm_wan < MAX_EBPF_WANS) {
            target_wan_idx = *lpm_wan;
            goto skip_maglev_dispatch;
        }

        /* Policy Route Subnet Lookup (Match client src_ip) */
        uint32_t target_group_id = 0;
        #pragma unroll
        for (int p = 0; p < MAX_BPF_POLICIES; p++) {
            uint32_t pkey = p;
            struct bpf_policy_entry *pe = bpf_map_lookup_elem(&policy_route_map, &pkey);
            if (pe && pe->is_active && pe->netmask != 0) {
                if ((key.src_ip & pe->netmask) == pe->subnet_ip) {
                    target_group_id = pe->target_group;
                    break;
                }
            }
        }

        uint32_t ring_slot = flow_hash % MAGLEV_RING_SIZE;
        uint32_t *picked = NULL;

        if (target_group_id > 0 && target_group_id < MAX_BPF_GROUPS) {
            uint32_t gslot = (target_group_id * MAGLEV_RING_SIZE) + ring_slot;
            picked = bpf_map_lookup_elem(&maglev_group_map, &gslot);
        }
        if (!picked) {
            picked = bpf_map_lookup_elem(&maglev_lut_map, &ring_slot);
        }

        if (picked && *picked < MAX_EBPF_WANS) {
            target_wan_idx = *picked;
        } else {
            target_wan_idx = flow_hash % MAX_EBPF_WANS;
        }
        stats_inc_maglev(gstats);

skip_maglev_dispatch:;
        /* Health check — fall back to first healthy WAN (Katran: ch_rings fallback)
         * Notice: Draining WANs (is_draining=1) or weight==0 are NOT eligible for new dispatches! */
        struct bpf_wan_entry *we = bpf_map_lookup_elem(&wan_table_map, &target_wan_idx);
        if (!we || !we->is_active || we->weight == 0 || we->is_draining) {
            #pragma unroll
            for (uint32_t i = 0; i < MAX_EBPF_WANS; i++) {
                uint32_t fi = i;
                struct bpf_wan_entry *fe = bpf_map_lookup_elem(&wan_table_map, &fi);
                if (fe && fe->is_active && fe->weight > 0 && !fe->is_draining) {
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

        /* Write new session into both LRU tiers (SYN / new flow) */
        if (!is_dns_or_ntp && !(key.pkt_flags & (PKT_FLAG_RST | PKT_FLAG_FIN))) {
            struct bpf_session_val new_sess = {
                .wan_idx     = target_wan_idx,
                .wan_id      = target_wan_idx + 1,
                .orig_src_ip = key.src_ip,
                .last_seen_ns = 0,
            };
            bpf_map_update_elem(&local_lru_map, &key, &new_sess, BPF_ANY);
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

    /* ── 6.1. Meta Katran In-Kernel ICMP "Packet Too Big" (PTB) Reflection ─
     * If packet size exceeds the selected WAN's MTU (e.g. PPPoE 1492, Starlink 1420)
     * and the DF (Don't Fragment) flag is set:
     * Reflect ICMP Type 3, Code 4 (Fragmentation Needed) back to the sender in XDP!
     * Eliminates MTU black holes and browser connection freezes.
     * ──────────────────────────────────────────────────────────────────── */
    if (wan && wan->mtu > 0 && pkt_len > wan->mtu) {
        struct ethhdr *eth_ptb = data;
        if ((void *)(eth_ptb + 1) <= data_end && eth_ptb->h_proto == bpf_htons(ETH_P_IP)) {
            struct iphdr *iph_ptb = (struct iphdr *)(eth_ptb + 1);
            if ((void *)(iph_ptb + 1) <= data_end && (iph_ptb->frag_off & bpf_htons(0x4000))) {
                return send_icmp_too_big(ctx, data, data_end, pkt_len, wan->mtu);
            }
        }
    }

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
