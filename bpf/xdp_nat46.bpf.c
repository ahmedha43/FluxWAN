// SPDX-License-Identifier: GPL-2.0
/* ==========================================================================
 * FluxWAN - High Performance Stateless NAT46 / SIIT Translation Engine
 * Translates IPv4 synthetic traffic to Native IPv6 for Starlink CGNAT Bypass
 * ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "nat46_maps.h"

/* Forward Map: Synthetic IPv4 -> Real IPv6 Target */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                      /* Synthetic IPv4 (Network Byte Order) */
    __type(value, struct nat46_forward_val); /* Real Destination IPv6 + Client IP */
    __uint(max_entries, 65536);
} v4_to_v6_map SEC(".maps");

/* Reverse Map: Real IPv6 Source -> Synthetic IPv4 & Client IPv4 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);            /* Real Server IPv6 */
    __type(value, struct nat46_reverse_val); /* Synthetic IPv4 + Client IPv4 */
    __uint(max_entries, 65536);
} v6_to_v4_map SEC(".maps");

/* Global Configuration Map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct nat46_config);
    __uint(max_entries, 1);
} nat46_cfg SEC(".maps");

/* Helper function to calculate standard IPv4 16-bit 1's complement header checksum */
static __always_inline __u16 calc_ip_csum(struct iphdr *iph) {
    __u16 *buf = (__u16 *)iph;
    __u32 csum = 0;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        csum += *buf++;
    }
    
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
        
    return ~((__u16)csum);
}

SEC("xdp")
int xdp_nat46_handler(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 zero = 0;
    struct nat46_config *cfg = bpf_map_lookup_elem(&nat46_cfg, &zero);
    if (!cfg || !cfg->enabled)
        return XDP_PASS;

    /* =========================================================================
     * PATH 1: EGRESS (Subscriber IPv4 -> Synthetic IP -> Starlink Native IPv6)
     * ========================================================================= */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        /* Check if destination IP falls within Synthetic Pool (198.18.0.0/15) */
        __u32 dst_ip_host = bpf_ntohl(iph->daddr);
        if ((dst_ip_host & SYNTH_IPV4_MASK) == SYNTH_IPV4_NET) {
            struct nat46_forward_val *fwd = bpf_map_lookup_elem(&v4_to_v6_map, &iph->daddr);
            if (!fwd)
                return XDP_PASS;

            /* Save packet metadata before memory restructuring */
            __u32 client_ip = iph->saddr;
            __u32 synth_ip  = iph->daddr;
            __u16 tot_len   = bpf_ntohs(iph->tot_len);
            __u8  ihl_bytes = iph->ihl * 4;
            if (tot_len < ihl_bytes)
                return XDP_PASS;

            __u16 payload_len = tot_len - ihl_bytes;
            __u8 proto = iph->protocol;
            struct in6_addr target_v6 = fwd->target_v6;

            /* Expand packet head: IPv6 Header (40B) - IPv4 Header (20B) = 20 Bytes */
            int adjust = -(int)(sizeof(struct ipv6hdr) - sizeof(struct iphdr));
            if (bpf_xdp_adjust_head(ctx, adjust))
                return XDP_DROP;

            /* Re-validate pointers after head adjustment */
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end)
                return XDP_DROP;

            struct ipv6hdr *ip6h = (void *)(eth + 1);
            if ((void *)(ip6h + 1) > data_end)
                return XDP_DROP;

            /* Populate IPv6 Header */
            ip6h->version = 6;
            ip6h->priority = 0;
            ip6h->flow_lbl[0] = 0;
            ip6h->flow_lbl[1] = 0;
            ip6h->flow_lbl[2] = 0;
            ip6h->payload_len = bpf_htons(payload_len);
            ip6h->nexthdr = proto;
            ip6h->hop_limit = 64;
            ip6h->saddr = cfg->router_v6_src;
            ip6h->daddr = target_v6;

            /* Rewrite Ethernet Header */
            eth->h_proto = bpf_htons(ETH_P_IPV6);
            __builtin_memcpy(eth->h_dest, cfg->starlink_gw_mac, 6);

            /* Update Reverse Mapping for Incoming Responses */
            struct nat46_reverse_val rev_entry;
            rev_entry.synthetic_v4 = synth_ip;
            rev_entry.client_v4    = client_ip;
            rev_entry.last_seen_sec = 0;
            bpf_map_update_elem(&v6_to_v4_map, &target_v6, &rev_entry, BPF_ANY);

            __sync_fetch_and_add(&cfg->total_translated_egress, 1);

            /* Forward packet directly into Starlink WAN interface */
            return bpf_redirect(cfg->starlink_ifindex, 0);
        }
    }

    /* =========================================================================
     * PATH 2: INGRESS (Starlink Native IPv6 Response -> Translated to IPv4)
     * ========================================================================= */
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        /* Check if incoming IPv6 packet source exists in reverse translation map */
        struct nat46_reverse_val *rev = bpf_map_lookup_elem(&v6_to_v4_map, &ip6h->saddr);
        if (rev) {
            __u16 payload_len = bpf_ntohs(ip6h->payload_len);
            __u8  proto = ip6h->nexthdr;
            __u32 synth_ip = rev->synthetic_v4;
            __u32 client_ip = rev->client_v4;

            /* Shrink packet head: IPv6 (40B) -> IPv4 (20B) = +20 Bytes */
            int adjust = (int)(sizeof(struct ipv6hdr) - sizeof(struct iphdr));
            if (bpf_xdp_adjust_head(ctx, adjust))
                return XDP_DROP;

            /* Re-validate pointers */
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end)
                return XDP_DROP;

            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end)
                return XDP_DROP;

            /* Populate IPv4 Header */
            iph->version  = 4;
            iph->ihl      = 5;
            iph->tos      = 0;
            iph->tot_len  = bpf_htons(payload_len + sizeof(struct iphdr));
            iph->id       = 0;
            iph->frag_off = bpf_htons(IP_DF);
            iph->ttl      = 64;
            iph->protocol = proto;
            iph->check    = 0;
            iph->saddr    = synth_ip;
            iph->daddr    = client_ip;
            iph->check    = calc_ip_csum(iph);

            /* Rewrite Ethernet Header to LAN client */
            eth->h_proto = bpf_htons(ETH_P_IP);
            __builtin_memcpy(eth->h_dest, cfg->lan_gw_mac, 6);

            __sync_fetch_and_add(&cfg->total_translated_ingress, 1);

            /* Forward packet directly into LAN interface */
            return bpf_redirect(cfg->lan_ifindex, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";