/* ===========================================================================
 * FluxWAN — XDP Tail-Call Dispatcher (Katran: xdp_root.c pattern)
 *
 * Implements Katran's modular dispatcher architecture using BPF tail calls.
 * Each pipeline stage is a separate XDP program chained via PROG_ARRAY.
 *
 * Benefits over monolithic xdp_router.bpf.c:
 *   - Each stage can be updated/reloaded independently (no full restart)
 *   - Easier Verifier path — smaller programs = faster verification
 *   - Cleaner separation of concerns
 *   - Future stages can be inserted without touching existing code
 *
 * Pipeline:
 *   [LAN ingress] → xdp_dispatcher → xdp_classifier → xdp_lb →
 *                   xdp_snat → xdp_stats → XDP_PASS
 *
 * Usage: Load xdp_dispatcher.bpf.o and populate xdp_progs PROG_ARRAY
 *        with the FDs of classifier/lb/snat/stats programs.
 *        OR use the standalone xdp_router.bpf.o for simpler deployments.
 *
 * Note: Both dispatcher and standalone router can coexist in the binary.
 *       Choose at runtime via bpf_loader_attach_xdp() mode parameter.
 * =========================================================================== */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(__BPF__) || defined(BPF_HELPERS)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#endif

#define MAX_EBPF_WANS      8
#define MAGLEV_RING_SIZE   65537
#define MAX_STICKY_ENTRIES 16384

/* Dispatcher program indices in xdp_progs array */
#define PROG_CLASSIFIER 0
#define PROG_LB         1
#define PROG_SNAT       2
#define PROG_STATS      3

/* ── Per-packet context passed between tail-called programs ──────────────
 * Since tail calls reset the stack, we use a PERCPU_ARRAY as "call stack".
 * Each CPU has exactly one slot — safe since XDP is non-preemptible.
 * ─────────────────────────────────────────────────────────────────────── */
struct xdp_pkt_ctx {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pkt_flags;       /* PKT_FLAG_SYN/RST/FIN */
    uint8_t  stage;           /* Current pipeline stage */
    uint8_t  is_lan_src;      /* 1 if src is private LAN address */
    uint32_t target_wan_idx;  /* Selected WAN index */
    uint32_t wan_ip;          /* WAN IP for SNAT */
    uint32_t flow_hash;       /* Hash for Maglev lookup */
    uint32_t pad;
};

/* Packet flags (mirrors xdp_router.bpf.c) */
#define PKT_FLAG_SYN  (1 << 0)
#define PKT_FLAG_RST  (1 << 1)
#define PKT_FLAG_FIN  (1 << 2)
#define PKT_FLAG_ICMP (1 << 3)

/* WAN entry structure */
struct bpf_wan_entry {
    uint32_t wan_id;
    uint32_t ifindex;
    uint32_t ip_addr;
    uint32_t gateway;
    uint32_t weight;
    uint32_t is_active;
    uint32_t table_id;
    uint32_t fwmark;
};

/* Per-CPU stats */
struct bpf_wan_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t snat_packets;
    uint64_t dropped_packets;
};

/* Session value */
struct bpf_session_val {
    uint32_t wan_idx;
    uint32_t wan_id;
    uint32_t orig_src_ip;
    uint64_t last_seen_ns;
};

/* 5-tuple key */
struct flow_5tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pkt_flags;
    uint16_t pad;
};

/* VLAN header */
struct vlan_hdr {
    uint16_t h_vlan_TCI;
    uint16_t h_vlan_encapsulated_proto;
};

/* =========================================================================
 * BPF MAPS
 * ========================================================================= */

/* Katran xdp_root.c: PROG_ARRAY for tail call chaining */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, uint32_t);
    __type(value, uint32_t);
} xdp_progs SEC(".maps");

/* Per-CPU packet context scratch space */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct xdp_pkt_ctx);
} pkt_ctx_map SEC(".maps");

/* Shared maps (same as xdp_router.bpf.c — pinned to /sys/fs/bpf/fluxwan/) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAGLEV_RING_SIZE);
    __type(key, uint32_t);
    __type(value, uint32_t);
} maglev_lut_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_EBPF_WANS);
    __type(key, uint32_t);
    __type(value, struct bpf_wan_entry);
} wan_table_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_STICKY_ENTRIES);
    __type(key, struct flow_5tuple);
    __type(value, struct bpf_session_val);
} sticky_flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_EBPF_WANS);
    __type(key, uint32_t);
    __type(value, struct bpf_wan_stats);
} wan_percpu_stats_map SEC(".maps");

#if defined(__BPF__) || defined(BPF_HELPERS)

/* ── Hash function (same as xdp_router.bpf.c) ───────────────────────────── */
static __always_inline uint32_t hash_5tuple_ctx(const struct xdp_pkt_ctx *c) {
    uint32_t h = c->src_ip ^ c->dst_ip;
    h ^= ((uint32_t)c->src_port << 16) | (uint32_t)c->dst_port;
    h ^= (uint32_t)c->proto;
    h = (h ^ (h >> 16)) * 0x45d9f3bU;
    h = (h ^ (h >> 16)) * 0x45d9f3bU;
    h ^= h >> 16;
    return h;
}

/* IP checksum update */
static __always_inline uint16_t csum_fold(uint64_t csum) {
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

/* =========================================================================
 * STAGE 0 — Dispatcher Entry Point (Katran: xdp_root.c)
 * Initializes per-CPU packet context, tail-calls classifier.
 * ========================================================================= */
SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx) {
    uint32_t key = 0;
    struct xdp_pkt_ctx *pctx = bpf_map_lookup_elem(&pkt_ctx_map, &key);
    if (!pctx)
        return XDP_PASS;

    /* Zero the context for this packet */
    pctx->stage          = 0;
    pctx->target_wan_idx = 0;
    pctx->wan_ip         = 0;
    pctx->flow_hash      = 0;
    pctx->pkt_flags      = 0;
    pctx->is_lan_src     = 0;

    /* Tail call to classifier (stage 0) */
    bpf_tail_call(ctx, &xdp_progs, PROG_CLASSIFIER);
    return XDP_PASS; /* tail call failed — pass to kernel */
}

/* =========================================================================
 * STAGE 1 — Packet Classifier (parse headers, extract 5-tuple)
 * ========================================================================= */
SEC("xdp/classifier")
int xdp_classifier(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *cur      = data;

    uint32_t key = 0;
    struct xdp_pkt_ctx *pctx = bpf_map_lookup_elem(&pkt_ctx_map, &key);
    if (!pctx) return XDP_PASS;

    /* Parse Ethernet + optional VLAN */
    struct ethhdr *eth = cur;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    uint16_t proto = eth->h_proto;
    cur = eth + 1;

    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto == bpf_htons(0x8100) || proto == bpf_htons(0x88A8)) {
            struct vlan_hdr *v = cur;
            if ((void *)(v + 1) > data_end) return XDP_PASS;
            proto = v->h_vlan_encapsulated_proto;
            cur = v + 1;
        }
    }

    if (proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    /* Parse IPv4 */
    struct iphdr *iph = cur;
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->version != 4 || iph->ihl < 5) return XDP_PASS;
    uint32_t ihl = (uint32_t)iph->ihl * 4;
    if (((char *)cur + ihl) > (char *)data_end) return XDP_PASS;

    pctx->src_ip = iph->saddr;
    pctx->dst_ip = iph->daddr;
    pctx->proto  = iph->protocol;
    cur = (char *)cur + ihl;

    /* Parse L4 */
    if (pctx->proto == IPPROTO_TCP) {
        struct tcphdr *t = cur;
        if ((void *)(t + 1) > data_end) return XDP_PASS;
        pctx->src_port  = t->source;
        pctx->dst_port  = t->dest;
        pctx->pkt_flags = (t->syn ? PKT_FLAG_SYN : 0) |
                          (t->rst ? PKT_FLAG_RST : 0) |
                          (t->fin ? PKT_FLAG_FIN : 0);
    } else if (pctx->proto == IPPROTO_UDP) {
        struct udphdr *u = cur;
        if ((void *)(u + 1) > data_end) return XDP_PASS;
        pctx->src_port  = u->source;
        pctx->dst_port  = u->dest;
        pctx->pkt_flags = 0;
    } else if (pctx->proto == IPPROTO_ICMP) {
        struct icmphdr *ic = cur;
        if ((void *)(ic + 1) > data_end) return XDP_PASS;
        pctx->src_port  = ic->un.echo.id;
        pctx->dst_port  = ic->un.echo.sequence;
        pctx->pkt_flags = PKT_FLAG_ICMP;
    } else {
        return XDP_PASS;
    }

    /* LAN source detection (RFC 1918: 10/8, 172.16/12, 192.168/16) */
    uint32_t src = bpf_ntohl(pctx->src_ip);
    pctx->is_lan_src = (uint8_t)(
        ((src & 0xFF000000) == 0x0A000000) ||
        ((src & 0xFFF00000) == 0xAC100000) ||
        ((src & 0xFFFF0000) == 0xC0A80000));

    pctx->flow_hash = hash_5tuple_ctx(pctx);
    pctx->stage = 1;

    bpf_tail_call(ctx, &xdp_progs, PROG_LB);
    return XDP_PASS;
}

/* =========================================================================
 * STAGE 2 — Load Balancer (Maglev + LRU sticky sessions)
 * ========================================================================= */
SEC("xdp/lb")
int xdp_lb(struct xdp_md *ctx) {
    uint32_t key = 0;
    struct xdp_pkt_ctx *pctx = bpf_map_lookup_elem(&pkt_ctx_map, &key);
    if (!pctx) return XDP_PASS;

    /* Build 5-tuple for LRU lookup */
    struct flow_5tuple fkey = {
        .src_ip    = pctx->src_ip,
        .dst_ip    = pctx->dst_ip,
        .src_port  = pctx->src_port,
        .dst_port  = pctx->dst_port,
        .proto     = pctx->proto,
        .pkt_flags = pctx->pkt_flags,
        .pad       = 0,
    };

    uint32_t target = 0;
    bool need_dispatch = true;

    /* LRU sticky session lookup */
    struct bpf_session_val *sticky = bpf_map_lookup_elem(&sticky_flow_map, &fkey);
    if (sticky && sticky->wan_idx < MAX_EBPF_WANS) {
        uint32_t cidx = sticky->wan_idx;
        struct bpf_wan_entry *we = bpf_map_lookup_elem(&wan_table_map, &cidx);
        if (we && we->is_active && we->weight > 0) {
            if (pctx->pkt_flags & (PKT_FLAG_RST | PKT_FLAG_FIN)) {
                bpf_map_delete_elem(&sticky_flow_map, &fkey);
            } else {
                target = cidx;
                need_dispatch = false;
            }
        }
    }

    /* Maglev hash dispatch */
    if (need_dispatch) {
        uint32_t slot = pctx->flow_hash % MAGLEV_RING_SIZE;
        uint32_t *picked = bpf_map_lookup_elem(&maglev_lut_map, &slot);
        target = (picked && *picked < MAX_EBPF_WANS) ? *picked :
                 (pctx->flow_hash % MAX_EBPF_WANS);

        /* Health fallback */
        struct bpf_wan_entry *we = bpf_map_lookup_elem(&wan_table_map, &target);
        if (!we || !we->is_active || we->weight == 0) {
            #pragma unroll
            for (uint32_t i = 0; i < MAX_EBPF_WANS; i++) {
                uint32_t fi = i;
                struct bpf_wan_entry *fe = bpf_map_lookup_elem(&wan_table_map, &fi);
                if (fe && fe->is_active && fe->weight > 0) {
                    target = fi;
                    break;
                }
            }
        }

        /* Save session */
        if (!(pctx->pkt_flags & (PKT_FLAG_RST | PKT_FLAG_FIN))) {
            struct bpf_session_val ns = {
                .wan_idx     = target,
                .wan_id      = target + 1,
                .orig_src_ip = pctx->src_ip,
                .last_seen_ns = 0,
            };
            bpf_map_update_elem(&sticky_flow_map, &fkey, &ns, BPF_ANY);
        }
    }

    pctx->target_wan_idx = target;

    /* Get WAN IP for SNAT */
    struct bpf_wan_entry *wan = bpf_map_lookup_elem(&wan_table_map, &target);
    if (wan && wan->is_active)
        pctx->wan_ip = wan->ip_addr;

    pctx->stage = 2;
    bpf_tail_call(ctx, &xdp_progs, PROG_SNAT);
    return XDP_PASS;
}

/* =========================================================================
 * STAGE 3 — SNAT Rewriter
 * ========================================================================= */
SEC("xdp/snat")
int xdp_snat(struct xdp_md *ctx) {
    uint32_t key = 0;
    struct xdp_pkt_ctx *pctx = bpf_map_lookup_elem(&pkt_ctx_map, &key);
    if (!pctx) return XDP_PASS;

    if (pctx->is_lan_src && pctx->wan_ip != 0) {
        void *data     = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) goto out;

        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) goto out;
        if (iph->version != 4 || iph->ihl < 5) goto out;

        /* SNAT: rewrite src_ip → WAN IP */
        iph->saddr = pctx->wan_ip;

        /* Recalculate IP header checksum */
        iph->check = 0;
        uint64_t csum = 0;
        uint16_t *p = (uint16_t *)iph;
        #pragma unroll
        for (int i = 0; i < 10; i++) csum += p[i];
        iph->check = csum_fold(csum);
    }

out:
    pctx->stage = 3;
    bpf_tail_call(ctx, &xdp_progs, PROG_STATS);
    return XDP_PASS;
}

/* =========================================================================
 * STAGE 4 — Stats Collector + Debug Event Emitter
 * ========================================================================= */
SEC("xdp/stats")
int xdp_stats(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    uint32_t key = 0;
    struct xdp_pkt_ctx *pctx = bpf_map_lookup_elem(&pkt_ctx_map, &key);
    if (!pctx) return XDP_PASS;

    uint32_t wan_idx = pctx->target_wan_idx;
    if (wan_idx >= MAX_EBPF_WANS) wan_idx = 0;

    struct bpf_wan_stats *stats = bpf_map_lookup_elem(&wan_percpu_stats_map, &wan_idx);
    if (stats) {
        stats->rx_packets++;
        stats->rx_bytes += (uint64_t)((char *)data_end - (char *)data);
        if (pctx->wan_ip != 0 && pctx->is_lan_src)
            stats->snat_packets++;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
#endif /* __BPF__ */
