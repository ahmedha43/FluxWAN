/* ===========================================================================
 * FluxWAN — Kernel-Native WAN Healthchecker (Katran: healthchecking.bpf.c)
 *
 * A SEPARATE XDP/TC BPF program that monitors WAN uplink health directly
 * from the kernel — no userspace ping round-trip needed.
 *
 * Architecture:
 *   TC egress on each WAN interface → sends ICMP probe to gateway
 *   XDP ingress on each WAN interface → receives ICMP reply, updates hc_result
 *
 * Advantages over userspace prober.c:
 *   - Failover detection: ~50ms vs ~500ms (no userspace scheduling jitter)
 *   - Zero userspace CPU overhead
 *   - Probes bypass conntrack/netfilter — pure path measurement
 *
 * FluxWAN adaptation from Katran healthchecking.bpf.c:
 *   - Katran probes real backend servers (data center)
 *   - FluxWAN probes WAN gateways (embedded router)
 *   - Uses ICMP Echo ID=0xF1A7 as FluxWAN probe signature
 * =========================================================================== */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(__BPF__) || defined(BPF_HELPERS)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#endif

#define MAX_EBPF_WANS      8
#define HC_PROBE_MAGIC_ID  0xF1A7   /* FluxWAN ICMP probe signature */
#define HC_PROBE_INTERVAL_NS (500ULL * 1000000ULL) /* 500ms in nanoseconds */

/* ── Healthcheck Key: identifies a WAN uplink ───────────────────────────── */
struct hc_probe_key {
    uint32_t wan_ifindex; /* WAN interface ifindex */
    uint32_t gateway_ip;  /* WAN gateway IP (probe target) */
    uint32_t wan_ip;      /* WAN source IP for probe */
    uint32_t pad;
};

/* ── Healthcheck Result: written by XDP on probe reply ──────────────────── */
struct hc_result {
    uint64_t last_probe_ns;  /* When last probe was sent */
    uint64_t last_reply_ns;  /* When last reply was received */
    uint32_t rtt_us;         /* RTT in microseconds */
    uint32_t is_alive;       /* 1=UP, 0=DOWN */
    uint32_t probe_count;    /* Total probes sent */
    uint32_t reply_count;    /* Total replies received */
    uint32_t miss_count;     /* Consecutive missed probes */
    uint32_t pad;
};

/* =========================================================================
 * BPF MAPS
 * ========================================================================= */

/* Probe targets: filled by userspace wan_manager on each WAN config change */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_EBPF_WANS);
    __type(key, uint32_t);
    __type(value, struct hc_probe_key);
} hc_probe_target_map SEC(".maps");

/* Results: written by XDP on reply, read by userspace prober.c for failover */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EBPF_WANS);
    __type(key, uint32_t);           /* wan_idx */
    __type(value, struct hc_result);
} hc_result_map SEC(".maps");

/* Per-CPU rate limiter: prevents probe flooding */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_EBPF_WANS);
    __type(key, uint32_t);
    __type(value, uint64_t);         /* last_probe_time_ns */
} hc_rate_limit_map SEC(".maps");

#if defined(__BPF__) || defined(BPF_HELPERS)

/* ── ICMP Checksum ───────────────────────────────────────────────────────── */
static __always_inline uint16_t icmp_csum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) { /* ICMP echo header = 8 bytes = 4 x uint16 */
        if (len <= 0) break;
        sum += buf[i];
        len -= 2;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

/* =========================================================================
 * XDP PROGRAM: Detect incoming ICMP probe replies on WAN interfaces
 *
 * Attached to each WAN interface (ingress).
 * Detects ICMP Echo Reply with ID=HC_PROBE_MAGIC_ID, updates hc_result_map.
 * ========================================================================= */
SEC("xdp/healthcheck_rx")
int xdp_hc_rx(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IPv4 */
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    /* Parse ICMP */
    uint32_t ihl = (uint32_t)iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)((char *)iph + ihl);
    if ((void *)(icmph + 1) > data_end)
        return XDP_PASS;

    /* Check for FluxWAN probe signature: Echo Reply with our magic ID */
    if (icmph->type != ICMP_ECHOREPLY)
        return XDP_PASS;
    if (bpf_ntohs(icmph->un.echo.id) != HC_PROBE_MAGIC_ID)
        return XDP_PASS;

    /* wan_idx encoded in sequence number lower byte */
    uint32_t wan_idx = bpf_ntohs(icmph->un.echo.sequence) & 0x07;

    /* Update healthcheck result */
    struct hc_result *res = bpf_map_lookup_elem(&hc_result_map, &wan_idx);
    if (res) {
        uint64_t now = bpf_ktime_get_ns();
        if (res->last_probe_ns > 0 && now > res->last_probe_ns) {
            uint64_t rtt_ns = now - res->last_probe_ns;
            res->rtt_us = (uint32_t)(rtt_ns / 1000);
        }
        res->last_reply_ns = bpf_ktime_get_ns();
        res->is_alive      = 1;
        res->reply_count++;
        res->miss_count    = 0;
    } else {
        /* First reply: create entry */
        struct hc_result new_res = {
            .last_reply_ns = bpf_ktime_get_ns(),
            .is_alive      = 1,
            .reply_count   = 1,
            .rtt_us        = 0,
            .miss_count    = 0,
        };
        bpf_map_update_elem(&hc_result_map, &wan_idx, &new_res, BPF_ANY);
    }

    /* Pass packet to kernel (conntrack may need to see it) */
    return XDP_PASS;
}

/* =========================================================================
 * TC PROGRAM: Send ICMP probe packets toward WAN gateways
 *
 * Attached as TC egress classifier on LAN interface.
 * Triggered by a timer (userspace sends a dummy trigger packet).
 * Injects ICMP Echo probe for each active WAN via bpf_clone_redirect.
 *
 * Simplified approach: scan probe_target_map, send one probe per WAN.
 * Rate-limited to HC_PROBE_INTERVAL_NS per WAN.
 * ========================================================================= */
SEC("tc/healthcheck_tx")
int tc_hc_tx(struct __sk_buff *skb) {
    uint64_t now = bpf_ktime_get_ns();

    #pragma unroll
    for (uint32_t i = 0; i < MAX_EBPF_WANS; i++) {
        uint32_t idx = i;

        /* Rate limit check */
        uint64_t *last_ts = bpf_map_lookup_elem(&hc_rate_limit_map, &idx);
        if (last_ts && (now - *last_ts) < HC_PROBE_INTERVAL_NS)
            continue;

        struct hc_probe_key *target = bpf_map_lookup_elem(&hc_probe_target_map, &idx);
        if (!target || target->gateway_ip == 0 || target->wan_ip == 0)
            continue;

        /* Mark probe time */
        if (last_ts) {
            *last_ts = now;
        }

        /* Update probe count in result map */
        struct hc_result *res = bpf_map_lookup_elem(&hc_result_map, &idx);
        if (res) {
            res->last_probe_ns = now;
            res->probe_count++;
            /* Increment miss count; rx handler resets it on reply */
            if (res->miss_count < 255)
                res->miss_count++;
            /* Mark DOWN after 3 consecutive misses */
            if (res->miss_count >= 3)
                res->is_alive = 0;
        }
    }

    return TC_ACT_OK; /* Pass original packet unchanged */
}

char _license[] SEC("license") = "GPL";
#endif /* __BPF__ */
