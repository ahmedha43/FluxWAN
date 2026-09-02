/* ===========================================================================
 * FluxWAN — Global BPF Introspection Stats (Katran: introspection.h)
 *
 * Single PERCPU_ARRAY[1] map with global router counters.
 * Userspace (fluxwan-cli stats) reads and aggregates across all CPUs.
 * Separate from per-WAN stats to avoid touching 8 map entries every packet.
 * =========================================================================== */
#pragma once

#include <stdint.h>

/* ── Global Router Statistics (one entry, per-CPU for lockless updates) ───── */
struct router_global_stats {
    uint64_t total_rx_packets;        /* Total packets seen by XDP */
    uint64_t total_rx_bytes;          /* Total bytes processed */
    uint64_t total_snat_rewrites;     /* Total SNAT src_ip rewrites */
    uint64_t total_sticky_hits;       /* LRU session cache hits */
    uint64_t total_maglev_dispatches; /* New flows via Maglev hash */
    uint64_t total_failovers;         /* WAN fallback events */
    uint64_t total_drops;             /* Packets dropped (no healthy WAN) */
    uint64_t total_session_evictions; /* RST/FIN session evictions */
    uint64_t total_hc_probes_rx;      /* Healthcheck reply probes received */
    uint64_t pad[7];                  /* Pad to 128 bytes (2 cache lines) */
};

#if defined(__BPF__) || defined(BPF_HELPERS)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* ── Global Stats Map: PERCPU_ARRAY[1] — lockless multi-core ─────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct router_global_stats);
} global_stats_map SEC(".maps");

/* Inline helpers — called from XDP hot path, zero overhead */
static __always_inline struct router_global_stats *global_stats_get(void) {
    uint32_t key = 0;
    return (struct router_global_stats *)bpf_map_lookup_elem(&global_stats_map, &key);
}

static __always_inline void stats_inc_rx(struct router_global_stats *s, uint64_t bytes) {
    if (!s) return;
    s->total_rx_packets++;
    s->total_rx_bytes += bytes;
}

static __always_inline void stats_inc_snat(struct router_global_stats *s) {
    if (!s) return;
    s->total_snat_rewrites++;
}

static __always_inline void stats_inc_sticky_hit(struct router_global_stats *s) {
    if (!s) return;
    s->total_sticky_hits++;
}

static __always_inline void stats_inc_maglev(struct router_global_stats *s) {
    if (!s) return;
    s->total_maglev_dispatches++;
}

static __always_inline void stats_inc_failover(struct router_global_stats *s) {
    if (!s) return;
    s->total_failovers++;
}

static __always_inline void stats_inc_drop(struct router_global_stats *s) {
    if (!s) return;
    s->total_drops++;
}

static __always_inline void stats_inc_session_evict(struct router_global_stats *s) {
    if (!s) return;
    s->total_session_evictions++;
}

#endif /* __BPF__ */
