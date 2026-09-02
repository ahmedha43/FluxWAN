/* ===========================================================================
 * FluxWAN — Flow Debug RingBuffer (Katran: flow_debug.h + introspection.h)
 *
 * Uses BPF_MAP_TYPE_RINGBUF to stream live flow events from XDP → userspace.
 * Zero-copy: events are reserved in kernel ringbuf, userspace polls via epoll.
 * Replaces userspace logging with kernel-native per-packet observability.
 * =========================================================================== */
#pragma once

#if defined(__BPF__) || defined(__bpf__)
#include <linux/types.h>
#ifndef _BPF_INT_TYPES_
#define _BPF_INT_TYPES_
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#endif
#else
#include <stdint.h>
#endif

#define FLOW_DEBUG_RINGBUF_SIZE  (256 * 1024) /* 256 KB ring — Katran default */
#define MAX_EVENT_SIZE           128          /* Katran: MAX_EVENT_SIZE = 128 */
#define WAN_NAME_LEN             16

/* ── Event Types (maps to router pipeline stages) ────────────────────────── */
#define EVT_NEW_FLOW      0  /* New flow dispatched via Maglev */
#define EVT_STICKY_HIT    1  /* Existing session found in LRU map */
#define EVT_SNAT_REWRITE  2  /* SNAT src_ip → WAN IP applied */
#define EVT_FAILOVER      3  /* Primary WAN down, switched to fallback */
#define EVT_SESSION_CLOSE 4  /* RST/FIN: session evicted from LRU */
#define EVT_DROP          5  /* Packet dropped (no healthy WAN) */
#define EVT_HC_REPLY      6  /* Healthcheck probe reply received */

/* ── Flow Debug Event Structure (≤ MAX_EVENT_SIZE = 128 bytes) ────────────── */
struct flow_debug_event {
    uint64_t timestamp_ns;   /* bpf_ktime_get_ns() at event time */
    uint32_t src_ip;         /* Original source IP (LAN client) */
    uint32_t dst_ip;         /* Destination IP */
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;          /* IPPROTO_TCP / UDP / ICMP */
    uint8_t  wan_idx;        /* Selected WAN index (0–7) */
    uint8_t  event_type;     /* EVT_* constants */
    uint8_t  pkt_flags;      /* PKT_FLAG_SYN/RST/FIN */
    uint32_t orig_src_ip;    /* LAN IP before SNAT */
    uint32_t wan_ip;         /* WAN IP after SNAT */
    uint32_t flow_hash;      /* Maglev hash value for this flow */
    char     wan_name[WAN_NAME_LEN]; /* Human-readable WAN name */
    uint8_t  pad[8];         /* Pad to 64 bytes total */
} __attribute__((packed));

/* Verify size constraint at compile time */
_Static_assert(sizeof(struct flow_debug_event) <= MAX_EVENT_SIZE,
               "flow_debug_event exceeds MAX_EVENT_SIZE");

#if defined(__BPF__) || defined(BPF_HELPERS)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* ── RingBuffer Map — Katran: flow_debug_maps.h pattern ─────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, FLOW_DEBUG_RINGBUF_SIZE);
} flow_ringbuf SEC(".maps");

/* ── Emit a debug event to the ringbuf (zero-copy, non-blocking) ──────────
 * Only emits when debug_enabled flag is set in ctrl_map.
 * Uses bpf_ringbuf_reserve/submit — never blocks, drops if full.
 * Inspired by Katran's KATRAN_INTROSPECTION macro pattern.
 * ─────────────────────────────────────────────────────────────────────────── */
static __always_inline void flow_debug_emit(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t proto, uint8_t pkt_flags,
    uint8_t wan_idx, uint32_t orig_src_ip, uint32_t wan_ip,
    uint32_t flow_hash, uint8_t event_type,
    uint32_t debug_enabled)
{
    if (!debug_enabled)
        return;

    struct flow_debug_event *evt = bpf_ringbuf_reserve(
        &flow_ringbuf, sizeof(struct flow_debug_event), 0);
    if (!evt)
        return; /* ringbuf full — drop silently, never block XDP path */

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip       = src_ip;
    evt->dst_ip       = dst_ip;
    evt->src_port     = src_port;
    evt->dst_port     = dst_port;
    evt->proto        = proto;
    evt->wan_idx      = wan_idx;
    evt->event_type   = event_type;
    evt->pkt_flags    = pkt_flags;
    evt->orig_src_ip  = orig_src_ip;
    evt->wan_ip       = wan_ip;
    evt->flow_hash    = flow_hash;

    /* wan_name filled by userspace via separate lookup */
    evt->wan_name[0] = 'W';
    evt->wan_name[1] = 'A';
    evt->wan_name[2] = 'N';
    evt->wan_name[3] = '0' + (wan_idx & 7);
    evt->wan_name[4] = '\0';

    bpf_ringbuf_submit(evt, 0);
}

#endif /* __BPF__ */
