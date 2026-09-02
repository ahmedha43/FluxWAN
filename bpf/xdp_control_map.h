/* ===========================================================================
 * FluxWAN — BPF Control Data Map (Katran: control_data_maps.h)
 *
 * Provides atomic config passing from userspace → XDP kernel program.
 * Userspace writes once; XDP reads on every packet path with zero syscalls.
 * =========================================================================== */
#pragma once

#include <stdint.h>

/* ── Router Control Flags (router_ctrl.router_flags bitmask) ─────────────── */
#define CTRL_FLAG_SNAT_ENABLED   (1u << 0) /* Apply SNAT in XDP path */
#define CTRL_FLAG_DEBUG_ENABLED  (1u << 1) /* Emit flow events to ringbuf */
#define CTRL_FLAG_STRICT_LB      (1u << 2) /* Drop if no healthy WAN */
#define CTRL_FLAG_HC_ENABLED     (1u << 3) /* Kernel healthchecker active */
#define CTRL_FLAG_DISPATCHER     (1u << 4) /* Use tail-call dispatcher mode */

/* ── Control Struct (max 64 bytes to fit in one cache line) ──────────────── */
struct router_ctrl {
    uint32_t lan_ip;         /* LAN gateway IP (network byte order) */
    uint32_t active_wans;    /* Number of currently active WANs (0–8) */
    uint32_t snat_enabled;   /* 1 = SNAT rewrites enabled in XDP */
    uint32_t debug_enabled;  /* 1 = emit flow events to ringbuf */
    uint32_t router_flags;   /* CTRL_FLAG_* bitmask */
    uint32_t hc_interval_ms; /* Healthcheck probe interval in ms */
    uint32_t pad[2];         /* Reserved / cache-line alignment */
};

#if defined(__BPF__) || defined(BPF_HELPERS)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* ── Katran-style ctrl_map: ARRAY[1] — single slot holds router config ───── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct router_ctrl);
} ctrl_map SEC(".maps");

/* Inline helper to read router config atomically */
static __always_inline struct router_ctrl *ctrl_map_get(void) {
    uint32_t key = 0;
    return (struct router_ctrl *)bpf_map_lookup_elem(&ctrl_map, &key);
}

#endif /* __BPF__ */
