#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include "fluxwan.h"

typedef struct bpf_loader_ctx bpf_loader_ctx_t;

/**
 * Initialize BPF loader and load XDP bytecode.
 * @param bpf_obj_path Path to compiled xdp_router.bpf.o file
 * @return bpf_loader_ctx_t handle or NULL on error
 */
bpf_loader_ctx_t *bpf_loader_init(const char *bpf_obj_path);

/**
 * Cleanup and detach BPF programs.
 */
void bpf_loader_close(bpf_loader_ctx_t *ctx);

/**
 * Attach XDP program to specified interface name
 */
int bpf_loader_attach_xdp(bpf_loader_ctx_t *ctx, const char *ifname);

/**
 * Detach XDP program from interface
 */
int bpf_loader_detach_xdp(bpf_loader_ctx_t *ctx, const char *ifname);

/**
 * Update WAN configuration entry inside BPF map
 */
int bpf_loader_update_wan_map(bpf_loader_ctx_t *ctx, uint32_t wan_idx, const wan_config_t *wan);

/**
 * Update Maglev Consistent Hashing Lookup Table (LUT) inside BPF map
 */
int bpf_loader_update_maglev_lut(bpf_loader_ctx_t *ctx, const uint32_t *lut, uint32_t ring_size);

/**
 * Fetch live packet/byte statistics for a given WAN index from BPF stats map
 */
int bpf_loader_get_wan_stats(bpf_loader_ctx_t *ctx, uint32_t wan_idx, uint64_t *out_rx_bytes, uint64_t *out_rx_pkts);

/**
 * Fetch multi-core Per-CPU statistics for a given WAN index
 */
/**
 * Update Control Plane map (LAN IP, SNAT mode, debug flags)
 */
int bpf_loader_update_ctrl_map(bpf_loader_ctx_t *ctx, uint32_t lan_ip,
                              uint32_t active_wans, uint32_t snat_enabled,
                              uint32_t debug_enabled);

/**
 * Update Policy Routing Subnet Map in BPF
 */
int bpf_loader_update_policy_routes(bpf_loader_ctx_t *ctx, const policy_route_t *routes, uint32_t count);

/**
 * Update WAN Group Maglev Ring in BPF
 */
int bpf_loader_update_group_maglev_lut(bpf_loader_ctx_t *ctx, uint32_t group_id, const uint32_t *lut, uint32_t ring_size);

/**
 * Fetch aggregated global router statistics across all CPU cores
 */
int bpf_loader_get_global_stats(bpf_loader_ctx_t *ctx, void *out_stats);

#endif /* BPF_LOADER_H */
