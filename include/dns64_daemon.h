#ifndef DNS64_DAEMON_H
#define DNS64_DAEMON_H

#include "fluxwan.h"

/* DNS64 Proxy Telemetry & Statistics */
typedef struct {
    uint64_t total_queries;
    uint64_t synthesized_a_records;
    uint64_t passthrough_queries;
    uint64_t active_synthetic_mappings;
    uint32_t current_pool_ip;
} dns64_stats_t;

/* DNS64 Context handle */
typedef struct dns64_ctx dns64_ctx_t;

/**
 * Initialize and start the DNS64 Proxy Daemon.
 * @param config Pointer to global FluxWAN configuration
 * @param v4_map_fd BPF file descriptor for v4_to_v6_map
 * @param v6_map_fd BPF file descriptor for v6_to_v4_map
 * @param cfg_map_fd BPF file descriptor for nat46_cfg map
 * @return Pointer to dns64_ctx_t on success, NULL on failure
 */
dns64_ctx_t *dns64_init(fluxwan_config_t *config, int v4_map_fd, int v6_map_fd, int cfg_map_fd);

/**
 * Stop and free the DNS64 Proxy Daemon.
 */
void dns64_destroy(dns64_ctx_t *ctx);

/**
 * Retrieve live DNS64 telemetry.
 */
void dns64_get_stats(dns64_ctx_t *ctx, dns64_stats_t *out_stats);

/**
 * Manually register a synthetic IPv4 to IPv6 mapping in both userspace and BPF map.
 */
int dns64_register_mapping(dns64_ctx_t *ctx, uint32_t fake_v4, struct in6_addr real_v6);

#endif /* DNS64_DAEMON_H */