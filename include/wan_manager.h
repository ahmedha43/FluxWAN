#ifndef WAN_MANAGER_H
#define WAN_MANAGER_H

#include "fluxwan.h"
#include "netlink_manager.h"
#include "bpf_loader.h"

typedef struct wan_manager_ctx wan_manager_ctx_t;

/**
 * Initialize WAN Manager
 */
wan_manager_ctx_t *wan_manager_init(fluxwan_config_t *config, netlink_ctx_t *nl, bpf_loader_ctx_t *bpf);

/**
 * Destroy WAN Manager
 */
void wan_manager_close(wan_manager_ctx_t *ctx);

/**
 * Handle WAN health state updates from Prober
 */
void wan_manager_on_health_update(uint32_t wan_idx, wan_state_t state, const wan_metrics_t *metrics, void *user_data);

/**
 * Recalculate dynamic weights and trigger failover if needed
 */
int wan_manager_rebalance(wan_manager_ctx_t *ctx);

/**
 * Periodic tick for WAN DHCP lease checks and PPPoE reconnects
 */
void wan_manager_periodic_tick(wan_manager_ctx_t *ctx, uint64_t now_ms);

/**
 * Record a system event log
 */
void wan_manager_add_log(const char *level, const char *fmt, ...);

/**
 * Fetch latest system logs
 */
uint32_t wan_manager_get_logs(system_log_entry_t *out_logs, uint32_t max_count);

#endif /* WAN_MANAGER_H */
