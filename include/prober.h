#ifndef PROBER_H
#define PROBER_H

#include "fluxwan.h"

typedef struct prober_ctx prober_ctx_t;

/* Callback function type invoked when WAN metrics or health state changes */
typedef void (*wan_health_callback_t)(uint32_t wan_idx, wan_state_t new_state, const wan_metrics_t *metrics, void *user_data);

/**
 * Initialize Health Prober Engine
 * @param config Pointer to global fluxwan_config_t
 * @param cb Callback function for state change notifications
 * @param user_data Opaque pointer passed to callback
 * @return prober_ctx_t handle or NULL on error
 */
prober_ctx_t *prober_init(fluxwan_config_t *config, wan_health_callback_t cb, void *user_data);

/**
 * Destroy Prober Engine
 */
void prober_close(prober_ctx_t *ctx);

/**
 * Get Prober RAW ICMP socket file descriptor for epoll loop
 */
int prober_get_fd(const prober_ctx_t *ctx);

/**
 * Trigger send of ICMP probes across all active WAN interfaces
 */
int prober_send_probes(prober_ctx_t *ctx);

/**
 * Process incoming ICMP Echo responses from RAW socket
 */
int prober_process_responses(prober_ctx_t *ctx);

#endif /* PROBER_H */
