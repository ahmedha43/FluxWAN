#ifndef PROXY_MANAGER_H
#define PROXY_MANAGER_H

#include "fluxwan.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct proxy_manager_ctx proxy_manager_ctx_t;

/**
 * Initialize Proxy Manager Subsystem
 */
proxy_manager_ctx_t *proxy_manager_init(fluxwan_config_t *config);

/**
 * Destroy Proxy Manager Subsystem and terminate all running proxy daemons
 */
void proxy_manager_close(proxy_manager_ctx_t *ctx);

/**
 * Apply proxy configuration for all WAN interfaces:
 * Spawns/updates proxy daemons for enabled proxy WANs, stops disabled ones.
 */
int proxy_manager_apply(proxy_manager_ctx_t *ctx);

/**
 * Start or reload proxy daemon for a specific WAN index
 */
int proxy_manager_start_wan(proxy_manager_ctx_t *ctx, uint32_t wan_idx);

/**
 * Stop proxy daemon for a specific WAN index
 */
int proxy_manager_stop_wan(proxy_manager_ctx_t *ctx, uint32_t wan_idx);

/**
 * Parse standard proxy URI link (vless://, vmess://, trojan://, ss://)
 * Extracts server, port, uuid, sni, host, path, transport, security.
 */
int proxy_manager_parse_uri(const char *uri, wan_proxy_config_t *out_proxy);

/**
 * Probe / Test proxy tunnel latency through the TUN device or directly
 */
int proxy_manager_test_tunnel(const wan_proxy_config_t *proxy, uint32_t *out_latency_ms);

/**
 * Periodic tick (check daemon health, restart if crashed, update status)
 */
void proxy_manager_tick(proxy_manager_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* PROXY_MANAGER_H */
