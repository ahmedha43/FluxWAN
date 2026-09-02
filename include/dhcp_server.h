#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

#include "fluxwan.h"

#define MAX_DHCP_LEASES 254

typedef struct {
    uint32_t ip_addr;
    uint8_t mac_addr[6];
    char mac_str[18];
    char hostname[64];
    uint64_t lease_start_sec;
    uint64_t lease_expire_sec;
    bool is_active;
} dhcp_lease_t;

typedef struct dhcp_server_ctx dhcp_server_ctx_t;

/**
 * Initialize embedded lightweight RFC 2131 DHCP Server on LAN interface
 */
dhcp_server_ctx_t *dhcp_server_init(const fluxwan_config_t *config);

/**
 * Destroy DHCP Server
 */
void dhcp_server_close(dhcp_server_ctx_t *ctx);

/**
 * Get DHCP UDP socket file descriptor for epoll integration
 */
socket_t dhcp_server_get_fd(const dhcp_server_ctx_t *ctx);

/**
 * Process pending incoming DHCP message (DISCOVER / REQUEST / RELEASE)
 */
int dhcp_server_process(dhcp_server_ctx_t *ctx);

/**
 * Get active client lease count and array
 */
uint32_t dhcp_server_get_leases(const dhcp_server_ctx_t *ctx, dhcp_lease_t *out_leases, uint32_t max_count);

#endif /* DHCP_SERVER_H */
