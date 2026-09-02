#ifndef NETLINK_MANAGER_H
#define NETLINK_MANAGER_H

#include "fluxwan.h"

/**
 * Netlink context handle
 */
typedef struct netlink_ctx netlink_ctx_t;

/**
 * Initialize netlink manager socket
 * @return Allocated netlink context or NULL on error
 */
netlink_ctx_t *netlink_init(void);

/**
 * Destroy netlink context
 */
void netlink_close(netlink_ctx_t *ctx);

/**
 * Get Netlink socket file descriptor for epoll integration
 */
int netlink_get_fd(const netlink_ctx_t *ctx);

/**
 * Add an IP policy rule pointing to a specific routing table.
 * Equivalent to: ip rule add fwmark <mark> table <table_id>
 */
int netlink_add_ip_rule(netlink_ctx_t *ctx, uint32_t fwmark, uint32_t table_id, uint32_t priority);

/**
 * Delete an IP policy rule.
 */
int netlink_del_ip_rule(netlink_ctx_t *ctx, uint32_t fwmark, uint32_t table_id, uint32_t priority);

/**
 * Add a default route to a specific routing table.
 * Equivalent to: ip route add default via <gateway> dev <ifname> table <table_id>
 */
int netlink_add_default_route(netlink_ctx_t *ctx, uint32_t table_id, uint32_t gateway_ip, int ifindex);

/**
 * Delete default route from a specific routing table.
 */
int netlink_del_default_route(netlink_ctx_t *ctx, uint32_t table_id, uint32_t gateway_ip, int ifindex);

/**
 * Set interface IP address and netmask via Netlink.
 */
int netlink_set_interface_ip(netlink_ctx_t *ctx, int ifindex, uint32_t ip_addr, uint32_t netmask);

/**
 * Set interface state UP or DOWN via Netlink.
 */
int netlink_set_interface_state(netlink_ctx_t *ctx, int ifindex, bool up);

/**
 * Process pending Netlink event messages (link UP/DOWN, route changes)
 */
int netlink_process_events(netlink_ctx_t *ctx, fluxwan_config_t *config);

#endif /* NETLINK_MANAGER_H */
