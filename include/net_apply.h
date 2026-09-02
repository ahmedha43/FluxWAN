#ifndef NET_APPLY_H
#define NET_APPLY_H

#include "fluxwan.h"
#include "netlink_manager.h"

/**
 * Apply the full network configuration to the Linux Kernel.
 * - Enables kernel IPv4 forwarding (/proc/sys/net/ipv4/ip_forward = 1)
 * - Configures LAN interface IP and brings it UP via Netlink
 * - Configures all assigned WAN interfaces (Static/DHCP/PPPoE)
 * - Provisions Policy Routing Tables (Tables 101..108) with default routes
 * - Sets up NAT/Masquerade firewall rules
 */
int net_apply_configuration(const fluxwan_config_t *config, netlink_ctx_t *nl);

/**
 * Enable or disable Linux Kernel IPv4 packet forwarding
 */
int net_apply_set_ip_forward(bool enable);

/**
 * Enable NAT/Masquerade for a specific WAN interface
 */
int net_apply_wan_nat(const char *wan_ifname, bool enable);

#endif /* NET_APPLY_H */
