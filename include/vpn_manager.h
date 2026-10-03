/*
 * FluxWAN - High-Performance Multi-WAN Load Balancing OS
 *
 * Copyright (C) 2026 Ahmed Al-Dulaimi (أحمد الدليمي). All rights reserved.
 * Author: Ahmed Al-Dulaimi (أحمد الدليمي)
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VPN_MANAGER_H
#define VPN_MANAGER_H

#include "fluxwan.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize VPN Manager and directory structures */
int vpn_manager_init(vpn_config_t *vpn);

/* Apply both WireGuard and ZeroTier configurations to the system */
int vpn_manager_apply(const vpn_config_t *vpn);

/* WireGuard operations */
int vpn_manager_apply_wireguard(const wireguard_config_t *wg);
int vpn_manager_add_wg_peer(wireguard_config_t *wg, const wireguard_peer_t *peer);
int vpn_manager_delete_wg_peer(wireguard_config_t *wg, const char *public_key);
int vpn_manager_gen_wg_keypair(char *out_priv, size_t priv_sz, char *out_pub, size_t pub_sz);
int vpn_manager_generate_client_conf(const wireguard_config_t *wg, const wireguard_peer_t *peer,
                                     const char *client_priv, const char *server_endpoint,
                                     char *out_conf, size_t max_len);

/* ZeroTier operations */
int vpn_manager_apply_zerotier(const zerotier_config_t *zt);
int vpn_manager_zt_join(zerotier_config_t *zt, const char *nwid, const char *name);
int vpn_manager_zt_leave(zerotier_config_t *zt, const char *nwid);
int vpn_manager_zt_refresh_node_id(zerotier_config_t *zt);

/* Real-time status sync & JSON telemetry */
int vpn_manager_sync_status(vpn_config_t *vpn);
int vpn_manager_build_json_status(const vpn_config_t *vpn, char *out_json, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* VPN_MANAGER_H */
