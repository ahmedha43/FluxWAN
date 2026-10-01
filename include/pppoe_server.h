/*
 * FluxWAN - High-Performance Multi-WAN Load Balancing OS
 * Broadband Remote Access Server (BRAS) / PPPoE Server Engine
 *
 * Copyright (C) 2026 Ahmed Al-Dulaimi (أحمد الدليمي). All rights reserved.
 * Author: Ahmed Al-Dulaimi (أحمد الدليمي)
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PPPOE_SERVER_H
#define PPPOE_SERVER_H

#include "fluxwan.h"



/* PPPoE Active Live Session */
typedef struct {
    char ifname[32];
    char username[64];
    char ip[32];
    char mac[32];
    uint64_t connect_time;
    uint64_t uptime_sec;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint32_t rx_rate_kbps;
    uint32_t tx_rate_kbps;
    char profile[64];
} pppoe_active_session_t;

typedef struct pppoe_server_ctx pppoe_server_ctx_t;

/**
 * Initialize the Broadband PPPoE Server module
 */
pppoe_server_ctx_t *pppoe_server_init(fluxwan_config_t *config);

/**
 * Destroy the Broadband PPPoE Server module
 */
void pppoe_server_close(pppoe_server_ctx_t *ctx);

/**
 * Start the PPPoE Server daemon (generates options, secrets, and runs pppoe-server)
 */
int pppoe_server_start(pppoe_server_ctx_t *ctx);

/**
 * Stop the PPPoE Server daemon
 */
int pppoe_server_stop(pppoe_server_ctx_t *ctx);

/**
 * Reload credentials / secrets and profiles without dropping server daemon
 */
int pppoe_server_reload(pppoe_server_ctx_t *ctx);

/**
 * Check if the PPPoE Server daemon process is running
 */
bool pppoe_server_is_running(pppoe_server_ctx_t *ctx);

/**
 * Retrieve active live PPPoE client sessions
 */
int pppoe_server_get_sessions(pppoe_server_ctx_t *ctx, pppoe_active_session_t *out_sessions, uint32_t max_sessions, uint32_t *out_count);

/**
 * Disconnect an active PPPoE session by interface name (e.g. "ppp0")
 */
int pppoe_server_disconnect_session(pppoe_server_ctx_t *ctx, const char *ifname);

/**
 * Add or update a user account in config and secrets
 */
int pppoe_server_set_user(pppoe_server_ctx_t *ctx, const pppoe_user_t *user);

/**
 * Delete a user account from config and secrets
 */
int pppoe_server_delete_user(pppoe_server_ctx_t *ctx, const char *username);

/**
 * Add or update a speed profile in config
 */
int pppoe_server_set_profile(pppoe_server_ctx_t *ctx, const pppoe_profile_t *profile);

/**
 * Delete a speed profile from config
 */
int pppoe_server_delete_profile(pppoe_server_ctx_t *ctx, const char *name);

/**
 * Renew subscriber subscription (extends expires_at by additional_days or by profile's validity_days; optionally switches profile)
 */
int pppoe_server_renew_user(pppoe_server_ctx_t *ctx, const char *username, uint32_t additional_days, const char *new_profile);

/**
 * Toggle user enabled/disabled state (disconnects active session immediately if disabled)
 */
int pppoe_server_toggle_user(pppoe_server_ctx_t *ctx, const char *username, bool enable);

/**
 * Periodic tick to check for expired active sessions and disconnect them
 */
void pppoe_server_periodic_tick(pppoe_server_ctx_t *ctx, uint64_t now_ms);

#endif /* PPPOE_SERVER_H */
