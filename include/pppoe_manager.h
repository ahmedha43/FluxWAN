/*
 * FluxWAN PPPoE Session Manager
 * ==============================
 * Real PPPoE client implementation using Linux pppd + rp-pppoe plugin.
 * Manages the full session lifecycle: dial → authenticate → connected → auto-reconnect.
 *
 * Features:
 *  - Launches pppd per session with PAP/CHAP credentials
 *  - Detects assigned IP/gateway after PPP negotiation via /proc/net
 *  - Monitors pppd process health (SIGCHLD / waitpid)
 *  - Auto-reconnects with exponential backoff (15s → 30s → 60s → max 120s)
 *  - Supports N simultaneous PPPoE sessions on the same physical port
 *  - Notifies WAN manager on connect/disconnect events
 */
#pragma once

#include "fluxwan.h"
#include <sys/types.h>

/* ── PPPoE session states ─────────────────────────────────────────── */
typedef enum {
    PPPOE_STATE_IDLE        = 0,   /* Not started */
    PPPOE_STATE_DIALING,           /* pppd process launched, LCP negotiating */
    PPPOE_STATE_AUTH,              /* LCP done, PAP/CHAP auth in progress */
    PPPOE_STATE_CONNECTED,         /* IP assigned, traffic flowing */
    PPPOE_STATE_DISCONNECTED,      /* pppd exited unexpectedly */
    PPPOE_STATE_RECONNECTING,      /* Waiting before next dial attempt */
    PPPOE_STATE_STOPPING,          /* Admin requested shutdown */
} pppoe_state_t;

/* ── Per-session context ──────────────────────────────────────────── */
typedef struct {
    int          wan_index;               /* Index into config->wans[] */
    pppoe_state_t state;

    /* pppd process */
    pid_t        pppd_pid;               /* PID of running pppd, or -1 */
    char         opts_path[64];          /* /tmp/fluxwan_ppp<N>.opts */
    char         pid_file[64];           /* /tmp/fluxwan_ppp<N>.pid  */

    /* Assigned PPP interface & MACVLAN Virtual Interface */
    char         ppp_ifname[16];
    char         macvlan_ifname[16];
    char         virtual_mac[18];

    /* Negotiated address from ISP */
    uint32_t     assigned_ip;            /* Host byte order */
    uint32_t     remote_ip;             /* Peer/gateway IP (host byte order) */
    char         assigned_ip_str[20];
    char         remote_ip_str[20];

    /* Timing */
    uint64_t     dial_start_ms;
    uint64_t     connected_since_ms;
    uint64_t     next_retry_ms;
    uint64_t     last_check_ms;

    /* Backoff: 15 → 30 → 60 → 120 (seconds) */
    uint32_t     backoff_s;
    int          reconnect_attempts;
} pppoe_session_t;

/* ── Manager context ──────────────────────────────────────────────── */
typedef struct {
    pppoe_session_t sessions[MAX_WANS];
    int             active_count;
} pppoe_manager_ctx_t;

/* ── Callback types (called from pppoe_manager_tick) ─────────────── */
typedef void (*pppoe_on_connected_fn)(
    int wan_index,
    const char *ppp_ifname,
    uint32_t local_ip,     /* host byte order */
    uint32_t remote_ip,    /* host byte order (= ISP gateway) */
    void *userdata);

typedef void (*pppoe_on_disconnected_fn)(
    int wan_index,
    const char *ppp_ifname,
    int reconnect_attempt,
    void *userdata);

/* ── Public API ───────────────────────────────────────────────────── */

/** Allocate and zero-init the manager */
pppoe_manager_ctx_t *pppoe_manager_init(void);

/**
 * Start a PPPoE dial session for wan_index.
 * Writes a pppd options file and forks pppd.
 * @return 0 on success, -1 on error (pppd not found, etc.)
 */
int pppoe_session_start(pppoe_manager_ctx_t *pctx, int wan_index,
                        const wan_config_t *wan);

/**
 * Terminate a PPPoE session cleanly (kill pppd, remove opts file).
 */
int pppoe_session_stop(pppoe_manager_ctx_t *pctx, int wan_index);

/**
 * Periodic tick — call every ~500ms from the main event loop.
 * Checks pppd process status, reads assigned IP once connected,
 * fires callbacks, handles auto-reconnect backoff.
 */
void pppoe_manager_tick(pppoe_manager_ctx_t *pctx,
                        fluxwan_config_t *config,
                        pppoe_on_connected_fn    on_connected,
                        pppoe_on_disconnected_fn on_disconnected,
                        void *userdata);

/** Start sessions for all WANs of type WAN_TYPE_PPPOE */
void pppoe_manager_start_all(pppoe_manager_ctx_t *pctx, fluxwan_config_t *config);

/** Stop all sessions and free resources */
void pppoe_manager_destroy(pppoe_manager_ctx_t *pctx);

/** Get human-readable session state string */
const char *pppoe_state_str(pppoe_state_t s);

/** Get session for wan_index (or NULL) */
pppoe_session_t *pppoe_get_session(pppoe_manager_ctx_t *pctx, int wan_index);
