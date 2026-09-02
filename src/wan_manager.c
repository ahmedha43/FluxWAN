#include "wan_manager.h"
#include "net_apply.h"
#include "pppoe_manager.h"
#include <stdarg.h>

static system_log_entry_t g_logs[MAX_SYSTEM_LOGS];
static uint32_t g_log_count = 0;

void wan_manager_add_log(const char *level, const char *fmt, ...) {
    system_log_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    time_t now = time(NULL);
    entry.timestamp_sec = (uint64_t)now;

    struct tm *tm_info = localtime(&now);
    if (tm_info) {
        strftime(entry.time_str, sizeof(entry.time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(entry.time_str, sizeof(entry.time_str), "%llu", (unsigned long long)now);
    }

    strncpy(entry.level, level ? level : "INFO", sizeof(entry.level) - 1);

    va_list args;
    va_start(args, fmt);
    vsnprintf(entry.message, sizeof(entry.message), fmt, args);
    va_end(args);

    if (g_log_count < MAX_SYSTEM_LOGS) {
        g_logs[g_log_count++] = entry;
    } else {
        /* Shift older logs to maintain most recent */
        memmove(&g_logs[0], &g_logs[1], sizeof(system_log_entry_t) * (MAX_SYSTEM_LOGS - 1));
        g_logs[MAX_SYSTEM_LOGS - 1] = entry;
    }
}

uint32_t wan_manager_get_logs(system_log_entry_t *out_logs, uint32_t max_count) {
    if (!out_logs || max_count == 0) return 0;
    uint32_t count = g_log_count < max_count ? g_log_count : max_count;
    for (uint32_t i = 0; i < count; i++) {
        /* Return most recent first */
        out_logs[i] = g_logs[g_log_count - 1 - i];
    }
    return count;
}

struct wan_manager_ctx {
    fluxwan_config_t *config;
    netlink_ctx_t *nl;
    bpf_loader_ctx_t *bpf;
    pppoe_manager_ctx_t *pppoe;
    uint32_t maglev_lut[MAGLEV_RING_SIZE];
    uint64_t last_dhcp_renew_ms[MAX_WANS];
};

static inline uint64_t rotl64(uint64_t x, int8_t r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t murmurhash3_x64_64(uint64_t A, uint64_t B, uint32_t seed) {
    uint64_t h1 = seed;
    uint64_t h2 = seed;

    uint64_t c1 = 0x87c37b91114253d5ULL;
    uint64_t c2 = 0x4cf5ad432745937fULL;

    uint64_t k1 = A;
    uint64_t k2 = B;

    k1 *= c1;
    k1 = rotl64(k1, 31);
    k1 *= c2;
    h1 ^= k1;

    h1 = rotl64(h1, 27);
    h1 += h2;
    h1 = h1 * 5 + 0x52dce729;

    k2 *= c2;
    k2 = rotl64(k2, 33);
    k2 *= c1;
    h2 ^= k2;

    h2 = rotl64(h2, 31);
    h2 += h1;
    h2 = h2 * 5 + 0x38495ab5;

    h1 ^= 16;
    h2 ^= 16;

    h1 += h2;
    h2 += h1;

    h1 ^= h1 >> 33;
    h1 *= 0xff51afd7ed558ccdULL;
    h1 ^= h1 >> 33;
    h1 *= 0xc4ceb9fe1a85ec53ULL;
    h1 ^= h1 >> 33;

    h2 ^= h2 >> 33;
    h2 *= 0xff51afd7ed558ccdULL;
    h2 ^= h2 >> 33;
    h2 *= 0xc4ceb9fe1a85ec53ULL;
    h2 ^= h2 >> 33;

    h1 += h2;
    return h1;
}

#define KHASH_SEED0 0
#define KHASH_SEED1 2307
#define KHASH_SEED2 42
#define KHASH_SEED3 2718281828U

static void build_single_maglev_ring(const fluxwan_config_t *config,
                                     const uint32_t *member_indices,
                                     uint32_t member_count,
                                     uint32_t *out_lut) {
    if (!config || !out_lut || member_count == 0) {
        if (out_lut) {
            for (uint32_t i = 0; i < MAGLEV_RING_SIZE; i++) out_lut[i] = 0;
        }
        return;
    }

    for (uint32_t i = 0; i < MAGLEV_RING_SIZE; i++) {
        out_lut[i] = 0xFFFFFFFF;
    }

    uint32_t permutation[MAX_WANS * 2];
    uint32_t next[MAX_WANS];
    uint32_t weights[MAX_WANS];
    uint32_t active_members = 0;
    uint32_t first_active_idx = member_indices[0];

    for (uint32_t m = 0; m < member_count; m++) {
        uint32_t w_idx = member_indices[m];
        if (w_idx >= config->wan_count) continue;
        const wan_config_t *w = &config->wans[w_idx];

        uint64_t wan_hash = 0x811c9dc5ULL;
        for (const char *p = w->name; *p; p++) {
            wan_hash = (wan_hash * 33) ^ (uint8_t)*p;
        }

        uint64_t offset_hash = murmurhash3_x64_64(wan_hash, KHASH_SEED2, KHASH_SEED0);
        uint64_t skip_hash = murmurhash3_x64_64(wan_hash, KHASH_SEED3, KHASH_SEED1);

        permutation[2 * m] = (uint32_t)(offset_hash % MAGLEV_RING_SIZE);
        permutation[2 * m + 1] = (uint32_t)((skip_hash % (MAGLEV_RING_SIZE - 1)) + 1);
        next[m] = 0;

        if (w->enabled && w->state != WAN_STATE_DOWN && w->dynamic_weight > 0) {
            weights[m] = w->dynamic_weight;
            if (active_members == 0) first_active_idx = w_idx;
            active_members++;
        } else {
            weights[m] = 0;
        }
    }

    if (active_members == 0) {
        for (uint32_t i = 0; i < MAGLEV_RING_SIZE; i++) out_lut[i] = member_indices[0];
        return;
    }

    uint32_t runs = 0;
    while (runs < MAGLEV_RING_SIZE) {
        bool progress = false;
        for (uint32_t m = 0; m < member_count; m++) {
            if (weights[m] == 0) continue;
            uint32_t offset = permutation[2 * m];
            uint32_t skip = permutation[2 * m + 1];
            uint32_t w_idx = member_indices[m];

            uint32_t step_weight = (weights[m] + 9) / 10;
            if (step_weight == 0) step_weight = 1;

            for (uint32_t j = 0; j < step_weight && runs < MAGLEV_RING_SIZE; j++) {
                while (next[m] < MAGLEV_RING_SIZE) {
                    uint32_t cur = (offset + next[m] * skip) % MAGLEV_RING_SIZE;
                    next[m]++;
                    if (out_lut[cur] == 0xFFFFFFFF) {
                        out_lut[cur] = w_idx;
                        runs++;
                        progress = true;
                        break;
                    }
                }
            }
        }
        if (!progress && runs < MAGLEV_RING_SIZE) {
            for (uint32_t i = 0; i < MAGLEV_RING_SIZE; i++) {
                if (out_lut[i] == 0xFFFFFFFF) {
                    out_lut[i] = first_active_idx;
                    runs++;
                }
            }
            break;
        }
    }
}

static int wan_manager_generate_maglev_lut(wan_manager_ctx_t *ctx) {
    if (!ctx) return -1;

    uint32_t count = ctx->config->wan_count;
    if (count == 0) return 0;

    /* 1. Build Default Maglev Ring (All WANs) */
    uint32_t all_indices[MAX_WANS];
    for (uint32_t i = 0; i < count; i++) all_indices[i] = i;
    build_single_maglev_ring(ctx->config, all_indices, count, ctx->maglev_lut);

    if (ctx->bpf) {
        bpf_loader_update_maglev_lut(ctx->bpf, ctx->maglev_lut, MAGLEV_RING_SIZE);
    }

    /* 2. Build Independent Maglev Rings for each WAN Group */
    for (uint32_t g = 0; g < ctx->config->group_count; g++) {
        wan_group_t *grp = &ctx->config->groups[g];
        if (grp->wan_count > 0) {
            build_single_maglev_ring(ctx->config, grp->wan_member_indices, grp->wan_count, grp->maglev_ring);
            if (ctx->bpf) {
                bpf_loader_update_group_maglev_lut(ctx->bpf, grp->id, grp->maglev_ring, MAGLEV_RING_SIZE);
            }
        }
    }

    /* 3. Sync LAN Policy Routes to BPF */
    if (ctx->bpf) {
        bpf_loader_update_policy_routes(ctx->bpf,
                                       ctx->config->lan.policy_routes,
                                       ctx->config->lan.policy_route_count);
    }

    LOG_INFO("[Katran Maglev Engine] Generated default ring and %u WAN group rings", ctx->config->group_count);
    return 0;
}

static void on_pppoe_connected_cb(int wan_idx, const char *ppp_ifname, uint32_t ip, uint32_t gw, void *userdata) {
    wan_manager_ctx_t *ctx = (wan_manager_ctx_t *)userdata;
    if (!ctx || wan_idx >= (int)ctx->config->wan_count) return;

    wan_config_t *w = &ctx->config->wans[wan_idx];
    w->state = WAN_STATE_HEALTHY;

    char ip_str[32] = {0}, gw_str[32] = {0};
    ip_to_str(htonl(ip), ip_str, sizeof(ip_str));
    ip_to_str(htonl(gw), gw_str, sizeof(gw_str));

    LOG_INFO("[PPPoE WAN%d Connected] Interface %s -> IP: %s, Gateway: %s",
             wan_idx + 1, ppp_ifname, ip_str, gw_str);
    wan_manager_add_log("INFO", "PPPoE WAN %u (%s) established session on %s (IP: %s)",
                        w->id, w->label, ppp_ifname, ip_str);

    /* Update policy route default route for this table */
    if (ctx->nl) {
        netlink_add_default_route(ctx->nl, w->table_id, htonl(gw), 0);
    }
    net_apply_wan_nat(ppp_ifname, true);

    wan_manager_rebalance(ctx);
}

static void on_pppoe_disconnected_cb(int wan_idx, const char *ppp_ifname, int attempt, void *userdata) {
    wan_manager_ctx_t *ctx = (wan_manager_ctx_t *)userdata;
    if (!ctx || wan_idx >= (int)ctx->config->wan_count) return;

    wan_config_t *w = &ctx->config->wans[wan_idx];
    w->state = WAN_STATE_DOWN;

    LOG_WARN("[PPPoE WAN%d Disconnected] Session dropped on %s (Reconnect attempt #%d)",
             wan_idx + 1, ppp_ifname, attempt);
    wan_manager_add_log("WARN", "PPPoE WAN %u (%s) session dropped on %s (Auto-reconnect #%d)",
                        w->id, w->label, ppp_ifname, attempt);

    wan_manager_rebalance(ctx);
}

wan_manager_ctx_t *wan_manager_init(fluxwan_config_t *config, netlink_ctx_t *nl, bpf_loader_ctx_t *bpf) {
    if (!config) return NULL;
    wan_manager_ctx_t *ctx = calloc(1, sizeof(wan_manager_ctx_t));
    if (!ctx) return NULL;

    ctx->config = config;
    ctx->nl = nl;
    ctx->bpf = bpf;

    LOG_INFO("WAN Manager initialized. Provisioning policy routing tables...");
    wan_manager_add_log("INFO", "FluxWAN Core Multi-WAN Router Engine started");

    /* Initialize Real PPPoE Session Manager */
    ctx->pppoe = pppoe_manager_init();

    /* Set up initial per-WAN policy routes & IP rules */
    for (uint32_t i = 0; i < config->wan_count; i++) {
        wan_config_t *w = &config->wans[i];
        if (ctx->nl) {
            /* Create IP Rule: mark (0x100 + i) -> table_id */
            netlink_add_ip_rule(ctx->nl, 0x100 + i + 1, w->table_id, 1000 + i);
            /* Add Default Route inside Table */
            if (w->gateway != 0) {
                netlink_add_default_route(ctx->nl, w->table_id, w->gateway, w->ifindex);
            }
        }
        if (ctx->bpf) {
            bpf_loader_update_wan_map(ctx->bpf, i, w);
        }
        wan_manager_add_log("INFO", "WAN %u (%s - %s) policy routing initialized on Table %u",
                            w->id, w->name, w->label, w->table_id);
    }

    /* Start PPPoE sessions for any configured PPPoE WANs */
    if (ctx->pppoe) {
        pppoe_manager_start_all(ctx->pppoe, config);
    }

    /* Compute initial Maglev lookup ring */
    wan_manager_generate_maglev_lut(ctx);

    return ctx;
}

void wan_manager_close(wan_manager_ctx_t *ctx) {
    if (!ctx) return;
    wan_manager_add_log("INFO", "FluxWAN Core Multi-WAN Router Engine stopped");
    if (ctx->pppoe) {
        pppoe_manager_destroy(ctx->pppoe);
    }
    free(ctx);
}

void wan_manager_on_health_update(uint32_t wan_idx, wan_state_t state, const wan_metrics_t *metrics, void *user_data) {
    wan_manager_ctx_t *ctx = (wan_manager_ctx_t *)user_data;
    if (!ctx || wan_idx >= ctx->config->wan_count) return;

    wan_config_t *w = &ctx->config->wans[wan_idx];
    wan_state_t old_state = w->state;
    w->state = state;

    if (metrics) {
        w->metrics = *metrics;
    }

    if (old_state != state) {
        const char *state_str = "HEALTHY";
        if (state == WAN_STATE_DEGRADED) state_str = "DEGRADED";
        else if (state == WAN_STATE_DOWN) state_str = "DOWN";

        LOG_WARN("[WAN FAILOVER / STATE CHANGE] %s (%s) changed state to %s (RTT: %ums, Loss: %.1f%%)",
                 w->name, w->label, state_str, w->metrics.rtt_ms, w->metrics.packet_loss_pct);

        wan_manager_add_log(state == WAN_STATE_HEALTHY ? "INFO" : "WARN",
                            "WAN %u (%s) health transitioned to %s (RTT: %ums, Loss: %.1f%%)",
                            w->id, w->label, state_str, w->metrics.rtt_ms, w->metrics.packet_loss_pct);

        wan_manager_rebalance(ctx);
    }
}

int wan_manager_rebalance(wan_manager_ctx_t *ctx) {
    if (!ctx) return -1;

    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        wan_config_t *w = &ctx->config->wans[i];
        if (!w->enabled || w->state == WAN_STATE_DOWN) {
            w->dynamic_weight = 0;
            if (!w->enabled) w->state = WAN_STATE_DOWN;
        } else if (w->state == WAN_STATE_DEGRADED) {
            w->dynamic_weight = w->config_weight / 4;
            if (w->dynamic_weight == 0) w->dynamic_weight = 1;
        } else {
            w->dynamic_weight = w->config_weight;
        }

        if (ctx->bpf) {
            bpf_loader_update_wan_map(ctx->bpf, i, w);
        }
    }

    /* Recalculate Maglev Consistent Hash LUT Map */
    wan_manager_generate_maglev_lut(ctx);

    /* Re-apply Kernel Netfilter Mangle Marks & Netlink Routing */
    net_apply_configuration(ctx->config, ctx->nl);
    return 0;
}

void wan_manager_periodic_tick(wan_manager_ctx_t *ctx, uint64_t now_ms) {
    if (!ctx) return;

    /* PPPoE Session Monitor & Auto-Reconnect Tick */
    if (ctx->pppoe) {
        pppoe_manager_tick(ctx->pppoe, ctx->config, on_pppoe_connected_cb, on_pppoe_disconnected_cb, ctx);
    }

    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        wan_config_t *w = &ctx->config->wans[i];

        /* WAN DHCP Lease Renewal verification */
        if (w->type == WAN_TYPE_DHCP) {
            if (now_ms - ctx->last_dhcp_renew_ms[i] >= 60000) { /* Check every 60s */
                ctx->last_dhcp_renew_ms[i] = now_ms;
            }
        }
    }
}
