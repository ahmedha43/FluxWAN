#include "wan_manager.h"
#include "net_apply.h"
#include "pppoe_manager.h"
#include <stdarg.h>

#if defined(__linux__)
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#endif

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
    uint32_t dhcp_dead_cycles[MAX_WANS];
    uint64_t last_dhcp_rebind_ms[MAX_WANS];
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

        if (w->enabled && w->state != WAN_STATE_DOWN && w->state != WAN_STATE_DRAINING && w->dynamic_weight > 0) {
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

    /* Meta Katran MaglevHashV2 algorithm:
     * Guarantees exact proportional slot distribution for arbitrary weights */
    uint32_t max_weight = 0;
    for (uint32_t m = 0; m < member_count; m++) {
        if (weights[m] > max_weight) {
            max_weight = weights[m];
        }
    }
    if (max_weight == 0) max_weight = 1;

    uint32_t cum_weight[MAX_WANS] = {0};
    uint32_t runs = 0;

    while (runs < MAGLEV_RING_SIZE) {
        bool progress = false;
        for (uint32_t m = 0; m < member_count; m++) {
            if (weights[m] == 0) continue;
            cum_weight[m] += weights[m];
            if (cum_weight[m] >= max_weight) {
                cum_weight[m] -= max_weight;
                uint32_t offset = permutation[2 * m];
                uint32_t skip = permutation[2 * m + 1];
                uint32_t w_idx = member_indices[m];

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
                if (runs == MAGLEV_RING_SIZE) break;
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

    /* Sync router control data (LAN IP, WAN count) to eBPF */
    if (ctx->bpf) {
        bpf_loader_update_ctrl_map(ctx->bpf, config->lan.ip_addr, config->wan_count, 1, 0);
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

static void send_telegram_alert(const telegram_config_t *tg, const char *msg) {
    if (!tg || !tg->enabled || !tg->bot_token[0] || !tg->chat_id[0] || !msg) return;
#if defined(__linux__)
    pid_t pid = fork();
    if (pid == 0) {
        char url[512];
        snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", tg->bot_token);
        char post_data[1024];
        snprintf(post_data, sizeof(post_data), "chat_id=%s&text=%s", tg->chat_id, msg);
        execlp("curl", "curl", "-s", "-X", "POST", url, "-d", post_data, "-o", "/dev/null", (char *)NULL);
        _exit(0);
    }
#endif
}

void wan_manager_on_health_update(uint32_t wan_idx, wan_state_t state, const wan_metrics_t *metrics, void *user_data) {
    wan_manager_ctx_t *ctx = (wan_manager_ctx_t *)user_data;
    if (!ctx || wan_idx >= ctx->config->wan_count) return;

    wan_config_t *w = &ctx->config->wans[wan_idx];
    if (metrics) {
        w->metrics = *metrics;
    }

    /* If WAN is manually set to DRAINING for maintenance, preserve DRAINING status */
    if (w->state == WAN_STATE_DRAINING) {
        return;
    }

    wan_state_t old_state = w->state;
    w->state = state;

    if (old_state != state) {
        const char *state_str = "HEALTHY";
        if (state == WAN_STATE_DEGRADED) state_str = "DEGRADED";
        else if (state == WAN_STATE_DOWN) state_str = "DOWN";
        else if (state == WAN_STATE_DRAINING) state_str = "DRAINING";

        LOG_WARN("[WAN FAILOVER / STATE CHANGE] %s (%s) changed state to %s (RTT: %ums, Loss: %.1f%%)",
                 w->name, w->label, state_str, w->metrics.rtt_ms, w->metrics.packet_loss_pct);

        wan_manager_add_log(state == WAN_STATE_HEALTHY ? "INFO" : "WARN",
                            "WAN %u (%s) health transitioned to %s (RTT: %ums, Loss: %.1f%%)",
                            w->id, w->label, state_str, w->metrics.rtt_ms, w->metrics.packet_loss_pct);

        /* Send Telegram Notification if enabled */
        if (ctx->config->telegram.enabled) {
            char tg_msg[512];
            if ((state == WAN_STATE_DOWN || state == WAN_STATE_DEGRADED) && ctx->config->telegram.notify_on_failover) {
                snprintf(tg_msg, sizeof(tg_msg), "⚠️ FluxWAN Alert: WAN %u (%s) is %s (RTT: %ums, Loss: %.1f%%)",
                         w->id, w->label, state_str, w->metrics.rtt_ms, w->metrics.packet_loss_pct);
                send_telegram_alert(&ctx->config->telegram, tg_msg);
            } else if (state == WAN_STATE_HEALTHY && ctx->config->telegram.notify_on_recovery) {
                snprintf(tg_msg, sizeof(tg_msg), "✅ FluxWAN Recovery: WAN %u (%s) is now HEALTHY (RTT: %ums, Loss: %.1f%%)",
                         w->id, w->label, w->metrics.rtt_ms, w->metrics.packet_loss_pct);
                send_telegram_alert(&ctx->config->telegram, tg_msg);
            }
        }

        wan_manager_rebalance(ctx);
    }
}

int wan_manager_rebalance(wan_manager_ctx_t *ctx) {
    if (!ctx) return -1;

    /* Find minimum RTT among healthy WANs for latency steering */
    uint32_t min_healthy_rtt = 999999;
    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        const wan_config_t *w = &ctx->config->wans[i];
        if (w->enabled && w->state == WAN_STATE_HEALTHY && w->metrics.rtt_ms > 0) {
            if (w->metrics.rtt_ms < min_healthy_rtt) {
                min_healthy_rtt = w->metrics.rtt_ms;
            }
        }
    }

    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        wan_config_t *w = &ctx->config->wans[i];
        if (!w->enabled || w->state == WAN_STATE_DOWN) {
            w->dynamic_weight = 0;
            if (!w->enabled) w->state = WAN_STATE_DOWN;
        } else if (w->state == WAN_STATE_DRAINING) {
            w->dynamic_weight = 0;
        } else {
            /* Ratio / Bandwidth-weighted base weight */
            uint32_t base_weight = (w->bandwidth_down_mbps > 0) ? w->bandwidth_down_mbps : w->config_weight;
            if (base_weight == 0) base_weight = 1;

            if (w->state == WAN_STATE_DEGRADED) {
                w->dynamic_weight = base_weight / 4;
                if (w->dynamic_weight == 0) w->dynamic_weight = 1;
            } else {
                w->dynamic_weight = base_weight;
            }

            /* Latency-Aware Steering: penalize WANs whose RTT significantly exceeds the lowest latency line */
            if (ctx->config->prober.dynamic_latency_steering && min_healthy_rtt < 999999 && w->metrics.rtt_ms > min_healthy_rtt + 60) {
                uint32_t scaled = (w->dynamic_weight * min_healthy_rtt) / w->metrics.rtt_ms;
                w->dynamic_weight = (scaled > 0) ? scaled : 1;
            }
        }

        if (ctx->bpf) {
            bpf_loader_update_wan_map(ctx->bpf, i, w);
        }
    }

    /* Recalculate Maglev Consistent Hash LUT Map */
    wan_manager_generate_maglev_lut(ctx);

    /* Sync active WAN count to eBPF control map */
    if (ctx->bpf) {
        uint32_t active_count = 0;
        for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
            if (ctx->config->wans[i].enabled && ctx->config->wans[i].state != WAN_STATE_DOWN) {
                active_count++;
            }
        }
        bpf_loader_update_ctrl_map(ctx->bpf, ctx->config->lan.ip_addr, active_count, 1, 0);
    }

    /* Re-apply Kernel Netfilter Mangle Marks & Netlink Routing */
    net_apply_configuration(ctx->config, ctx->nl);
    return 0;
}

static void ensure_dhcp_hook_script(void) {
#if defined(__linux__)
    const char *path = "/run/fluxwan_wan_dhcp.sh";
    if (access(path, X_OK) == 0) return;

    FILE *f = fopen(path, "w");
    if (!f) return;

    fprintf(f,
        "#!/bin/sh\n"
        "# FluxWAN Multi-WAN udhcpc Hook Script\n"
        "[ -z \"$1\" ] && exit 1\n"
        "case \"$1\" in\n"
        "    deconfig)\n"
        "        ip addr flush dev \"$interface\" 2>/dev/null || true\n"
        "        ip link set \"$interface\" up 2>/dev/null || true\n"
        "        rm -f \"/run/fluxwan_wan_${interface}.lease\"\n"
        "        ;;\n"
        "    bound|renew)\n"
        "        PREFIX=24\n"
        "        if [ -n \"$mask\" ]; then\n"
        "            case \"$mask\" in\n"
        "                255.255.255.255) PREFIX=32 ;;\n"
        "                255.255.255.254) PREFIX=31 ;;\n"
        "                255.255.255.252) PREFIX=30 ;;\n"
        "                255.255.255.248) PREFIX=29 ;;\n"
        "                255.255.255.240) PREFIX=28 ;;\n"
        "                255.255.255.224) PREFIX=27 ;;\n"
        "                255.255.255.192) PREFIX=26 ;;\n"
        "                255.255.255.128) PREFIX=25 ;;\n"
        "                255.255.255.0)   PREFIX=24 ;;\n"
        "                255.255.254.0)   PREFIX=23 ;;\n"
        "                255.255.252.0)   PREFIX=22 ;;\n"
        "                255.255.248.0)   PREFIX=21 ;;\n"
        "                255.255.240.0)   PREFIX=20 ;;\n"
        "                255.255.0.0)     PREFIX=16 ;;\n"
        "                255.0.0.0)       PREFIX=8  ;;\n"
        "                *)               PREFIX=24 ;;\n"
        "            esac\n"
        "        fi\n"
        "        ip addr flush dev \"$interface\" 2>/dev/null || true\n"
        "        ip addr add \"$ip/$PREFIX\" dev \"$interface\" 2>/dev/null || ip addr replace \"$ip/$PREFIX\" dev \"$interface\" 2>/dev/null || true\n"
        "        ip link set \"$interface\" up 2>/dev/null || true\n"
        "        cat > \"/run/fluxwan_wan_${interface}.lease\" << EOF\n"
        "IP=$ip\n"
        "NETMASK=${mask:-$subnet}\n"
        "GATEWAY=$router\n"
        "DNS=$dns\n"
        "TIMESTAMP=$(date +%%s)\n"
        "EOF\n"
        "        TABLE_ID=$(cat \"/run/fluxwan_table_${interface}\" 2>/dev/null)\n"
        "        [ -z \"$TABLE_ID\" ] && TABLE_ID=101\n"
        "        if [ -n \"$router\" ]; then\n"
        "            ip route replace default via \"$router\" dev \"$interface\" table \"$TABLE_ID\" proto static 2>/dev/null || true\n"
        "            ip rule del oif \"$interface\" table \"$TABLE_ID\" 2>/dev/null || true\n"
        "            ip rule add oif \"$interface\" table \"$TABLE_ID\" pref 100 2>/dev/null || true\n"
        "            ip rule del from \"$ip\" table \"$TABLE_ID\" 2>/dev/null || true\n"
        "            ip rule add from \"$ip\" table \"$TABLE_ID\" pref 100 2>/dev/null || true\n"
        "            ip route replace default via \"$router\" dev \"$interface\" 2>/dev/null || true\n"
        "        fi\n"
        "        sysctl -w net.ipv4.conf.${interface}.rp_filter=2 >/dev/null 2>&1 || true\n"
        "        ;;\n"
        "esac\n"
        "exit 0\n"
    );
    fclose(f);
    chmod(path, 0755);
#endif
}

void wan_manager_dhcp_renew(wan_manager_ctx_t *ctx, int wan_idx) {
    if (!ctx) return;
    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        if (wan_idx >= 0 && (int)i != wan_idx) continue;
        wan_config_t *w = &ctx->config->wans[i];
        if (w->type == WAN_TYPE_DHCP && w->enabled) {
            LOG_INFO("[WAN DHCP] Force-renewing IP lease on %s (Table %u)...", w->name, w->table_id);
            wan_manager_add_log("INFO", "[DHCP Client] Force-renewing IP lease on %s...", w->name);
#if defined(__linux__)
            char flush_cmd[128];
            snprintf(flush_cmd, sizeof(flush_cmd), "ip addr flush dev %s 2>/dev/null || true", w->name);
            safe_system(flush_cmd);

            char pid_path[64];
            snprintf(pid_path, sizeof(pid_path), "/run/udhcpc_%s.pid", w->name);
            FILE *pf = fopen(pid_path, "r");
            if (pf) {
                int pid = 0;
                if (fscanf(pf, "%d", &pid) == 1 && pid > 1) {
                    kill(pid, SIGKILL);
                }
                fclose(pf);
                unlink(pid_path);
            }
            char lpath[64];
            snprintf(lpath, sizeof(lpath), "/run/fluxwan_wan_%s.lease", w->name);
            unlink(lpath);
#endif
            ctx->last_dhcp_renew_ms[i] = 0;
            ctx->dhcp_dead_cycles[i] = 0;
        }
    }
}

void wan_manager_periodic_tick(wan_manager_ctx_t *ctx, uint64_t now_ms) {
    if (!ctx) return;

    /* PPPoE Session Monitor & Auto-Reconnect Tick */
    if (ctx->pppoe) {
        pppoe_manager_tick(ctx->pppoe, ctx->config, on_pppoe_connected_cb, on_pppoe_disconnected_cb, ctx);
    }

    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        wan_config_t *w = &ctx->config->wans[i];

        /* WAN DHCP Client Engine */
        if (w->type == WAN_TYPE_DHCP && w->enabled) {
            /* DHCP Dead Gateway Watchdog:
             * If an interface is in WAN_STATE_DOWN or packet loss >= 99% for 5 consecutive checks (~10s),
             * and at least 15s elapsed since last rebind, the network environment likely changed (e.g. router moved).
             * Automatically trigger a rebind to discover the new gateway. */
            if (w->state == WAN_STATE_DOWN || w->metrics.packet_loss_pct >= 99.0f) {
                ctx->dhcp_dead_cycles[i]++;
                if (ctx->dhcp_dead_cycles[i] >= 5 && (now_ms - ctx->last_dhcp_rebind_ms[i] >= 15000)) {
                    ctx->last_dhcp_rebind_ms[i] = now_ms;
                    ctx->dhcp_dead_cycles[i] = 0;
                    LOG_WARN("[DHCP Watchdog] Gateway unreachable on %s (100%% packet loss). Auto-rebinding DHCP...", w->name);
                    wan_manager_add_log("WARN", "[DHCP Watchdog] Gateway unreachable on %s. Re-discovering network...", w->name);
                    wan_manager_dhcp_renew(ctx, (int)i);
                }
            } else {
                ctx->dhcp_dead_cycles[i] = 0;
            }

            if (now_ms - ctx->last_dhcp_renew_ms[i] >= 2000) { /* Check every 2s */
                ctx->last_dhcp_renew_ms[i] = now_ms;
                ensure_dhcp_hook_script();

#if defined(__linux__)
                /* 1. Ensure table ID mapping file is current */
                char tbl_path[64];
                snprintf(tbl_path, sizeof(tbl_path), "/run/fluxwan_table_%s", w->name);
                FILE *tf = fopen(tbl_path, "w");
                if (tf) {
                    fprintf(tf, "%u\n", w->table_id);
                    fclose(tf);
                }

                /* 2. Ensure interface is administratively UP */
                char up_cmd[128];
                snprintf(up_cmd, sizeof(up_cmd), "ip link set %s up 2>/dev/null || true", w->name);
                safe_system(up_cmd);

                /* 3. Check if udhcpc is actively running */
                char pid_path[64];
                snprintf(pid_path, sizeof(pid_path), "/run/udhcpc_%s.pid", w->name);
                bool running = false;
                FILE *pf = fopen(pid_path, "r");
                if (pf) {
                    int pid = 0;
                    if (fscanf(pf, "%d", &pid) == 1 && pid > 1) {
                        if (kill(pid, 0) == 0) running = true;
                    }
                    fclose(pf);
                }

                if (!running) {
                    const char *script = (access("/usr/local/bin/fluxwan_wan_dhcp.sh", X_OK) == 0)
                                         ? "/usr/local/bin/fluxwan_wan_dhcp.sh"
                                         : "/run/fluxwan_wan_dhcp.sh";
                    LOG_INFO("[WAN DHCP] Spawning udhcpc on %s (Table %u, Script: %s)", w->name, w->table_id, script);
                    wan_manager_add_log("INFO", "[DHCP Client] Starting DHCP client on %s (Table %u)", w->name, w->table_id);
                    char dhcp_cmd[512];
                    snprintf(dhcp_cmd, sizeof(dhcp_cmd),
                             "udhcpc -i %s -p %s -s %s -b -R -O 33 -x hostname:FluxWAN >/dev/null 2>&1 &",
                             w->name, pid_path, script);
                    safe_system(dhcp_cmd);
                }

                /* 4. Read lease file if written by hook script */
                char lease_path[64];
                snprintf(lease_path, sizeof(lease_path), "/run/fluxwan_wan_%s.lease", w->name);
                FILE *lf = fopen(lease_path, "r");
                if (lf) {
                    char line[256];
                    char ip_str[32] = {0}, gw_str[32] = {0}, mask_str[32] = {0};
                    while (fgets(line, sizeof(line), lf)) {
                        if (strncmp(line, "IP=", 3) == 0) {
                            sscanf(line + 3, "%31s", ip_str);
                        } else if (strncmp(line, "GATEWAY=", 8) == 0) {
                            sscanf(line + 8, "%31s", gw_str);
                        } else if (strncmp(line, "NETMASK=", 8) == 0) {
                            sscanf(line + 8, "%31s", mask_str);
                        }
                    }
                    fclose(lf);

                    uint32_t new_ip = str_to_ip(ip_str);
                    uint32_t new_gw = str_to_ip(gw_str);
                    uint32_t new_mask = str_to_ip(mask_str);
                    if (new_mask == 0) new_mask = str_to_ip("255.255.255.0");

                    if (new_ip != 0 && (new_ip != w->ip_addr || new_gw != w->gateway)) {
                        LOG_INFO("[WAN DHCP] Bound on %s: IP=%s, GW=%s, Table=%u",
                                 w->name, ip_str, gw_str, w->table_id);
                        wan_manager_add_log("INFO", "[DHCP WAN%u] Bound IP %s, Gateway %s on %s",
                                            w->id, ip_str, gw_str, w->name);
                        w->ip_addr = new_ip;
                        w->gateway = new_gw;
                        w->netmask = new_mask;
                        w->state = WAN_STATE_HEALTHY;

                        if (new_gw != 0) {
                            char rc[512];
                            snprintf(rc, sizeof(rc),
                                     "ip route replace default via %s dev %s table %u proto static 2>/dev/null || true; "
                                     "ip rule del oif %s table %u 2>/dev/null || true; "
                                     "ip rule add oif %s table %u pref 100 2>/dev/null || true; "
                                     "ip rule del from %s table %u 2>/dev/null || true; "
                                     "ip rule add from %s table %u pref 100 2>/dev/null || true; "
                                     "ip route replace default via %s dev %s 2>/dev/null || true",
                                     gw_str, w->name, w->table_id,
                                     w->name, w->table_id,
                                     w->name, w->table_id,
                                     ip_str, w->table_id,
                                     ip_str, w->table_id,
                                     gw_str, w->name);
                            safe_system(rc);
                        }

                        net_apply_wan_nat(w->name, true);
                        wan_manager_rebalance(ctx);
                    }
                } else if (w->ip_addr == 0) {
                    /* Fallback: Query live interface IP via ioctl SIOCGIFADDR */
                    int s = socket(AF_INET, SOCK_DGRAM, 0);
                    if (s >= 0) {
                        struct ifreq ifr;
                        memset(&ifr, 0, sizeof(ifr));
                        strncpy(ifr.ifr_name, w->name, sizeof(ifr.ifr_name) - 1);
                        if (ioctl(s, SIOCGIFADDR, &ifr) == 0) {
                            struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
                            if (sin->sin_addr.s_addr != 0 && sin->sin_addr.s_addr != str_to_ip("127.0.0.1")) {
                                w->ip_addr = sin->sin_addr.s_addr;
                                w->state = WAN_STATE_HEALTHY;
                                LOG_INFO("[WAN DHCP] Detected existing IP on %s via ioctl: %s",
                                         w->name, inet_ntoa(sin->sin_addr));
                                wan_manager_rebalance(ctx);
                            }
                        }
                        close(s);
                    }
                }
#endif
            }
        }
    }
}
