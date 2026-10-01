/*
 * FluxWAN - High-Performance Multi-WAN Load Balancing OS
 * Broadband Remote Access Server (BRAS) / PPPoE Server Engine
 *
 * Copyright (C) 2026 Ahmed Al-Dulaimi (أحمد الدليمي). All rights reserved.
 * Author: Ahmed Al-Dulaimi (أحمد الدليمي)
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pppoe_server.h"
#include "config.h"
#include <pthread.h>
#include <sys/stat.h>
#include <dirent.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#endif

typedef struct {
    char ifname[32];
    uint64_t last_rx_bytes;
    uint64_t last_tx_bytes;
    uint64_t last_time_ms;
} session_history_t;

struct pppoe_server_ctx {
    fluxwan_config_t *config;
    pthread_mutex_t lock;
    session_history_t history[MAX_PPPOE_SESSIONS];
    uint32_t history_count;
};

static inline void safe_str_copy(char *dst, const char *src, size_t max_len) {
    if (!dst || max_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t slen = strlen(src);
    if (slen >= max_len) slen = max_len - 1;
    memcpy(dst, src, slen);
    dst[slen] = '\0';
}

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (ts.tv_nsec / 1000000ULL);
}

pppoe_server_ctx_t *pppoe_server_init(fluxwan_config_t *config) {
    if (!config) return NULL;
    pppoe_server_ctx_t *ctx = calloc(1, sizeof(pppoe_server_ctx_t));
    if (!ctx) return NULL;

    ctx->config = config;
    pthread_mutex_init(&ctx->lock, NULL);

    /* Populate default broadband configuration if unset */
    pppoe_server_config_t *pcfg = &config->pppoe_server;
    if (!pcfg->interface[0]) {
        safe_str_copy(pcfg->interface, config->lan.name[0] ? config->lan.name : "eth0", sizeof(pcfg->interface));
    }
    if (!pcfg->lan_mode[0]) {
        safe_str_copy(pcfg->lan_mode, "dual", sizeof(pcfg->lan_mode));
    }
    if (!pcfg->service_name[0]) {
        safe_str_copy(pcfg->service_name, "FluxWAN-Broadband", sizeof(pcfg->service_name));
    }
    if (!pcfg->ac_name[0]) {
        safe_str_copy(pcfg->ac_name, "FluxWAN-BRAS", sizeof(pcfg->ac_name));
    }
    if (!pcfg->local_ip[0]) {
        safe_str_copy(pcfg->local_ip, "10.100.0.1", sizeof(pcfg->local_ip));
    }
    if (!pcfg->pool_start[0]) {
        safe_str_copy(pcfg->pool_start, "10.100.0.2", sizeof(pcfg->pool_start));
    }
    if (!pcfg->pool_end[0]) {
        safe_str_copy(pcfg->pool_end, "10.100.0.254", sizeof(pcfg->pool_end));
    }
    if (pcfg->pool_count == 0) {
        pcfg->pool_count = 250;
    }
    if (!pcfg->dns1[0]) {
        safe_str_copy(pcfg->dns1, "1.1.1.1", sizeof(pcfg->dns1));
    }
    if (!pcfg->dns2[0]) {
        safe_str_copy(pcfg->dns2, "8.8.8.8", sizeof(pcfg->dns2));
    }
    if (pcfg->mru == 0) pcfg->mru = 1492;
    if (pcfg->mss == 0) pcfg->mss = 1452;

    /* Add default profiles if none exist */
    if (pcfg->profile_count == 0) {
        safe_str_copy(pcfg->profiles[0].name, "Economy_10M", sizeof(pcfg->profiles[0].name));
        pcfg->profiles[0].rate_down_kbps = 10240;
        pcfg->profiles[0].rate_up_kbps = 5120;
        pcfg->profiles[0].validity_days = 30;
        safe_str_copy(pcfg->profiles[0].description, "10 Mbps Down / 5 Mbps Up (30 Days)", sizeof(pcfg->profiles[0].description));

        safe_str_copy(pcfg->profiles[1].name, "Standard_25M", sizeof(pcfg->profiles[1].name));
        pcfg->profiles[1].rate_down_kbps = 25600;
        pcfg->profiles[1].rate_up_kbps = 10240;
        pcfg->profiles[1].validity_days = 30;
        safe_str_copy(pcfg->profiles[1].description, "25 Mbps Down / 10 Mbps Up (30 Days)", sizeof(pcfg->profiles[1].description));

        safe_str_copy(pcfg->profiles[2].name, "Ultra_50M", sizeof(pcfg->profiles[2].name));
        pcfg->profiles[2].rate_down_kbps = 51200;
        pcfg->profiles[2].rate_up_kbps = 20480;
        pcfg->profiles[2].validity_days = 30;
        safe_str_copy(pcfg->profiles[2].description, "50 Mbps Down / 20 Mbps Up (30 Days)", sizeof(pcfg->profiles[2].description));

        safe_str_copy(pcfg->profiles[3].name, "Unlimited", sizeof(pcfg->profiles[3].name));
        pcfg->profiles[3].rate_down_kbps = 0;
        pcfg->profiles[3].rate_up_kbps = 0;
        pcfg->profiles[3].validity_days = 0;
        safe_str_copy(pcfg->profiles[3].description, "Max Line Speed (No Shaping / Unlimited)", sizeof(pcfg->profiles[3].description));

        pcfg->profile_count = 4;
    }

    /* Add default test user if none exist */
    if (pcfg->user_count == 0) {
        safe_str_copy(pcfg->users[0].username, "fluxwan", sizeof(pcfg->users[0].username));
        safe_str_copy(pcfg->users[0].password, "123456", sizeof(pcfg->users[0].password));
        safe_str_copy(pcfg->users[0].profile, "Standard_25M", sizeof(pcfg->users[0].profile));
        pcfg->users[0].enabled = true;
        pcfg->users[0].created_at = (uint64_t)time(NULL);
        pcfg->users[0].expires_at = 0; /* Unlimited */
        safe_str_copy(pcfg->users[0].comment, "Default Broadband User", sizeof(pcfg->users[0].comment));
        pcfg->user_count = 1;
    }

    LOG_INFO("Broadband PPPoE Server initialized (Pool: %s - %s, Users: %u)",
             pcfg->pool_start, pcfg->pool_end, pcfg->user_count);
    return ctx;
}

void pppoe_server_close(pppoe_server_ctx_t *ctx) {
    if (!ctx) return;
    pppoe_server_stop(ctx);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

static int write_pppoe_server_options(const pppoe_server_config_t *cfg) {
#if defined(__linux__)
    FILE *f = fopen("/etc/ppp/pppoe-server-options", "w");
    if (!f) {
        LOG_ERROR("Could not open /etc/ppp/pppoe-server-options for writing");
        return -1;
    }

    fprintf(f, "# FluxWAN Broadband Remote Access Server Options\n");
    fprintf(f, "# Generated dynamically by FluxWAN Core\n\n");
    fprintf(f, "auth\n");
    fprintf(f, "+chap\n");
    fprintf(f, "+pap\n");
    fprintf(f, "lcp-echo-interval 10\n");
    fprintf(f, "lcp-echo-failure 3\n");
    fprintf(f, "ms-dns %s\n", cfg->dns1[0] ? cfg->dns1 : "1.1.1.1");
    fprintf(f, "ms-dns %s\n", cfg->dns2[0] ? cfg->dns2 : "8.8.8.8");
    fprintf(f, "default-asyncmap\n");
    fprintf(f, "nopcomp\n");
    fprintf(f, "noaccomp\n");
    fprintf(f, "nodeflate\n");
    fprintf(f, "novj\n");
    fprintf(f, "nobsdcomp\n");
    fprintf(f, "ktune\n");
    fprintf(f, "mru %u\n", cfg->mru > 0 ? cfg->mru : 1492);
    fprintf(f, "mtu %u\n", cfg->mru > 0 ? cfg->mru : 1492);
    fclose(f);
#else
    (void)cfg;
#endif
    return 0;
}

static int write_pppoe_secrets(const pppoe_server_config_t *cfg) {
#if defined(__linux__)
    FILE *f_chap = fopen("/etc/ppp/chap-secrets", "w");
    FILE *f_pap = fopen("/etc/ppp/pap-secrets", "w");
    if (!f_chap && !f_pap) {
        LOG_ERROR("Could not open /etc/ppp/*-secrets for writing");
        return -1;
    }

    const char *header = "# FluxWAN Broadband Accounts Secrets\n# Secrets for authentication using CHAP / PAP\n# client server secret IP_addresses\n";
    if (f_chap) fprintf(f_chap, "%s", header);
    if (f_pap) fprintf(f_pap, "%s", header);

    time_t now_sec = time(NULL);
    for (uint32_t i = 0; i < cfg->user_count; i++) {
        const pppoe_user_t *u = &cfg->users[i];
        if (!u->enabled || !u->username[0]) continue;
        /* Exclude expired subscribers */
        if (u->expires_at > 0 && (uint64_t)now_sec >= u->expires_at) {
            continue;
        }
        const char *ip_target = (u->static_ip[0]) ? u->static_ip : "*";
        if (f_chap) {
            fprintf(f_chap, "\"%s\" * \"%s\" %s\n", u->username, u->password, ip_target);
        }
        if (f_pap) {
            fprintf(f_pap, "\"%s\" * \"%s\" %s\n", u->username, u->password, ip_target);
        }
    }

    if (f_chap) fclose(f_chap);
    if (f_pap) fclose(f_pap);
#else
    (void)cfg;
#endif
    return 0;
}

static int setup_pppoe_scripts(const pppoe_server_config_t *cfg) {
#if defined(__linux__)
    safe_system("mkdir -p /run/fluxwan/pppoe /etc/ppp 2>/dev/null || true");

    /* Create /etc/ppp/ip-up */
    FILE *f_up = fopen("/etc/ppp/ip-up", "w");
    if (f_up) {
        fprintf(f_up, "#!/bin/sh\n");
        fprintf(f_up, "# FluxWAN Broadband Dynamic Session Hook\n");
        fprintf(f_up, "mkdir -p /run/fluxwan/pppoe\n");
        fprintf(f_up, "SESSION_FILE=\"/run/fluxwan/pppoe/$1.session\"\n");
        fprintf(f_up, "cat << 'EOF' > \"$SESSION_FILE\"\n");
        fprintf(f_up, "IFNAME=$1\n");
        fprintf(f_up, "TTY=$2\n");
        fprintf(f_up, "SPEED=$3\n");
        fprintf(f_up, "LOCAL_IP=$4\n");
        fprintf(f_up, "REMOTE_IP=$5\n");
        fprintf(f_up, "IPPARAM=$6\n");
        fprintf(f_up, "USERNAME=${PEERNAME:-$USER}\n");
        fprintf(f_up, "CONNECT_TIME=$(date +%%s)\n");
        fprintf(f_up, "MAC=${MACREMOTE:-unknown}\n");
        fprintf(f_up, "EOF\n");

        /* Apply user traffic shaping if profile matches */
        for (uint32_t p = 0; p < cfg->profile_count; p++) {
            const pppoe_profile_t *prof = &cfg->profiles[p];
            if (prof->rate_down_kbps > 0) {
                fprintf(f_up, "if [ \"$PROFILE\" = \"%s\" ]; then\n", prof->name);
                fprintf(f_up, "  tc qdisc add dev \"$1\" root tbf rate %ukbit burst 32kbit latency 50ms 2>/dev/null || true\n", prof->rate_down_kbps);
                fprintf(f_up, "fi\n");
            }
        }
        fclose(f_up);
        safe_system("chmod +x /etc/ppp/ip-up 2>/dev/null || true");
    }

    /* Create /etc/ppp/ip-down */
    FILE *f_down = fopen("/etc/ppp/ip-down", "w");
    if (f_down) {
        fprintf(f_down, "#!/bin/sh\n");
        fprintf(f_down, "# FluxWAN Broadband Session Teardown Hook\n");
        fprintf(f_down, "rm -f \"/run/fluxwan/pppoe/$1.session\" 2>/dev/null || true\n");
        fclose(f_down);
        safe_system("chmod +x /etc/ppp/ip-down 2>/dev/null || true");
    }
#else
    (void)cfg;
#endif
    return 0;
}

int pppoe_server_start(pppoe_server_ctx_t *ctx) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);

    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;
    if (!cfg->enabled) {
        pthread_mutex_unlock(&ctx->lock);
        return 0;
    }

    LOG_INFO("Starting Broadband PPPoE Server on %s (Mode: %s)...", cfg->interface, cfg->lan_mode);

#if defined(__linux__)
    /* 1. Ensure kernel modules are loaded */
    safe_system("modprobe pppoe 2>/dev/null || true");
    safe_system("modprobe pppox 2>/dev/null || true");
    safe_system("modprobe ppp_generic 2>/dev/null || true");

    /* 2. Write options, secrets, and hooks */
    write_pppoe_server_options(cfg);
    write_pppoe_secrets(cfg);
    setup_pppoe_scripts(cfg);

    /* 3. Firewall & IP Forwarding: allow PPP forwarding and NAT */
    safe_system("iptables -A FORWARD -i ppp+ -j ACCEPT 2>/dev/null || true");
    safe_system("iptables -A FORWARD -o ppp+ -j ACCEPT 2>/dev/null || true");
    safe_system("iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o ppp+ -j TCPMSS --set-mss 1452 2>/dev/null || true");

    /* 4. Kill existing pppoe-server if running */
    safe_system("killall pppoe-server 2>/dev/null || true");
    usleep(50000);

    /* 5. Assemble pppoe-server command */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/pppoe-server -I %s -L %s -R %s -N %u -k -C \"%s\" -S \"%s\" -O /etc/ppp/pppoe-server-options",
             cfg->interface[0] ? cfg->interface : "eth0",
             cfg->local_ip[0] ? cfg->local_ip : "10.100.0.1",
             cfg->pool_start[0] ? cfg->pool_start : "10.100.0.2",
             cfg->pool_count > 0 ? cfg->pool_count : 250,
             cfg->ac_name[0] ? cfg->ac_name : "FluxWAN-BRAS",
             cfg->service_name[0] ? cfg->service_name : "FluxWAN-Broadband");

    LOG_INFO("[Broadband] Executing: %s", cmd);
    int rc = safe_system(cmd);
    if (rc != 0) {
        LOG_WARN("[Broadband] Warning: pppoe-server exited with code %d", rc);
    }
#endif

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int pppoe_server_stop(pppoe_server_ctx_t *ctx) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);

    LOG_INFO("Stopping Broadband PPPoE Server and active PPP sessions...");

#if defined(__linux__)
    safe_system("killall -TERM pppoe-server 2>/dev/null || true");
    safe_system("pkill -TERM -f \"pppd.*pppoe-server-options\" 2>/dev/null || true");
    safe_system("rm -rf /run/fluxwan/pppoe/* 2>/dev/null || true");
#endif

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int pppoe_server_reload(pppoe_server_ctx_t *ctx) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);

    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;
    write_pppoe_server_options(cfg);
    write_pppoe_secrets(cfg);
    setup_pppoe_scripts(cfg);

    if (cfg->enabled && !pppoe_server_is_running(ctx)) {
        pthread_mutex_unlock(&ctx->lock);
        return pppoe_server_start(ctx);
    } else if (!cfg->enabled && pppoe_server_is_running(ctx)) {
        pthread_mutex_unlock(&ctx->lock);
        return pppoe_server_stop(ctx);
    }

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

bool pppoe_server_is_running(pppoe_server_ctx_t *ctx) {
    (void)ctx;
#if defined(__linux__)
    FILE *fp = popen("pgrep pppoe-server 2>/dev/null", "r");
    if (!fp) return false;
    char buf[32] = {0};
    bool found = (fgets(buf, sizeof(buf), fp) != NULL && atoi(buf) > 0);
    pclose(fp);
    return found;
#else
    return false;
#endif
}

static uint64_t read_sys_u64(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    uint64_t val = 0;
    if (fscanf(f, "%llu", (unsigned long long *)&val) != 1) val = 0;
    fclose(f);
    return val;
}

int pppoe_server_get_sessions(pppoe_server_ctx_t *ctx, pppoe_active_session_t *out_sessions, uint32_t max_sessions, uint32_t *out_count) {
    if (!ctx || !out_sessions || !out_count || max_sessions == 0) return -1;
    pthread_mutex_lock(&ctx->lock);

    uint32_t count = 0;
    uint64_t now_ms = get_time_ms();
    time_t now_sec = time(NULL);

#if defined(__linux__)
    DIR *d = opendir("/run/fluxwan/pppoe");
    if (d) {
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL && count < max_sessions) {
            if (strstr(dir->d_name, ".session") == NULL) continue;
            char path[512];
            snprintf(path, sizeof(path), "/run/fluxwan/pppoe/%s", dir->d_name);

            FILE *sf = fopen(path, "r");
            if (!sf) continue;

            pppoe_active_session_t *s = &out_sessions[count];
            memset(s, 0, sizeof(pppoe_active_session_t));

            char line[256];
            while (fgets(line, sizeof(line), sf)) {
                char *eq = strchr(line, '=');
                if (!eq) continue;
                *eq = '\0';
                char *val = eq + 1;
                /* strip newline */
                size_t vlen = strlen(val);
                while (vlen > 0 && (val[vlen - 1] == '\r' || val[vlen - 1] == '\n')) {
                    val[--vlen] = '\0';
                }

                if (strcmp(line, "IFNAME") == 0) safe_str_copy(s->ifname, val, sizeof(s->ifname));
                else if (strcmp(line, "REMOTE_IP") == 0) safe_str_copy(s->ip, val, sizeof(s->ip));
                else if (strcmp(line, "USERNAME") == 0) safe_str_copy(s->username, val, sizeof(s->username));
                else if (strcmp(line, "MAC") == 0) safe_str_copy(s->mac, val, sizeof(s->mac));
                else if (strcmp(line, "CONNECT_TIME") == 0) s->connect_time = (uint64_t)atoll(val);
            }
            fclose(sf);

            if (!s->ifname[0]) continue;

            /* Check interface exists in sysfs */
            char stat_path[512];
            snprintf(stat_path, sizeof(stat_path), "/sys/class/net/%s/statistics/rx_bytes", s->ifname);
            s->rx_bytes = read_sys_u64(stat_path);
            snprintf(stat_path, sizeof(stat_path), "/sys/class/net/%s/statistics/tx_bytes", s->ifname);
            s->tx_bytes = read_sys_u64(stat_path);
            snprintf(stat_path, sizeof(stat_path), "/sys/class/net/%s/statistics/rx_packets", s->ifname);
            s->rx_packets = read_sys_u64(stat_path);
            snprintf(stat_path, sizeof(stat_path), "/sys/class/net/%s/statistics/tx_packets", s->ifname);
            s->tx_packets = read_sys_u64(stat_path);

            if (s->connect_time > 0 && (uint64_t)now_sec >= s->connect_time) {
                s->uptime_sec = (uint64_t)now_sec - s->connect_time;
            } else {
                s->uptime_sec = 0;
            }

            /* Resolve user's profile */
            for (uint32_t u = 0; u < ctx->config->pppoe_server.user_count; u++) {
                if (strcmp(ctx->config->pppoe_server.users[u].username, s->username) == 0) {
                    safe_str_copy(s->profile, ctx->config->pppoe_server.users[u].profile, sizeof(s->profile));
                    break;
                }
            }
            if (!s->profile[0]) safe_str_copy(s->profile, "Standard_25M", sizeof(s->profile));

            /* Rate calculation via history */
            for (uint32_t h = 0; h < ctx->history_count; h++) {
                if (strcmp(ctx->history[h].ifname, s->ifname) == 0) {
                    uint64_t dt = now_ms - ctx->history[h].last_time_ms;
                    if (dt > 200 && dt < 10000) {
                        uint64_t drx = (s->rx_bytes >= ctx->history[h].last_rx_bytes) ? (s->rx_bytes - ctx->history[h].last_rx_bytes) : 0;
                        uint64_t dtx = (s->tx_bytes >= ctx->history[h].last_tx_bytes) ? (s->tx_bytes - ctx->history[h].last_tx_bytes) : 0;
                        s->rx_rate_kbps = (uint32_t)((drx * 8ULL) / dt);
                        s->tx_rate_kbps = (uint32_t)((dtx * 8ULL) / dt);
                    }
                    ctx->history[h].last_rx_bytes = s->rx_bytes;
                    ctx->history[h].last_tx_bytes = s->tx_bytes;
                    ctx->history[h].last_time_ms = now_ms;
                    break;
                }
            }

            count++;
        }
        closedir(d);
    }
#endif

    *out_count = count;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int pppoe_server_disconnect_session(pppoe_server_ctx_t *ctx, const char *ifname) {
    if (!ctx || !ifname || !ifname[0]) return -1;
    LOG_INFO("[Broadband] Disconnecting session on interface %s", ifname);

#if defined(__linux__)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pkill -f \"pppd.*%s\" 2>/dev/null || ip link set dev %s down 2>/dev/null || true", ifname, ifname);
    safe_system(cmd);
    snprintf(cmd, sizeof(cmd), "rm -f /run/fluxwan/pppoe/%s.session 2>/dev/null || true", ifname);
    safe_system(cmd);
#endif
    return 0;
}

int pppoe_server_set_user(pppoe_server_ctx_t *ctx, const pppoe_user_t *user) {
    if (!ctx || !user || !user->username[0]) return -1;
    pthread_mutex_lock(&ctx->lock);

    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;
    int found_idx = -1;
    for (uint32_t i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].username, user->username) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    pppoe_user_t u = *user;
    if (u.created_at == 0) {
        u.created_at = (uint64_t)time(NULL);
    }
    /* If expires_at is 0 and profile has validity_days > 0, calculate expiry */
    if (u.expires_at == 0 && u.profile[0]) {
        for (uint32_t p = 0; p < cfg->profile_count; p++) {
            if (strcmp(cfg->profiles[p].name, u.profile) == 0) {
                if (cfg->profiles[p].validity_days > 0) {
                    u.expires_at = (uint64_t)time(NULL) + ((uint64_t)cfg->profiles[p].validity_days * 86400ULL);
                }
                break;
            }
        }
    }

    if (found_idx >= 0) {
        /* Update existing */
        cfg->users[found_idx] = u;
    } else if (cfg->user_count < MAX_PPPOE_USERS) {
        /* Append new */
        cfg->users[cfg->user_count++] = u;
    } else {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    write_pppoe_secrets(cfg);
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int pppoe_server_delete_user(pppoe_server_ctx_t *ctx, const char *username) {
    if (!ctx || !username || !username[0]) return -1;
    pthread_mutex_lock(&ctx->lock);

    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;
    int found_idx = -1;
    for (uint32_t i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].username, username) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx >= 0) {
        for (uint32_t i = found_idx; i + 1 < cfg->user_count; i++) {
            cfg->users[i] = cfg->users[i + 1];
        }
        cfg->user_count--;
        write_pppoe_secrets(cfg);
    }

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int pppoe_server_renew_user(pppoe_server_ctx_t *ctx, const char *username, uint32_t additional_days, const char *new_profile) {
    if (!ctx || !username || !username[0]) return -1;
    pthread_mutex_lock(&ctx->lock);

    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;
    int found_idx = -1;
    for (uint32_t i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].username, username) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    pppoe_user_t *u = &cfg->users[found_idx];
    bool profile_changed = false;
    if (new_profile && new_profile[0] && strcmp(u->profile, new_profile) != 0) {
        safe_str_copy(u->profile, new_profile, sizeof(u->profile));
        profile_changed = true;
    }

    /* If additional_days is 0, find validity from user's (new or existing) profile */
    if (additional_days == 0) {
        for (uint32_t p = 0; p < cfg->profile_count; p++) {
            if (strcmp(cfg->profiles[p].name, u->profile) == 0) {
                additional_days = cfg->profiles[p].validity_days;
                break;
            }
        }
        if (additional_days == 0) additional_days = 30; /* Default 30 days */
    }

    time_t now = time(NULL);
    uint64_t add_sec = (uint64_t)additional_days * 86400ULL;
    if (u->expires_at == 0 || (uint64_t)now >= u->expires_at) {
        /* Already expired or previously unset: renew starting from right now */
        u->expires_at = (uint64_t)now + add_sec;
    } else {
        /* Still active: extend from current expiration date */
        u->expires_at += add_sec;
    }

    /* Auto-enable if disabled */
    u->enabled = true;

    write_pppoe_secrets(cfg);
    LOG_INFO("[Broadband] Subscriber '%s' subscription renewed (profile: %s, +%u days, new expires_at: %llu)",
             username, u->profile, additional_days, (unsigned long long)u->expires_at);

    if (profile_changed) {
        pppoe_active_session_t sessions[MAX_PPPOE_SESSIONS];
        uint32_t count = 0;
        pthread_mutex_unlock(&ctx->lock);
        pppoe_server_get_sessions(ctx, sessions, MAX_PPPOE_SESSIONS, &count);
        for (uint32_t i = 0; i < count; i++) {
            if (strcmp(sessions[i].username, username) == 0) {
                pppoe_server_disconnect_session(ctx, sessions[i].ifname);
                LOG_INFO("[Broadband] Reconnecting session %s for user '%s' to apply new profile '%s'",
                         sessions[i].ifname, username, new_profile);
            }
        }
        return 0;
    }

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int pppoe_server_toggle_user(pppoe_server_ctx_t *ctx, const char *username, bool enable) {
    if (!ctx || !username || !username[0]) return -1;
    pthread_mutex_lock(&ctx->lock);

    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;
    int found_idx = -1;
    for (uint32_t i = 0; i < cfg->user_count; i++) {
        if (strcmp(cfg->users[i].username, username) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    pppoe_user_t *u = &cfg->users[found_idx];
    u->enabled = enable;
    write_pppoe_secrets(cfg);

    /* If disabled, find and disconnect any active session for this user */
    if (!enable) {
        pppoe_active_session_t sessions[MAX_PPPOE_SESSIONS];
        uint32_t count = 0;
        pthread_mutex_unlock(&ctx->lock);
        pppoe_server_get_sessions(ctx, sessions, MAX_PPPOE_SESSIONS, &count);
        for (uint32_t i = 0; i < count; i++) {
            if (strcmp(sessions[i].username, username) == 0) {
                pppoe_server_disconnect_session(ctx, sessions[i].ifname);
                LOG_INFO("[Broadband] Disconnected active session %s for disabled user '%s'", sessions[i].ifname, username);
            }
        }
        return 0;
    }

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

void pppoe_server_periodic_tick(pppoe_server_ctx_t *ctx, uint64_t now_ms) {
    if (!ctx || !ctx->config->pppoe_server.enabled) return;
    static uint64_t last_check_ms = 0;
    if (now_ms - last_check_ms < 5000) return; /* Check every 5 seconds */
    last_check_ms = now_ms;

    time_t now_sec = time(NULL);
    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;

    /* Check if secrets need update due to expiry */
    bool secrets_need_update = false;
    for (uint32_t i = 0; i < cfg->user_count; i++) {
        const pppoe_user_t *u = &cfg->users[i];
        if (u->enabled && u->expires_at > 0 && (uint64_t)now_sec >= u->expires_at) {
            secrets_need_update = true;
            break;
        }
    }

    if (secrets_need_update) {
        pthread_mutex_lock(&ctx->lock);
        write_pppoe_secrets(cfg);
        pthread_mutex_unlock(&ctx->lock);
    }

    /* Check active sessions: if user is expired or disabled, kick them immediately! */
    pppoe_active_session_t sessions[MAX_PPPOE_SESSIONS];
    uint32_t count = 0;
    pppoe_server_get_sessions(ctx, sessions, MAX_PPPOE_SESSIONS, &count);
    for (uint32_t i = 0; i < count; i++) {
        for (uint32_t u = 0; u < cfg->user_count; u++) {
            if (strcmp(cfg->users[u].username, sessions[i].username) == 0) {
                if (!cfg->users[u].enabled || (cfg->users[u].expires_at > 0 && (uint64_t)now_sec >= cfg->users[u].expires_at)) {
                    LOG_WARN("[Broadband] Session %s belongs to %s subscriber '%s'! Disconnecting immediately...",
                             sessions[i].ifname,
                             !cfg->users[u].enabled ? "disabled" : "EXPIRED",
                             sessions[i].username);
                    pppoe_server_disconnect_session(ctx, sessions[i].ifname);
                }
                break;
            }
        }
    }
}

int pppoe_server_set_profile(pppoe_server_ctx_t *ctx, const pppoe_profile_t *profile) {
    if (!ctx || !profile || !profile->name[0]) return -1;
    pthread_mutex_lock(&ctx->lock);

    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;
    int found_idx = -1;
    for (uint32_t i = 0; i < cfg->profile_count; i++) {
        if (strcmp(cfg->profiles[i].name, profile->name) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx >= 0) {
        cfg->profiles[found_idx] = *profile;
    } else if (cfg->profile_count < MAX_PPPOE_PROFILES) {
        cfg->profiles[cfg->profile_count++] = *profile;
    } else {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int pppoe_server_delete_profile(pppoe_server_ctx_t *ctx, const char *name) {
    if (!ctx || !name || !name[0]) return -1;
    pthread_mutex_lock(&ctx->lock);

    pppoe_server_config_t *cfg = &ctx->config->pppoe_server;
    int found_idx = -1;
    for (uint32_t i = 0; i < cfg->profile_count; i++) {
        if (strcmp(cfg->profiles[i].name, name) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx >= 0) {
        for (uint32_t i = found_idx; i + 1 < cfg->profile_count; i++) {
            cfg->profiles[i] = cfg->profiles[i + 1];
        }
        cfg->profile_count--;
    }

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}
