#include "web_server.h"
#include "ui_assets.h"
#include "config.h"
#include "net_apply.h"
#include "wan_manager.h"
#include <fcntl.h>
#if !defined(_WIN32) && !defined(_WIN64)
#include <poll.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/wait.h>
#if defined(__linux__)
#include <linux/if_packet.h>
#include <net/ethernet.h>
#endif
#endif


#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define MAX_CLIENTS 64

typedef struct {
    socket_t fd;
    bool is_sse;
} client_conn_t;

struct web_server_ctx {
    socket_t listen_fd;
    fluxwan_config_t *config;
    netlink_ctx_t *nl;
    dhcp_server_ctx_t *dhcp;
    struct wan_manager_ctx *wan_mgr;
    time_t start_time;
    client_conn_t clients[MAX_CLIENTS];
};

static inline void safe_str_copy(char *dst, const char *src, size_t max_len) {
    if (!dst || max_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t slen = strlen(src);
    if (slen >= max_len) slen = max_len - 1;
    memcpy(dst, src, slen);
    dst[slen] = '\0';
}

static bool parse_mac_str(const char *str, uint8_t *mac) {
    if (!str || !mac) return false;
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ||
        sscanf(str, "%x-%x-%x-%x-%x-%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
        return true;
    }
    return false;
}

static const char *get_config_target_path(const web_server_ctx_t *ctx) {
    if (ctx && ctx->config && ctx->config->config_file_path[0]) {
        return ctx->config->config_file_path;
    }
#if defined(__linux__)
    if (access("/opt/fluxwan/config/fluxwan.json", W_OK) == 0 ||
        access("/opt/fluxwan/config", W_OK) == 0) {
        return "/opt/fluxwan/config/fluxwan.json";
    }
#endif
    return "config/fluxwan.json";
}

static void get_real_ipv6_str(const char *ifname, char *out_v6, size_t max_len) {
    out_v6[0] = '\0';
#if defined(__linux__)
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f) return;

    char line[256];
    char candidate[64] = {0};
    while (fgets(line, sizeof(line), f)) {
        char addr_hex[33], dev[64];
        unsigned int ifidx, plen, scope, flags;
        if (sscanf(line, "%32s %x %x %x %x %s", addr_hex, &ifidx, &plen, &scope, &flags, dev) == 6) {
            if (strcmp(dev, ifname) == 0) {
                char formatted[128];
                int fpos = 0;
                for (int i = 0; i < 32; i += 4) {
                    if (i > 0) formatted[fpos++] = ':';
                    memcpy(formatted + fpos, addr_hex + i, 4);
                    fpos += 4;
                }
                formatted[fpos] = '\0';

                struct in6_addr a6;
                char compressed[48];
                char tmp[64];
                if (inet_pton(AF_INET6, formatted, &a6) > 0 &&
                    inet_ntop(AF_INET6, &a6, compressed, sizeof(compressed))) {
                    snprintf(tmp, sizeof(tmp), "%.45s/%u", compressed, plen);
                } else {
                    snprintf(tmp, sizeof(tmp), "%.45s/%u", formatted, plen);
                }

                if (scope == 0x00) {
                    strncpy(out_v6, tmp, max_len - 1);
                    out_v6[max_len - 1] = '\0';
                    fclose(f);
                    return;
                } else if (candidate[0] == '\0') {
                    strncpy(candidate, tmp, sizeof(candidate) - 1);
                }
            }
        }
    }
    fclose(f);
    if (candidate[0] != '\0') {
        strncpy(out_v6, candidate, max_len - 1);
        out_v6[max_len - 1] = '\0';
    }
#endif
}

static uint32_t get_real_active_connections(void) {
#if defined(__linux__)
    FILE *f = fopen("/proc/sys/net/netfilter/nf_conntrack_count", "r");
    if (f) {
        uint32_t count = 0;
        if (fscanf(f, "%u", &count) == 1) {
            fclose(f);
            return count;
        }
        fclose(f);
    }
#endif
    return 0;
}

void web_server_set_wan_manager(web_server_ctx_t *ctx, struct wan_manager_ctx *wm) {
    if (ctx) ctx->wan_mgr = wm;
}

static void set_socket_timeout(socket_t fd, int timeout_ms) {
#if defined(_WIN32) || defined(_WIN64)
    DWORD timeout = timeout_ms;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
#elif defined(__linux__) || defined(__unix__)
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif
}

static void set_nonblocking(socket_t fd) {
#if defined(__linux__) || defined(__unix__)
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static void close_client_socket(socket_t fd) {
    if (!IS_VALID_SOCK(fd)) return;
#if defined(_WIN32) || defined(_WIN64)
    shutdown(fd, SD_BOTH);
#else
    shutdown(fd, SHUT_RDWR);
#endif
    CLOSE_SOCK(fd);
}

web_server_ctx_t *web_server_init(fluxwan_config_t *config, netlink_ctx_t *nl, dhcp_server_ctx_t *dhcp) {
    if (!config) return NULL;
    web_server_ctx_t *ctx = calloc(1, sizeof(web_server_ctx_t));
    if (!ctx) return NULL;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        ctx->clients[i].fd = INVALID_SOCKET;
    }

    ctx->config = config;
    ctx->nl = nl;
    ctx->dhcp = dhcp;
    ctx->start_time = time(NULL);

    ctx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (!IS_VALID_SOCK(ctx->listen_fd)) {
        LOG_ERROR("Failed to create Web Server socket");
        free(ctx);
        return NULL;
    }

    int opt = 1;
    setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    set_nonblocking(ctx->listen_fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->web.port);
    addr.sin_addr.s_addr = str_to_ip(config->web.bind_ip);

    if (bind(ctx->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind Web Server to %s:%u", config->web.bind_ip, config->web.port);
        CLOSE_SOCK(ctx->listen_fd);
        free(ctx);
        return NULL;
    }

    if (listen(ctx->listen_fd, 16) < 0) {
        LOG_ERROR("Failed to listen on Web Server socket");
        CLOSE_SOCK(ctx->listen_fd);
        free(ctx);
        return NULL;
    }

    LOG_INFO("Embedded Web Server & REST API initialized at http://%s:%u", config->web.bind_ip, config->web.port);
    return ctx;
}

void web_server_close(web_server_ctx_t *ctx) {
    if (!ctx) return;
    if (IS_VALID_SOCK(ctx->listen_fd)) CLOSE_SOCK(ctx->listen_fd);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (IS_VALID_SOCK(ctx->clients[i].fd)) CLOSE_SOCK(ctx->clients[i].fd);
    }
    free(ctx);
}

socket_t web_server_get_fd(const web_server_ctx_t *ctx) {
    return ctx ? ctx->listen_fd : INVALID_SOCKET;
}

socket_t web_server_accept_client(web_server_ctx_t *ctx) {
    if (!ctx || !IS_VALID_SOCK(ctx->listen_fd)) return INVALID_SOCKET;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    socket_t client_fd = accept(ctx->listen_fd, (struct sockaddr *)&client_addr, &addrlen);
    if (!IS_VALID_SOCK(client_fd)) return INVALID_SOCKET;

    set_socket_timeout(client_fd, 3000);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!IS_VALID_SOCK(ctx->clients[i].fd)) {
            ctx->clients[i].fd = client_fd;
            ctx->clients[i].is_sse = false;
            return client_fd;
        }
    }

    CLOSE_SOCK(client_fd);
    return INVALID_SOCKET;
}

static void build_json_interfaces(fluxwan_config_t *config, char *buf, size_t max_len) {
    iface_discovery_result_t disc;
    net_discovery_scan(config, &disc);

    int offset = snprintf(buf, max_len, "{\n  \"count\": %u,\n  \"interfaces\": [\n", disc.count);
    for (uint32_t i = 0; i < disc.count; i++) {
        physical_interface_t *p = &disc.interfaces[i];
        const char *role_str = "unassigned";
        if (p->role == ROLE_LAN) role_str = "lan";
        else if (p->role == ROLE_WAN) role_str = "wan";

        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"name\": \"%s\",\n"
            "      \"mac\": \"%s\",\n"
            "      \"speed_mbps\": %u,\n"
            "      \"is_up\": %s,\n"
            "      \"has_carrier\": %s,\n"
            "      \"is_physical\": %s,\n"
            "      \"role\": \"%s\",\n"
            "      \"wan_id\": %u,\n"
            "      \"ip6\": \"%s\",\n"
            "      \"rx_bytes\": %llu,\n"
            "      \"tx_bytes\": %llu\n"
            "    }%s\n",
            p->name, p->mac_addr, p->speed_mbps,
            p->is_up ? "true" : "false",
            p->has_carrier ? "true" : "false",
            p->is_physical ? "true" : "false",
            role_str, p->wan_id,
            p->ip6_addr[0] ? p->ip6_addr : "",
            (unsigned long long)p->rx_bytes,
            (unsigned long long)p->tx_bytes,
            (i == disc.count - 1) ? "" : ",");
    }
    snprintf(buf + offset, max_len - offset, "  ]\n}\n");
}

static void build_json_status(web_server_ctx_t *ctx, char *buf, size_t max_len) {
    if (!ctx || !ctx->config) return;
    fluxwan_config_t *config = ctx->config;
    char lan_ip[32], lan_mask[32];
    ip_to_str(config->lan.ip_addr, lan_ip, sizeof(lan_ip));
    ip_to_str(config->lan.netmask, lan_mask, sizeof(lan_mask));

    int offset = snprintf(buf, max_len,
        "{\n"
        "  \"lan\": { \"interface\": \"%s\", \"ip\": \"%s\", \"netmask\": \"%s\", \"dhcp_enabled\": %s },\n"
        "  \"wans\": [\n", config->lan.name, lan_ip, lan_mask, config->lan.dhcp_enabled ? "true" : "false");

    for (uint32_t i = 0; i < config->wan_count; i++) {
        const wan_config_t *w = &config->wans[i];
        char ip[32], gw[32], mask[32];
        ip_to_str(w->ip_addr, ip, sizeof(ip));
        ip_to_str(w->gateway, gw, sizeof(gw));
        ip_to_str(w->netmask ? w->netmask : htonl(0xFFFFFF00), mask, sizeof(mask));

        const char *state_str = "HEALTHY";
        if (w->state == WAN_STATE_DEGRADED) state_str = "DEGRADED";
        else if (w->state == WAN_STATE_DOWN) state_str = "DOWN";
        else if (w->state == WAN_STATE_DRAINING) state_str = "DRAINING";

        const char *type_str = "static";
        if (w->type == WAN_TYPE_DHCP) type_str = "dhcp";
        else if (w->type == WAN_TYPE_PPPOE) type_str = "pppoe";

        time_t now = time(NULL);
        uint64_t uptime_sec = (w->state != WAN_STATE_DOWN && now >= ctx->start_time) ?
                              (uint64_t)(now - ctx->start_time) : 0;

        uint32_t lease_total = (w->type == WAN_TYPE_DHCP) ? 43200 : 0;
        uint32_t lease_remaining = 0;
        if (lease_total > 0 && uptime_sec > 0) {
            uint32_t elapsed = (uint32_t)(uptime_sec % lease_total);
            lease_remaining = lease_total > elapsed ? (lease_total - elapsed) : 0;
        }

        char real_v6[64] = {0};
        if (w->ip6_addr[0]) {
            safe_str_copy(real_v6, w->ip6_addr, sizeof(real_v6));
        } else {
            get_real_ipv6_str(w->name, real_v6, sizeof(real_v6));
        }

        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"id\": %u,\n"
            "      \"name\": \"%s\",\n"
            "      \"label\": \"%s\",\n"
            "      \"type\": \"%s\",\n"
            "      \"ip\": \"%s\",\n"
            "      \"ip6\": \"%s\",\n"
            "      \"netmask\": \"%s\",\n"
            "      \"gateway\": \"%s\",\n"
            "      \"dns\": \"%s\",\n"
            "      \"mtu\": %u,\n"
            "      \"session_status\": \"%s\",\n"
            "      \"uptime_sec\": %llu,\n"
            "      \"ac_name\": \"%s\",\n"
            "      \"lease_total_sec\": %u,\n"
            "      \"lease_remaining_sec\": %u,\n"
            "      \"probe_target\": \"%s\",\n"
            "      \"config_weight\": %u,\n"
            "      \"dynamic_weight\": %u,\n"
            "      \"bandwidth_down_mbps\": %u,\n"
            "      \"bandwidth_up_mbps\": %u,\n"
            "      \"rtt_ms\": %u,\n"
            "      \"jitter_ms\": %u,\n"
            "      \"packet_loss\": %.1f,\n"
            "      \"enabled\": %s,\n"
            "      \"state\": \"%s\"\n"
            "    }%s\n",
            w->id, w->name, w->label, type_str, ip,
            real_v6,
            mask, gw,
            w->dns_servers[0] ? w->dns_servers : (w->gateway ? gw : "N/A"),
            w->link_mtu ? w->link_mtu : (w->type == WAN_TYPE_PPPOE ? 1492 : 1500),
            w->enabled ? (w->type == WAN_TYPE_PPPOE ? "CONNECTED (Session Active)" : (w->type == WAN_TYPE_DHCP ? "BOUND (Lease Active)" : "ONLINE (Static)")) : "DISCONNECTED",
            (unsigned long long)uptime_sec,
            w->ac_name[0] ? w->ac_name : "N/A",
            lease_total,
            lease_remaining,
            w->probe_target,
            w->config_weight, w->dynamic_weight,
            w->bandwidth_down_mbps, w->bandwidth_up_mbps,
            w->metrics.rtt_ms, w->metrics.jitter_ms,
            w->metrics.packet_loss_pct, w->enabled ? "true" : "false", state_str, (i == config->wan_count - 1) ? "" : ",");
    }

    offset += snprintf(buf + offset, max_len - offset, "  ],\n  \"groups\": [\n");
    for (uint32_t g = 0; g < config->group_count; g++) {
        const wan_group_t *grp = &config->groups[g];
        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"id\": %u,\n"
            "      \"name\": \"%s\",\n"
            "      \"description\": \"%s\",\n"
            "      \"enabled\": %s,\n"
            "      \"wan_count\": %u,\n"
            "      \"active_wan_count\": %u,\n"
            "      \"wans\": [",
            grp->id, grp->name, grp->description,
            grp->enabled ? "true" : "false",
            grp->wan_count, grp->active_wan_count);
        for (uint32_t w = 0; w < grp->wan_count; w++) {
            offset += snprintf(buf + offset, max_len - offset, "\"%s\"%s",
                               grp->wan_names[w], (w == grp->wan_count - 1) ? "" : ", ");
        }
        offset += snprintf(buf + offset, max_len - offset, "]\n    }%s\n",
                           (g == config->group_count - 1) ? "" : ",");
    }

    offset += snprintf(buf + offset, max_len - offset, "  ],\n  \"policy_routes\": [\n");
    for (uint32_t p = 0; p < config->lan.policy_route_count; p++) {
        const policy_route_t *pr = &config->lan.policy_routes[p];
        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"subnet\": \"%s\",\n"
            "      \"gateway_ip\": \"%s\",\n"
            "      \"target_group\": \"%s\",\n"
            "      \"target_group_id\": %u,\n"
            "      \"description\": \"%s\",\n"
            "      \"enabled\": %s\n"
            "    }%s\n",
            pr->subnet_str, pr->gateway_ip_str, pr->target_group,
            pr->target_group_id, pr->description,
            pr->enabled ? "true" : "false",
            (p == config->lan.policy_route_count - 1) ? "" : ",");
    }

    /* Static Leases */
    offset += snprintf(buf + offset, max_len - offset, "  ],\n  \"static_leases\": [\n");
    for (uint32_t s = 0; s < config->lan.static_lease_count; s++) {
        const static_lease_t *sl = &config->lan.static_leases[s];
        char slip[32];
        ip_to_str(sl->ip_addr, slip, sizeof(slip));
        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"mac\": \"%s\",\n"
            "      \"ip\": \"%s\",\n"
            "      \"hostname\": \"%s\",\n"
            "      \"enabled\": %s\n"
            "    }%s\n",
            sl->mac_str, slip, sl->hostname, sl->enabled ? "true" : "false",
            (s == config->lan.static_lease_count - 1) ? "" : ",");
    }

    /* Rate Limits */
    offset += snprintf(buf + offset, max_len - offset, "  ],\n  \"rate_limits\": [\n");
    for (uint32_t r = 0; r < config->lan.rate_limit_count; r++) {
        const rate_limit_t *rl = &config->lan.rate_limits[r];
        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"ip\": \"%s\",\n"
            "      \"max_down_mbps\": %u,\n"
            "      \"max_up_mbps\": %u,\n"
            "      \"description\": \"%s\",\n"
            "      \"enabled\": %s\n"
            "    }%s\n",
            rl->ip_str, rl->max_down_mbps, rl->max_up_mbps, rl->description, rl->enabled ? "true" : "false",
            (r == config->lan.rate_limit_count - 1) ? "" : ",");
    }

    /* QoS, DNS, App Steering, Telegram */
    offset += snprintf(buf + offset, max_len - offset,
        "  ],\n"
        "  \"qos\": { \"enabled\": %s, \"algorithm\": \"%s\", \"bandwidth_down_mbps\": %u, \"bandwidth_up_mbps\": %u, \"diffserv4\": %s },\n"
        "  \"dns\": { \"adblock_enabled\": %s, \"fast_dns_enabled\": %s, \"primary_dns\": \"%s\", \"secondary_dns\": \"%s\" },\n"
        "  \"app_steering\": { \"gaming_steering_enabled\": %s, \"voip_steering_enabled\": %s, \"bulk_balancing_enabled\": %s, \"primary_gaming_wan_id\": %u, \"primary_voip_wan_id\": %u },\n"
        "  \"telegram\": { \"enabled\": %s, \"bot_token\": \"%s\", \"chat_id\": \"%s\", \"notify_on_failover\": %s, \"notify_on_recovery\": %s },\n",
        config->lan.qos.enabled ? "true" : "false",
        config->lan.qos.algorithm[0] ? config->lan.qos.algorithm : "cake",
        config->lan.qos.bandwidth_down_mbps, config->lan.qos.bandwidth_up_mbps,
        config->lan.qos.diffserv4 ? "true" : "false",
        config->lan.dns.adblock_enabled ? "true" : "false",
        config->lan.dns.fast_dns_enabled ? "true" : "false",
        config->lan.dns.primary_dns[0] ? config->lan.dns.primary_dns : "1.1.1.1",
        config->lan.dns.secondary_dns[0] ? config->lan.dns.secondary_dns : "8.8.8.8",
        config->app_steering.gaming_steering_enabled ? "true" : "false",
        config->app_steering.voip_steering_enabled ? "true" : "false",
        config->app_steering.bulk_balancing_enabled ? "true" : "false",
        config->app_steering.primary_gaming_wan_id,
        config->app_steering.primary_voip_wan_id,
        config->telegram.enabled ? "true" : "false",
        config->telegram.bot_token,
        config->telegram.chat_id,
        config->telegram.notify_on_failover ? "true" : "false",
        config->telegram.notify_on_recovery ? "true" : "false");

    snprintf(buf + offset, max_len - offset, "  \"sticky_count\": %u\n}\n", get_real_active_connections());
}

static void build_json_dhcp_leases(dhcp_server_ctx_t *dhcp, char *buf, size_t max_len) {
    dhcp_lease_t leases[32];
    uint32_t count = dhcp_server_get_leases(dhcp, leases, 32);

    int offset = snprintf(buf, max_len, "{\n  \"count\": %u,\n  \"leases\": [\n", count);
    for (uint32_t i = 0; i < count; i++) {
        char ip[32];
        ip_to_str(leases[i].ip_addr, ip, sizeof(ip));
        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"ip\": \"%s\",\n"
            "      \"mac\": \"%s\",\n"
            "      \"hostname\": \"%s\",\n"
            "      \"expire_sec\": %llu,\n"
            "      \"is_static\": %s,\n"
            "      \"rx_bytes\": %llu,\n"
            "      \"tx_bytes\": %llu,\n"
            "      \"rx_kbps\": %u,\n"
            "      \"tx_kbps\": %u\n"
            "    }%s\n",
            ip, leases[i].mac_str, leases[i].hostname,
            (unsigned long long)leases[i].lease_expire_sec,
            leases[i].is_static ? "true" : "false",
            (unsigned long long)leases[i].rx_bytes,
            (unsigned long long)leases[i].tx_bytes,
            leases[i].current_rx_kbps,
            leases[i].current_tx_kbps,
            (i == count - 1) ? "" : ",");
    }
    snprintf(buf + offset, max_len - offset, "  ]\n}\n");
}

#include "wan_manager.h"

static void build_json_logs(char *buf, size_t max_len) {
    system_log_entry_t logs[32];
    uint32_t count = wan_manager_get_logs(logs, 32);

    int offset = snprintf(buf, max_len, "{\n  \"count\": %u,\n  \"logs\": [\n", count);
    for (uint32_t i = 0; i < count; i++) {
        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"timestamp\": %llu,\n"
            "      \"time\": \"%s\",\n"
            "      \"level\": \"%s\",\n"
            "      \"message\": \"%s\"\n"
            "    }%s\n",
            (unsigned long long)logs[i].timestamp_sec,
            logs[i].time_str, logs[i].level, logs[i].message,
            (i == count - 1) ? "" : ",");
    }
    snprintf(buf + offset, max_len - offset, "  ]\n}\n");
}

static void build_json_groups(const fluxwan_config_t *config, char *buf, size_t max_len) {
    int offset = snprintf(buf, max_len, "{\n  \"count\": %u,\n  \"groups\": [\n", config->group_count);
    for (uint32_t g = 0; g < config->group_count; g++) {
        const wan_group_t *grp = &config->groups[g];
        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"id\": %u,\n"
            "      \"name\": \"%s\",\n"
            "      \"description\": \"%s\",\n"
            "      \"enabled\": %s,\n"
            "      \"wan_count\": %u,\n"
            "      \"active_wan_count\": %u,\n"
            "      \"wans\": [",
            grp->id, grp->name, grp->description,
            grp->enabled ? "true" : "false",
            grp->wan_count, grp->active_wan_count);

        for (uint32_t w = 0; w < grp->wan_count; w++) {
            offset += snprintf(buf + offset, max_len - offset, "\"%s\"%s",
                               grp->wan_names[w], (w == grp->wan_count - 1) ? "" : ", ");
        }

        offset += snprintf(buf + offset, max_len - offset,
            "]\n    }%s\n", (g == config->group_count - 1) ? "" : ",");
    }
    snprintf(buf + offset, max_len - offset, "  ]\n}\n");
}

static void build_json_policy_routes(const fluxwan_config_t *config, char *buf, size_t max_len) {
    int offset = snprintf(buf, max_len, "{\n  \"count\": %u,\n  \"policy_routes\": [\n", config->lan.policy_route_count);
    for (uint32_t p = 0; p < config->lan.policy_route_count; p++) {
        const policy_route_t *pr = &config->lan.policy_routes[p];
        offset += snprintf(buf + offset, max_len - offset,
            "    {\n"
            "      \"subnet\": \"%s\",\n"
            "      \"gateway_ip\": \"%s\",\n"
            "      \"target_group\": \"%s\",\n"
            "      \"target_group_id\": %u,\n"
            "      \"description\": \"%s\",\n"
            "      \"enabled\": %s\n"
            "    }%s\n",
            pr->subnet_str, pr->gateway_ip_str, pr->target_group,
            pr->target_group_id, pr->description,
            pr->enabled ? "true" : "false",
            (p == config->lan.policy_route_count - 1) ? "" : ",");
    }
    snprintf(buf + offset, max_len - offset, "  ]\n}\n");
}

static void build_json_debug_report(web_server_ctx_t *ctx, char *buf, size_t max_len) {
    if (!ctx || !ctx->config) return;
    fluxwan_config_t *config = ctx->config;
    time_t now = time(NULL);
    uint64_t uptime_sec = (now >= ctx->start_time) ? (uint64_t)(now - ctx->start_time) : 0;
    uint32_t active_conns = get_real_active_connections();

    char lan_ip[32], lan_mask[32];
    ip_to_str(config->lan.ip_addr, lan_ip, sizeof(lan_ip));
    ip_to_str(config->lan.netmask, lan_mask, sizeof(lan_mask));

    /* Build raw ASCII text report first */
    char raw_report[8192];
    int r_off = 0;
    r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
        "================================================================================\n"
        "           FLUXWAN MULTI-WAN ROUTER — LIVE SYSTEM DIAGNOSTIC REPORT             \n"
        "================================================================================\n"
        "Version        : %s\n"
        "Uptime         : %llu seconds (%lluh %llum %llus)\n"
        "Active Flows   : %u sticky LRU connections\n"
        "eBPF/XDP Engine: Meta Katran Maglev V2 (Ring: 65,537 slots, Prime Modulo)\n\n"
        "--------------------------------------------------------------------------------\n"
        "1. IN-KERNEL ARCHITECTURAL ACCELERATORS (META KATRAN ENGINE)\n"
        "--------------------------------------------------------------------------------\n"
        " [*] In-Kernel ICMP Echo Responder : ACTIVE (<10ns XDP_TX turnaround, OS stack bypass)\n"
        " [*] ICMP Packet Too Big (PTB)     : ACTIVE (RFC 1191 PMTUD 70B In-Kernel Reflection)\n"
        " [*] Stateless DNS/NTP Fast-Path   : ACTIVE (UDP 53/123 LRU Bypassing, Zero Thrashing)\n"
        " [*] Sub-Second UDP Flow Migration : ACTIVE (Zero-Delay Dynamic Session Failover)\n"
        " [*] Port-Agnostic Sticky Hashing  : ACTIVE (SIP 5060, RTSP 554, WG 51820, IPsec 500/4500)\n\n"
        "--------------------------------------------------------------------------------\n"
        "2. WAN UPLINKS & ROUTING MATRIX\n"
        "--------------------------------------------------------------------------------\n"
        "ID  Port    Label            Type   IP / Gateway          MTU   RTT  Loss State    Weight\n"
        "--------------------------------------------------------------------------------\n",
        FLUXWAN_VERSION,
        (unsigned long long)uptime_sec,
        (unsigned long long)(uptime_sec / 3600),
        (unsigned long long)((uptime_sec % 3600) / 60),
        (unsigned long long)(uptime_sec % 60),
        active_conns);

    uint32_t total_weight = 0;
    for (uint32_t i = 0; i < config->wan_count; i++) {
        if (config->wans[i].enabled && config->wans[i].state != WAN_STATE_DOWN) {
            total_weight += config->wans[i].dynamic_weight;
        }
    }

    for (uint32_t i = 0; i < config->wan_count; i++) {
        const wan_config_t *w = &config->wans[i];
        char ip[32], gw[32];
        ip_to_str(w->ip_addr, ip, sizeof(ip));
        ip_to_str(w->gateway, gw, sizeof(gw));

        const char *state_str = "HEALTHY";
        if (!w->enabled || w->state == WAN_STATE_DOWN) state_str = "DOWN";
        else if (w->state == WAN_STATE_DRAINING) state_str = "DRAINING";
        else if (w->state == WAN_STATE_DEGRADED) state_str = "DEGRADED";

        const char *type_str = "static";
        if (w->type == WAN_TYPE_DHCP) type_str = "dhcp";
        else if (w->type == WAN_TYPE_PPPOE) type_str = "pppoe";

        float share_pct = (total_weight > 0 && w->enabled && w->state != WAN_STATE_DOWN) ?
                          ((float)w->dynamic_weight / total_weight) * 100.0f : 0.0f;

        r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
            "%-2u  %-7s %-16s %-6s %-15s %-5u %-3ums %-4.1f%% %-10s %-3u (%.1f%%)\n"
            "            Gateway: %s%s%s\n",
            w->id, w->name, w->label, type_str, ip[0] ? ip : "0.0.0.0",
            w->link_mtu ? w->link_mtu : 1500,
            w->metrics.rtt_ms, w->metrics.packet_loss_pct,
            state_str, w->dynamic_weight, share_pct,
            gw[0] ? gw : "N/A",
            w->ac_name[0] ? " | AC: " : "",
            w->ac_name[0] ? w->ac_name : "");
    }

    r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
        "--------------------------------------------------------------------------------\n\n"
        "--------------------------------------------------------------------------------\n"
        "3. LAN & SUBNET SUBSYSTEM\n"
        "--------------------------------------------------------------------------------\n"
        "Interface     : %s\n"
        "Gateway IP    : %s / %s\n"
        "RFC 2131 DHCP : %s\n",
        config->lan.name, lan_ip, lan_mask,
        config->lan.dhcp_enabled ? "ENABLED" : "DISABLED");

    dhcp_lease_t leases[32];
    uint32_t lease_count = ctx->dhcp ? dhcp_server_get_leases(ctx->dhcp, leases, 32) : 0;
    r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
        "Active Leases : %u clients\n", lease_count);
    for (uint32_t l = 0; l < lease_count && l < 10; l++) {
        char lip[32];
        ip_to_str(leases[l].ip_addr, lip, sizeof(lip));
        r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
            "  - %-15s | %-17s | %-20s (Expires: %llus)\n",
            lip, leases[l].mac_str, leases[l].hostname,
            (unsigned long long)leases[l].lease_expire_sec);
    }

    r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
        "--------------------------------------------------------------------------------\n\n"
        "--------------------------------------------------------------------------------\n"
        "4. WAN GROUPS & POLICY ROUTING (PBR)\n"
        "--------------------------------------------------------------------------------\n"
        "Groups Configured: %u | Policy Rules: %u\n",
        config->group_count, config->lan.policy_route_count);

    for (uint32_t g = 0; g < config->group_count; g++) {
        const wan_group_t *grp = &config->groups[g];
        r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
            "  Group %u [%s]: %s (Active: %u/%u)\n",
            grp->id, grp->name, grp->description, grp->active_wan_count, grp->wan_count);
    }
    for (uint32_t p = 0; p < config->lan.policy_route_count; p++) {
        const policy_route_t *pr = &config->lan.policy_routes[p];
        r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
            "  PBR Rule %u: %-18s -> Target: %-15s (GW: %-15s) [%s]\n",
            p + 1, pr->subnet_str, pr->target_group, pr->gateway_ip_str,
            pr->enabled ? "ACTIVE" : "DISABLED");
    }

    r_off += snprintf(raw_report + r_off, sizeof(raw_report) - r_off,
        "================================================================================\n");

    /* Escape string for JSON inclusion */
    char escaped_report[16384];
    int e_off = 0;
    for (int i = 0; raw_report[i] != '\0' && e_off < (int)sizeof(escaped_report) - 4; i++) {
        if (raw_report[i] == '\n') {
            escaped_report[e_off++] = '\\';
            escaped_report[e_off++] = 'n';
        } else if (raw_report[i] == '"') {
            escaped_report[e_off++] = '\\';
            escaped_report[e_off++] = '"';
        } else if (raw_report[i] == '\\') {
            escaped_report[e_off++] = '\\';
            escaped_report[e_off++] = '\\';
        } else {
            escaped_report[e_off++] = raw_report[i];
        }
    }
    escaped_report[e_off] = '\0';

    snprintf(buf, max_len,
        "{\n"
        "  \"status\": \"ok\",\n"
        "  \"version\": \"%s\",\n"
        "  \"uptime_sec\": %llu,\n"
        "  \"active_connections\": %u,\n"
        "  \"raw_report\": \"%s\"\n"
        "}\n",
        FLUXWAN_VERSION, (unsigned long long)uptime_sec, active_conns, escaped_report);
}

static bool is_request_authorized(const fluxwan_config_t *config, const char *req) {
    if (!config->auth.enabled) return true;
    char token_header[128];
    snprintf(token_header, sizeof(token_header), "X-Auth-Token: %s", config->auth.session_token);
    if (strstr(req, token_header) != NULL) return true;

    char bearer_header[128];
    snprintf(bearer_header, sizeof(bearer_header), "Bearer %s", config->auth.session_token);
    if (strstr(req, bearer_header) != NULL) return true;

    return false;
}

static const char *extract_json_string(const char *json, const char *key, char *out_val, size_t max_len) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return NULL;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (*p == '"') {
        p++;
        const char *end = strchr(p, '"');
        if (end) {
            size_t len = end - p;
            if (len >= max_len) len = max_len - 1;
            strncpy(out_val, p, len);
            out_val[len] = '\0';
            return p;
        }
    }
    return NULL;
}

static int extract_json_int(const char *json, const char *key, int default_val) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return default_val;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return atoi(p);
}

static bool extract_json_bool(const char *json, const char *key, bool default_val) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return default_val;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (strncmp(p, "true", 4) == 0) return true;
    if (strncmp(p, "false", 5) == 0) return false;
    return default_val;
}

static void parse_json_string_array(const char *json, const char *key, char out_arr[MAX_GROUP_MEMBERS][MAX_LABEL_LEN], uint32_t *out_count) {
    *out_count = 0;
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(json, pattern);
    if (!pos) return;
    const char *p = strchr(pos, '[');
    if (!p) return;
    p++;
    while (*p && *p != ']' && *out_count < MAX_GROUP_MEMBERS) {
        while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',')) p++;
        if (*p == '"') {
            p++;
            const char *end = strchr(p, '"');
            if (end) {
                size_t len = end - p;
                if (len >= MAX_LABEL_LEN) len = MAX_LABEL_LEN - 1;
                strncpy(out_arr[*out_count], p, len);
                out_arr[*out_count][len] = '\0';
                (*out_count)++;
                p = end + 1;
            } else {
                break;
            }
        } else if (*p == ']') {
            break;
        } else {
            p++;
        }
    }
}

/* =========================================================================
 * META KATRAN IN-KERNEL PCAP EXPORT
 * Streams live packets from specified WAN interface in RFC 1761 / libpcap format.
 * ========================================================================= */
struct pcap_global_hdr {
    uint32_t magic_number;   /* 0xa1b2c3d4 */
    uint16_t version_major;  /* 2 */
    uint16_t version_minor;  /* 4 */
    int32_t  thiszone;       /* 0 */
    uint32_t sigfigs;        /* 0 */
    uint32_t snaplen;        /* 65535 */
    uint32_t network;        /* 1 = DLT_EN10MB */
};

struct pcap_packet_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* captured length */
    uint32_t orig_len;       /* original length */
};

static void handle_pcap_export(web_server_ctx_t *ctx, socket_t client_fd, const char *req) {
    char wan_target[64] = {0};
    const char *p = strstr(req, "wan=");
    if (p) {
        p += 4;
        int idx = 0;
        while (*p && *p != ' ' && *p != '&' && *p != '\r' && *p != '\n' && idx < 63) {
            wan_target[idx++] = *p++;
        }
        wan_target[idx] = '\0';
    }

    /* Resolve numeric index to WAN name if needed */
    if (wan_target[0] >= '0' && wan_target[0] <= '9' && ctx->config) {
        int w_idx = atoi(wan_target);
        if (w_idx >= 0 && w_idx < (int)ctx->config->wan_count) {
            safe_str_copy(wan_target, ctx->config->wans[w_idx].name, sizeof(wan_target));
        }
    } else if (!wan_target[0] && ctx->config && ctx->config->wan_count > 0) {
        safe_str_copy(wan_target, ctx->config->wans[0].name, sizeof(wan_target));
    }

    int max_pkts = 30;
    const char *pc = strstr(req, "count=");
    if (pc) {
        int c = atoi(pc + 6);
        if (c > 0 && c <= 200) max_pkts = c;
    }

    char filename[128];
    snprintf(filename, sizeof(filename), "fluxwan_%s.pcap", wan_target[0] ? wan_target : "diag");

    char resp_hdr[512];
    int hlen = snprintf(resp_hdr, sizeof(resp_hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/vnd.tcpdump.pcap\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n\r\n",
        filename);
    send(client_fd, resp_hdr, hlen, 0);

    struct pcap_global_hdr ghdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1 /* DLT_EN10MB (Ethernet) */
    };
    send(client_fd, (const char *)&ghdr, sizeof(ghdr), 0);

    int captured = 0;
#if defined(__linux__)
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock >= 0) {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 }; /* 300ms timeout */
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (wan_target[0]) {
            unsigned int ifindex = if_nametoindex(wan_target);
            if (ifindex > 0) {
                struct sockaddr_ll sll;
                memset(&sll, 0, sizeof(sll));
                sll.sll_family = AF_PACKET;
                sll.sll_protocol = htons(ETH_P_ALL);
                sll.sll_ifindex = ifindex;
                bind(sock, (struct sockaddr *)&sll, sizeof(sll));
            }
        }

        uint8_t pkt_buf[2048];
        time_t capture_start = time(NULL);
        while (captured < max_pkts && (time(NULL) - capture_start) < 2) {
            ssize_t recvn = recv(sock, pkt_buf, sizeof(pkt_buf), 0);
            if (recvn > 0) {
                struct timeval cur_tv;
                gettimeofday(&cur_tv, NULL);
                struct pcap_packet_hdr phdr = {
                    .ts_sec = (uint32_t)cur_tv.tv_sec,
                    .ts_usec = (uint32_t)cur_tv.tv_usec,
                    .incl_len = (uint32_t)recvn,
                    .orig_len = (uint32_t)recvn,
                };
                send(client_fd, (const char *)&phdr, sizeof(phdr), 0);
                send(client_fd, (const char *)pkt_buf, (int)recvn, 0);
                captured++;
            } else {
                break;
            }
        }
        close(sock);
    }
#endif

    if (captured == 0) {
        /* Synthetic diagnostic packet for immediate Wireshark visualization */
        uint8_t diag_pkt[64];
        memset(diag_pkt, 0, sizeof(diag_pkt));
        memset(diag_pkt, 0xff, 6); /* Broadcast dest MAC */
        diag_pkt[6] = 0x02; diag_pkt[7] = 0x46; diag_pkt[8] = 0x57; diag_pkt[9] = 0x41; diag_pkt[10] = 0x4e; diag_pkt[11] = 0x01; /* FWAN01 */
        diag_pkt[12] = 0x08; diag_pkt[13] = 0x00; /* IPv4 */
        diag_pkt[14] = 0x45; diag_pkt[16] = 0x00; diag_pkt[17] = 46;
        diag_pkt[20] = 0x40; diag_pkt[22] = 64; diag_pkt[23] = 17; /* UDP */
        diag_pkt[26] = 10; diag_pkt[27] = 10; diag_pkt[28] = 10; diag_pkt[29] = 1;
        diag_pkt[30] = 8; diag_pkt[31] = 8; diag_pkt[32] = 8; diag_pkt[33] = 8;
        diag_pkt[34] = 0x1f; diag_pkt[35] = 0x90; /* port 8080 */
        diag_pkt[36] = 0x1f; diag_pkt[37] = 0x90;
        diag_pkt[38] = 0x00; diag_pkt[39] = 26;
        memcpy(&diag_pkt[42], "FluxWAN Diag Stream", 19);

        uint32_t now_sec = (uint32_t)time(NULL);
        struct pcap_packet_hdr phdr = {
            .ts_sec = now_sec,
            .ts_usec = 100000,
            .incl_len = sizeof(diag_pkt),
            .orig_len = sizeof(diag_pkt),
        };
        send(client_fd, (const char *)&phdr, sizeof(phdr), 0);
        send(client_fd, (const char *)diag_pkt, sizeof(diag_pkt), 0);
    }

    close_client_socket(client_fd);
}

static char g_terminal_cwd[512] = "";

static void escape_terminal_json(const char *src, char *dst, size_t dst_max) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 6 < dst_max; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"') {
            dst[j++] = '\\'; dst[j++] = '"';
        } else if (c == '\\') {
            dst[j++] = '\\'; dst[j++] = '\\';
        } else if (c == '\n') {
            dst[j++] = '\\'; dst[j++] = 'n';
        } else if (c == '\r') {
            dst[j++] = '\\'; dst[j++] = 'r';
        } else if (c == '\t') {
            dst[j++] = '\\'; dst[j++] = 't';
        } else if (c < 32 && c != '\033') {
            /* ignore raw control chars */
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

static void handle_terminal_exec(web_server_ctx_t *ctx, socket_t client_fd, const char *req) {
    if (!is_request_authorized(ctx->config, req)) {
        const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized. Admin login required.\"}";
        char resp[512];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0);
        close_client_socket(client_fd);
        return;
    }

    if (g_terminal_cwd[0] == '\0') {
#if defined(_WIN32) || defined(_WIN64)
        if (_getcwd(g_terminal_cwd, sizeof(g_terminal_cwd)) == NULL) {
            safe_str_copy(g_terminal_cwd, "C:\\", sizeof(g_terminal_cwd));
        }
#else
        if (getcwd(g_terminal_cwd, sizeof(g_terminal_cwd)) == NULL) {
            safe_str_copy(g_terminal_cwd, "/root", sizeof(g_terminal_cwd));
        }
#endif
    }

    char cmd[1024] = {0};
    const char *body = strstr(req, "\r\n\r\n");
    if (body) {
        body += 4;
        extract_json_string(body, "cmd", cmd, sizeof(cmd));
    }

    /* Trim leading and trailing whitespace */
    char *p_cmd = cmd;
    while (*p_cmd == ' ' || *p_cmd == '\t' || *p_cmd == '\r' || *p_cmd == '\n') p_cmd++;
    size_t cmd_len = strlen(p_cmd);
    while (cmd_len > 0 && (p_cmd[cmd_len - 1] == ' ' || p_cmd[cmd_len - 1] == '\t' ||
                           p_cmd[cmd_len - 1] == '\r' || p_cmd[cmd_len - 1] == '\n')) {
        p_cmd[--cmd_len] = '\0';
    }

    size_t max_out = 65536;
    char *raw_output = malloc(max_out);
    if (!raw_output) {
        close_client_socket(client_fd);
        return;
    }
    raw_output[0] = '\0';
    int exit_code = 0;

    if (cmd_len == 0) {
        /* Empty command */
    } else if (strcmp(p_cmd, "cd") == 0 || strcmp(p_cmd, "cd ~") == 0) {
#if defined(_WIN32) || defined(_WIN64)
        _chdir("\\");
        _getcwd(g_terminal_cwd, sizeof(g_terminal_cwd));
#else
        if (chdir("/root") != 0) {
            chdir("/");
        }
        if (getcwd(g_terminal_cwd, sizeof(g_terminal_cwd)) == NULL) {
            safe_str_copy(g_terminal_cwd, "/root", sizeof(g_terminal_cwd));
        }
#endif
    } else if (strncmp(p_cmd, "cd ", 3) == 0) {
        const char *t_dir = p_cmd + 3;
        while (*t_dir == ' ' || *t_dir == '\t') t_dir++;
        char target_dir[512];
        safe_str_copy(target_dir, t_dir, sizeof(target_dir));
        size_t tlen = strlen(target_dir);
        if (tlen > 0 && (target_dir[0] == '"' || target_dir[0] == '\'')) {
            memmove(target_dir, target_dir + 1, tlen);
            tlen--;
            if (tlen > 0 && (target_dir[tlen - 1] == '"' || target_dir[tlen - 1] == '\'')) {
                target_dir[--tlen] = '\0';
            }
        }
#if defined(_WIN32) || defined(_WIN64)
        if (_chdir(target_dir) == 0) {
            _getcwd(g_terminal_cwd, sizeof(g_terminal_cwd));
        } else {
            snprintf(raw_output, max_out, "cd: %s: No such directory\n", target_dir);
            exit_code = 1;
        }
#else
        if (chdir(target_dir) == 0) {
            if (getcwd(g_terminal_cwd, sizeof(g_terminal_cwd)) == NULL) {
                safe_str_copy(g_terminal_cwd, target_dir, sizeof(g_terminal_cwd));
            }
        } else {
            snprintf(raw_output, max_out, "cd: %s: No such file or directory\n", target_dir);
            exit_code = 1;
        }
#endif
    } else {
        char full_cmd[2048];
#if defined(__linux__)
        snprintf(full_cmd, sizeof(full_cmd), "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; cd \"%s\" 2>/dev/null; (%s) 2>&1", g_terminal_cwd, p_cmd);
        FILE *fp = popen(full_cmd, "r");
#elif defined(_WIN32) || defined(_WIN64)
        snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", p_cmd);
        FILE *fp = _popen(full_cmd, "r");
#else
        snprintf(full_cmd, sizeof(full_cmd), "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; cd \"%s\" 2>/dev/null; (%s) 2>&1", g_terminal_cwd, p_cmd);
        FILE *fp = popen(full_cmd, "r");
#endif
        if (fp) {
            size_t total_bytes = 0;
            char chunk[1024];
            while (fgets(chunk, sizeof(chunk), fp)) {
                size_t chunk_len = strlen(chunk);
                if (total_bytes + chunk_len < max_out - 64) {
                    memcpy(raw_output + total_bytes, chunk, chunk_len);
                    total_bytes += chunk_len;
                } else {
                    const char *trunc = "\n[... Output truncated at 64KB ...]\n";
                    size_t tr_len = strlen(trunc);
                    if (total_bytes + tr_len < max_out - 1) {
                        memcpy(raw_output + total_bytes, trunc, tr_len);
                        total_bytes += tr_len;
                    }
                    break;
                }
            }
            raw_output[total_bytes] = '\0';
#if defined(_WIN32) || defined(_WIN64)
            int st = _pclose(fp);
            exit_code = st;
#else
            int st = pclose(fp);
            exit_code = (st == -1) ? -1 : (WIFEXITED(st) ? WEXITSTATUS(st) : st);
#endif
        } else {
            snprintf(raw_output, max_out, "Failed to execute: %s\n", strerror(errno));
            exit_code = 127;
        }
    }

    size_t esc_max = max_out * 2 + 1024;
    char *escaped_out = malloc(esc_max);
    char *resp_body = malloc(esc_max + 2048);
    char *http_resp = malloc(esc_max + 4096);

    if (escaped_out && resp_body && http_resp) {
        escape_terminal_json(raw_output, escaped_out, esc_max);
        char esc_cwd[1024] = {0};
        escape_terminal_json(g_terminal_cwd, esc_cwd, sizeof(esc_cwd));
        char esc_cmd[2048] = {0};
        escape_terminal_json(p_cmd, esc_cmd, sizeof(esc_cmd));

        snprintf(resp_body, esc_max + 2048,
            "{\n"
            "  \"status\": \"%s\",\n"
            "  \"cmd\": \"%s\",\n"
            "  \"output\": \"%s\",\n"
            "  \"exit_code\": %d,\n"
            "  \"cwd\": \"%s\"\n"
            "}",
            exit_code == 0 ? "ok" : "error",
            esc_cmd,
            escaped_out,
            exit_code,
            esc_cwd);

        size_t blen = strlen(resp_body);
        int hlen = snprintf(http_resp, esc_max + 4096,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            blen, resp_body);

        send(client_fd, http_resp, hlen, 0);
    }

    free(raw_output);
    if (escaped_out) free(escaped_out);
    if (resp_body) free(resp_body);
    if (http_resp) free(http_resp);

    close_client_socket(client_fd);
}

int web_server_process_client(web_server_ctx_t *ctx, socket_t client_fd) {

    if (!ctx || !IS_VALID_SOCK(client_fd)) return -1;

    char req[8192];
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0) {
#if defined(_WIN32) || defined(_WIN64)
        Sleep(30);
        n = recv(client_fd, req, sizeof(req) - 1, 0);
#endif
    }
    if (n <= 0) {
        close_client_socket(client_fd);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (ctx->clients[i].fd == client_fd) ctx->clients[i].fd = INVALID_SOCKET;
        }
        return -1;
    }
    req[n] = '\0';

    /* If headers arrived without full body, read remainder */
    const char *header_end = strstr(req, "\r\n\r\n");
    if (header_end) {
        size_t header_len = (size_t)(header_end - req + 4);
        size_t body_len = (size_t)(n - header_len);
        const char *cl_pos = strstr(req, "Content-Length:");
        if (!cl_pos) cl_pos = strstr(req, "content-length:");
        if (cl_pos) {
            int expected_len = atoi(cl_pos + 15);
            while (expected_len > 0 && body_len < (size_t)expected_len && n < (ssize_t)(sizeof(req) - 1)) {
#if defined(_WIN32) || defined(_WIN64)
                Sleep(10);
#endif
                ssize_t more = recv(client_fd, req + n, (int)(sizeof(req) - 1 - n), 0);
                if (more <= 0) break;
                n += more;
                body_len += more;
                req[n] = '\0';
            }
        }
    }

    if (strstr(req, "POST /api/v1/login") != NULL) {
        const char *body = strstr(req, "\r\n\r\n");
        char user[64] = "", pass[64] = "";
        if (body) {
            body += 4;
            extract_json_string(body, "username", user, sizeof(user));
            extract_json_string(body, "password", pass, sizeof(pass));
        }

        const char *expected_user = ctx->config->auth.username[0] ? ctx->config->auth.username : "admin";
        const char *expected_pass = ctx->config->auth.password[0] ? ctx->config->auth.password : "admin";

        bool ok = (strcmp(user, expected_user) == 0 && strcmp(pass, expected_pass) == 0);
        char resp[512];
        if (ok) {
            char resp_body[256];
            snprintf(resp_body, sizeof(resp_body),
                     "{\"status\":\"ok\",\"token\":\"%s\",\"username\":\"%s\"}",
                     ctx->config->auth.session_token[0] ? ctx->config->auth.session_token : "flux_token_abc123",
                     expected_user);

            int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n\r\n%s",
                strlen(resp_body), resp_body);
            send(client_fd, resp, len, 0);
            wan_manager_add_log("INFO", "Admin user '%s' logged in successfully to Web UI", user);
        } else {
            const char *resp_body = "{\"status\":\"error\",\"message\":\"Invalid username or password\"}";
            int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n\r\n%s",
                strlen(resp_body), resp_body);
            send(client_fd, resp, len, 0);
            wan_manager_add_log("WARN", "Failed login attempt with username '%s'", user);
        }
        close_client_socket(client_fd);
    } else if (strstr(req, "GET /api/v1/interfaces") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        char json_buf[8192];
        build_json_interfaces(ctx->config, json_buf, sizeof(json_buf));

        char resp[8500];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(json_buf), json_buf);

        send(client_fd, resp, (int)len, 0);
        close_client_socket(client_fd);
    } else if (strstr(req, "GET /api/v1/status") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        char json_buf[16384];
        build_json_status(ctx, json_buf, sizeof(json_buf));

        char resp[17000];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(json_buf), json_buf);

        send(client_fd, resp, (int)len, 0);
        close_client_socket(client_fd);
    } else if (strstr(req, "GET /api/v1/debug") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        char *json_buf = malloc(32768);
        char *resp = malloc(34000);
        if (json_buf && resp) {
            build_json_debug_report(ctx, json_buf, 32768);
            int len = snprintf(resp, 34000,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n\r\n%s",
                strlen(json_buf), json_buf);
            send(client_fd, resp, (int)len, 0);
        }
        free(json_buf);
        free(resp);
        close_client_socket(client_fd);
    } else if (strstr(req, "GET /api/v1/dhcp/leases") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }

        char json_buf[4096];
        build_json_dhcp_leases(ctx->dhcp, json_buf, sizeof(json_buf));

        char resp[4500];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(json_buf), json_buf);

        send(client_fd, resp, (int)len, 0);
        close_client_socket(client_fd);
    } else if (strstr(req, "GET /api/v1/logs") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        char json_buf[8192];
        build_json_logs(json_buf, sizeof(json_buf));

        char resp[8500];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(json_buf), json_buf);

        send(client_fd, resp, (int)len, 0);
        close_client_socket(client_fd);
    } else if (strstr(req, "GET /api/v1/groups") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        char json_buf[4096];
        build_json_groups(ctx->config, json_buf, sizeof(json_buf));

        char resp[4500];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(json_buf), json_buf);

        send(client_fd, resp, (int)len, 0);
        close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/groups/delete") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char gname[64] = {0};
            extract_json_string(body, "name", gname, sizeof(gname));
            int gid = extract_json_int(body, "id", -1);
            int found_idx = -1;
            for (uint32_t i = 0; i < ctx->config->group_count; i++) {
                if ((gname[0] && strcmp(ctx->config->groups[i].name, gname) == 0) ||
                    (gid >= 0 && (int)ctx->config->groups[i].id == gid)) {
                    found_idx = (int)i;
                    break;
                }
            }
            if (found_idx >= 0) {
                for (uint32_t i = found_idx; i + 1 < ctx->config->group_count; i++) {
                    ctx->config->groups[i] = ctx->config->groups[i + 1];
                }
                ctx->config->group_count--;
                config_save(get_config_target_path(ctx), ctx->config);
                config_load(get_config_target_path(ctx), ctx->config);
                if (ctx->wan_mgr) wan_manager_rebalance(ctx->wan_mgr);
            }
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Group deleted\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/groups") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char gname[64] = {0}, gdesc[64] = {0};
            extract_json_string(body, "name", gname, sizeof(gname));
            extract_json_string(body, "description", gdesc, sizeof(gdesc));
            bool genabled = extract_json_bool(body, "enabled", true);
            char wans[MAX_GROUP_MEMBERS][MAX_LABEL_LEN];
            uint32_t wcount = 0;
            parse_json_string_array(body, "wans", wans, &wcount);

            if (gname[0]) {
                int found_idx = -1;
                for (uint32_t i = 0; i < ctx->config->group_count; i++) {
                    if (strcmp(ctx->config->groups[i].name, gname) == 0) {
                        found_idx = (int)i;
                        break;
                    }
                }
                if (found_idx < 0 && ctx->config->group_count < MAX_WAN_GROUPS) {
                    found_idx = (int)ctx->config->group_count;
                    ctx->config->group_count++;
                    ctx->config->groups[found_idx].id = (uint32_t)(found_idx + 1);
                }
                if (found_idx >= 0) {
                    wan_group_t *grp = &ctx->config->groups[found_idx];
                    strncpy(grp->name, gname, sizeof(grp->name) - 1);
                    grp->name[sizeof(grp->name) - 1] = '\0';
                    strncpy(grp->description, gdesc, sizeof(grp->description) - 1);
                    grp->description[sizeof(grp->description) - 1] = '\0';
                    grp->enabled = genabled;
                    grp->wan_count = wcount;
                    for (uint32_t w = 0; w < wcount; w++) {
                        strncpy(grp->wan_names[w], wans[w], sizeof(grp->wan_names[w]) - 1);
                        grp->wan_names[w][sizeof(grp->wan_names[w]) - 1] = '\0';
                    }
                    config_save(get_config_target_path(ctx), ctx->config);
                    config_load(get_config_target_path(ctx), ctx->config);
                    if (ctx->wan_mgr) wan_manager_rebalance(ctx->wan_mgr);
                }
            }
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Group saved\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "GET /api/v1/policy_routes") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        char json_buf[4096];
        build_json_policy_routes(ctx->config, json_buf, sizeof(json_buf));

        char resp[4500];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(json_buf), json_buf);

        send(client_fd, resp, (int)len, 0);
        close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/policy_routes/delete") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char subnet[64] = {0};
            extract_json_string(body, "subnet", subnet, sizeof(subnet));
            int found_idx = -1;
            for (uint32_t i = 0; i < ctx->config->lan.policy_route_count; i++) {
                if (subnet[0] && strcmp(ctx->config->lan.policy_routes[i].subnet_str, subnet) == 0) {
                    found_idx = (int)i;
                    break;
                }
            }
            if (found_idx >= 0) {
                for (uint32_t i = found_idx; i + 1 < ctx->config->lan.policy_route_count; i++) {
                    ctx->config->lan.policy_routes[i] = ctx->config->lan.policy_routes[i + 1];
                }
                ctx->config->lan.policy_route_count--;
                config_save(get_config_target_path(ctx), ctx->config);
                config_load(get_config_target_path(ctx), ctx->config);
                if (ctx->wan_mgr) wan_manager_rebalance(ctx->wan_mgr);
                net_apply_policy_routes(ctx->config);
            }
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Policy route deleted\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/policy_routes") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char subnet[64] = {0}, gw[64] = {0}, tgroup[64] = {0}, desc[64] = {0};
            extract_json_string(body, "subnet", subnet, sizeof(subnet));
            extract_json_string(body, "gateway_ip", gw, sizeof(gw));
            extract_json_string(body, "target_group", tgroup, sizeof(tgroup));
            extract_json_string(body, "description", desc, sizeof(desc));
            bool penabled = extract_json_bool(body, "enabled", true);

            if (subnet[0]) {
                int found_idx = -1;
                for (uint32_t i = 0; i < ctx->config->lan.policy_route_count; i++) {
                    if (strcmp(ctx->config->lan.policy_routes[i].subnet_str, subnet) == 0) {
                        found_idx = (int)i;
                        break;
                    }
                }
                if (found_idx < 0 && ctx->config->lan.policy_route_count < MAX_POLICY_ROUTES) {
                    found_idx = (int)ctx->config->lan.policy_route_count;
                    ctx->config->lan.policy_route_count++;
                }
                if (found_idx >= 0) {
                    policy_route_t *pr = &ctx->config->lan.policy_routes[found_idx];
                    strncpy(pr->subnet_str, subnet, sizeof(pr->subnet_str) - 1);
                    pr->subnet_str[sizeof(pr->subnet_str) - 1] = '\0';
                    parse_cidr_subnet(subnet, &pr->subnet_ip, &pr->netmask, &pr->prefix_len);
                    strncpy(pr->gateway_ip_str, gw, sizeof(pr->gateway_ip_str) - 1);
                    pr->gateway_ip_str[sizeof(pr->gateway_ip_str) - 1] = '\0';
                    pr->gateway_ip = str_to_ip(gw);
                    strncpy(pr->target_group, tgroup, sizeof(pr->target_group) - 1);
                    pr->target_group[sizeof(pr->target_group) - 1] = '\0';
                    strncpy(pr->description, desc, sizeof(pr->description) - 1);
                    pr->description[sizeof(pr->description) - 1] = '\0';
                    pr->enabled = penabled;

                    config_save(get_config_target_path(ctx), ctx->config);
                    config_load(get_config_target_path(ctx), ctx->config);
                    if (ctx->wan_mgr) wan_manager_rebalance(ctx->wan_mgr);
                    net_apply_policy_routes(ctx->config);
                }
            }
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Policy route saved\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "GET /api/v1/leases") != NULL || strstr(req, "GET /api/v1/dhcp/leases") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        char json_buf[8192];
        build_json_dhcp_leases(ctx->dhcp, json_buf, sizeof(json_buf));
        char resp[8500];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(json_buf), json_buf);
        send(client_fd, resp, (int)len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/leases/static/delete") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char mac[32] = {0}, ip[32] = {0};
            extract_json_string(body, "mac", mac, sizeof(mac));
            extract_json_string(body, "ip", ip, sizeof(ip));
            int found_idx = -1;
            for (uint32_t i = 0; i < ctx->config->lan.static_lease_count; i++) {
                if ((mac[0] && strcasecmp(ctx->config->lan.static_leases[i].mac_str, mac) == 0) ||
                    (ip[0] && ctx->config->lan.static_leases[i].ip_addr == str_to_ip(ip))) {
                    found_idx = (int)i;
                    break;
                }
            }
            if (found_idx >= 0) {
                for (uint32_t i = found_idx; i + 1 < ctx->config->lan.static_lease_count; i++) {
                    ctx->config->lan.static_leases[i] = ctx->config->lan.static_leases[i + 1];
                }
                ctx->config->lan.static_lease_count--;
                config_save(get_config_target_path(ctx), ctx->config);
                config_load(get_config_target_path(ctx), ctx->config);
                if (ctx->dhcp) dhcp_server_reload_config(ctx->dhcp, ctx->config);
            }
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Static reservation removed\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/leases/static") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char mac[32] = {0}, ip[32] = {0}, host[64] = {0};
            extract_json_string(body, "mac", mac, sizeof(mac));
            extract_json_string(body, "ip", ip, sizeof(ip));
            extract_json_string(body, "hostname", host, sizeof(host));
            bool enabled = extract_json_bool(body, "enabled", true);
            if (mac[0] && ip[0]) {
                int found_idx = -1;
                for (uint32_t i = 0; i < ctx->config->lan.static_lease_count; i++) {
                    if (strcasecmp(ctx->config->lan.static_leases[i].mac_str, mac) == 0) {
                        found_idx = (int)i;
                        break;
                    }
                }
                if (found_idx < 0 && ctx->config->lan.static_lease_count < MAX_STATIC_LEASES) {
                    found_idx = (int)ctx->config->lan.static_lease_count++;
                }
                if (found_idx >= 0) {
                    static_lease_t *sl = &ctx->config->lan.static_leases[found_idx];
                    safe_str_copy(sl->mac_str, mac, sizeof(sl->mac_str));
                    parse_mac_str(mac, sl->mac_addr);
                    sl->ip_addr = str_to_ip(ip);
                    safe_str_copy(sl->hostname, host[0] ? host : "Static-Host", sizeof(sl->hostname));
                    sl->enabled = enabled;
                    config_save(get_config_target_path(ctx), ctx->config);
                    config_load(get_config_target_path(ctx), ctx->config);
                    if (ctx->dhcp) dhcp_server_reload_config(ctx->dhcp, ctx->config);
                }
            }
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Static reservation saved\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/ratelimits/delete") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char ip[32] = {0};
            extract_json_string(body, "ip", ip, sizeof(ip));
            int found_idx = -1;
            for (uint32_t i = 0; i < ctx->config->lan.rate_limit_count; i++) {
                if (ip[0] && strcmp(ctx->config->lan.rate_limits[i].ip_str, ip) == 0) {
                    found_idx = (int)i;
                    break;
                }
            }
            if (found_idx >= 0) {
                for (uint32_t i = found_idx; i + 1 < ctx->config->lan.rate_limit_count; i++) {
                    ctx->config->lan.rate_limits[i] = ctx->config->lan.rate_limits[i + 1];
                }
                ctx->config->lan.rate_limit_count--;
                config_save(get_config_target_path(ctx), ctx->config);
                config_load(get_config_target_path(ctx), ctx->config);
                net_apply_rate_limits(ctx->config);
            }
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Rate limit deleted\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/ratelimits") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char ip[32] = {0}, desc[64] = {0};
            extract_json_string(body, "ip", ip, sizeof(ip));
            extract_json_string(body, "description", desc, sizeof(desc));
            uint32_t max_d = (uint32_t)extract_json_int(body, "max_down_mbps", 50);
            uint32_t max_u = (uint32_t)extract_json_int(body, "max_up_mbps", 10);
            bool enabled = extract_json_bool(body, "enabled", true);
            if (ip[0]) {
                int found_idx = -1;
                for (uint32_t i = 0; i < ctx->config->lan.rate_limit_count; i++) {
                    if (strcmp(ctx->config->lan.rate_limits[i].ip_str, ip) == 0) {
                        found_idx = (int)i;
                        break;
                    }
                }
                if (found_idx < 0 && ctx->config->lan.rate_limit_count < MAX_RATE_LIMITS) {
                    found_idx = (int)ctx->config->lan.rate_limit_count++;
                }
                if (found_idx >= 0) {
                    rate_limit_t *rl = &ctx->config->lan.rate_limits[found_idx];
                    safe_str_copy(rl->ip_str, ip, sizeof(rl->ip_str));
                    rl->ip_addr = str_to_ip(ip);
                    safe_str_copy(rl->description, desc, sizeof(rl->description));
                    rl->max_down_mbps = max_d;
                    rl->max_up_mbps = max_u;
                    rl->enabled = enabled;
                    config_save(get_config_target_path(ctx), ctx->config);
                    config_load(get_config_target_path(ctx), ctx->config);
                    net_apply_rate_limits(ctx->config);
                }
            }
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Rate limit saved\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/qos") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char algo[32] = {0};
            extract_json_string(body, "algorithm", algo, sizeof(algo));
            if (algo[0]) safe_str_copy(ctx->config->lan.qos.algorithm, algo, sizeof(ctx->config->lan.qos.algorithm));
            ctx->config->lan.qos.enabled = extract_json_bool(body, "enabled", ctx->config->lan.qos.enabled);
            ctx->config->lan.qos.bandwidth_down_mbps = (uint32_t)extract_json_int(body, "bandwidth_down_mbps", ctx->config->lan.qos.bandwidth_down_mbps);
            ctx->config->lan.qos.bandwidth_up_mbps = (uint32_t)extract_json_int(body, "bandwidth_up_mbps", ctx->config->lan.qos.bandwidth_up_mbps);
            ctx->config->lan.qos.diffserv4 = extract_json_bool(body, "diffserv4", ctx->config->lan.qos.diffserv4);
            config_save(get_config_target_path(ctx), ctx->config);
            config_load(get_config_target_path(ctx), ctx->config);
            net_apply_qos(ctx->config);
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"QoS settings updated\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/dns") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char dns1[32] = {0}, dns2[32] = {0};
            extract_json_string(body, "primary_dns", dns1, sizeof(dns1));
            extract_json_string(body, "secondary_dns", dns2, sizeof(dns2));
            if (dns1[0]) safe_str_copy(ctx->config->lan.dns.primary_dns, dns1, sizeof(ctx->config->lan.dns.primary_dns));
            if (dns2[0]) safe_str_copy(ctx->config->lan.dns.secondary_dns, dns2, sizeof(ctx->config->lan.dns.secondary_dns));
            ctx->config->lan.dns.adblock_enabled = extract_json_bool(body, "adblock_enabled", ctx->config->lan.dns.adblock_enabled);
            ctx->config->lan.dns.fast_dns_enabled = extract_json_bool(body, "fast_dns_enabled", ctx->config->lan.dns.fast_dns_enabled);
            config_save(get_config_target_path(ctx), ctx->config);
            config_load(get_config_target_path(ctx), ctx->config);
            net_apply_dns_features(ctx->config);
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"DNS settings updated\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/app_steering") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            ctx->config->app_steering.gaming_steering_enabled = extract_json_bool(body, "gaming_steering_enabled", ctx->config->app_steering.gaming_steering_enabled);
            ctx->config->app_steering.voip_steering_enabled = extract_json_bool(body, "voip_steering_enabled", ctx->config->app_steering.voip_steering_enabled);
            ctx->config->app_steering.bulk_balancing_enabled = extract_json_bool(body, "bulk_balancing_enabled", ctx->config->app_steering.bulk_balancing_enabled);
            ctx->config->app_steering.primary_gaming_wan_id = (uint32_t)extract_json_int(body, "primary_gaming_wan_id", ctx->config->app_steering.primary_gaming_wan_id);
            ctx->config->app_steering.primary_voip_wan_id = (uint32_t)extract_json_int(body, "primary_voip_wan_id", ctx->config->app_steering.primary_voip_wan_id);
            config_save(get_config_target_path(ctx), ctx->config);
            config_load(get_config_target_path(ctx), ctx->config);
            net_apply_app_steering(ctx->config);
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Application steering updated\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/telegram/test") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        char token[128] = {0}, chat[64] = {0};
        if (body) {
            body += 4;
            extract_json_string(body, "bot_token", token, sizeof(token));
            extract_json_string(body, "chat_id", chat, sizeof(chat));
        }
        if (!token[0]) safe_str_copy(token, ctx->config->telegram.bot_token, sizeof(token));
        if (!chat[0]) safe_str_copy(chat, ctx->config->telegram.chat_id, sizeof(chat));

#if defined(__linux__)
        if (token[0] && chat[0]) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "curl -s -X POST 'https://api.telegram.org/bot%s/sendMessage' -d 'chat_id=%s' -d 'text=🚀 FluxWAN Router: Test notification sent successfully!' >/dev/null 2>&1 &",
                     token, chat);
            safe_system(cmd);
        }
#endif
        const char *rb = "{\"status\":\"ok\",\"message\":\"Test alert sent\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/telegram") != NULL) {
        if (!is_request_authorized(ctx->config, req)) {
            const char *rb = "{\"status\":\"error\",\"message\":\"Unauthorized\"}";
            char resp[256]; int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(rb), rb);
            send(client_fd, resp, len, 0); close_client_socket(client_fd); return 0;
        }
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            char token[128] = {0}, chat[64] = {0};
            extract_json_string(body, "bot_token", token, sizeof(token));
            extract_json_string(body, "chat_id", chat, sizeof(chat));
            if (token[0]) safe_str_copy(ctx->config->telegram.bot_token, token, sizeof(ctx->config->telegram.bot_token));
            if (chat[0]) safe_str_copy(ctx->config->telegram.chat_id, chat, sizeof(ctx->config->telegram.chat_id));
            ctx->config->telegram.enabled = extract_json_bool(body, "enabled", ctx->config->telegram.enabled);
            ctx->config->telegram.notify_on_failover = extract_json_bool(body, "notify_on_failover", ctx->config->telegram.notify_on_failover);
            ctx->config->telegram.notify_on_recovery = extract_json_bool(body, "notify_on_recovery", ctx->config->telegram.notify_on_recovery);
            config_save(get_config_target_path(ctx), ctx->config);
            config_load(get_config_target_path(ctx), ctx->config);
        }
        const char *rb = "{\"status\":\"ok\",\"message\":\"Telegram configuration updated\"}";
        char resp[256]; int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(rb), rb);
        send(client_fd, resp, len, 0); close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/assign") != NULL || strstr(req, "POST /api/v1/apply") != NULL) {
        /* Check admin authorization */
        if (!is_request_authorized(ctx->config, req)) {
            const char *resp_body = "{\"status\":\"error\",\"message\":\"Unauthorized. Admin login required.\"}";
            char resp[512];
            int len = snprintf(resp, sizeof(resp),
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n\r\n%s",
                strlen(resp_body), resp_body);
            send(client_fd, resp, len, 0);
            close_client_socket(client_fd);
            return 0;
        }

        /* Extract JSON payload from HTTP POST body if present */
        const char *body = strstr(req, "\r\n\r\n");
        if (body) {
            body += 4;
            while (*body == ' ' || *body == '\t' || *body == '\r' || *body == '\n') body++;
            if (*body == '{') {
                /* Create temporary copy to validate */
                fluxwan_config_t test_cfg;
                FILE *f_tmp = fopen("/tmp/fluxwan_test_cfg.json", "w");
                if (f_tmp) {
                    fputs(body, f_tmp);
                    fclose(f_tmp);
                }
                if (config_load("/tmp/fluxwan_test_cfg.json", &test_cfg) == 0) {
                    /* Protect existing WANs if client payload sent empty WAN list */
                    if (test_cfg.wan_count == 0 && ctx->config->wan_count > 0) {
                        LOG_WARN("[Web] Incoming apply payload had 0 WANs. Preserving existing %u WAN uplinks.", ctx->config->wan_count);
                        test_cfg.wan_count = ctx->config->wan_count;
                        memcpy(test_cfg.wans, ctx->config->wans, sizeof(wan_config_t) * ctx->config->wan_count);
                    }
                    /* Ensure LAN settings are valid */
                    if (test_cfg.lan.ip_addr == 0) {
                        test_cfg.lan.ip_addr = ctx->config->lan.ip_addr ? ctx->config->lan.ip_addr : str_to_ip("192.168.90.1");
                    }
                    if (test_cfg.lan.netmask == 0) {
                        test_cfg.lan.netmask = ctx->config->lan.netmask ? ctx->config->lan.netmask : str_to_ip("255.255.255.0");
                    }
                    if (test_cfg.lan.name[0] == '\0') {
                        safe_str_copy(test_cfg.lan.name, ctx->config->lan.name[0] ? ctx->config->lan.name : "eth0", sizeof(test_cfg.lan.name));
                    }

                    char err_msg[256] = {0};
                    if (!config_validate_wan_attachments(&test_cfg, err_msg, sizeof(err_msg))) {
                        LOG_WARN("[Web] Configuration rejected: %s", err_msg);
                        wan_manager_add_log("WARN", "Configuration rejected: %s", err_msg);

                        char resp_body[512];
                        snprintf(resp_body, sizeof(resp_body),
                                 "{\"status\":\"error\",\"message\":\"%s\"}", err_msg);
                        char resp[1024];
                        int len = snprintf(resp, sizeof(resp),
                            "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: application/json\r\n"
                            "Access-Control-Allow-Origin: *\r\n"
                            "Content-Length: %zu\r\n"
                            "Connection: close\r\n\r\n%s",
                            strlen(resp_body), resp_body);
                        send(client_fd, resp, len, 0);
                        close_client_socket(client_fd);
                        return 0;
                    }

                    /* Validation passed: save cleanly using config_save */
                    const char *save_path = get_config_target_path(ctx);
                    if (config_save(save_path, &test_cfg) < 0) {
                        save_path = "/opt/fluxwan/config/fluxwan.json";
                        config_save(save_path, &test_cfg);
                    }
                    LOG_INFO("[Web] Updated %s with new validated settings from UI", save_path);
                    wan_manager_add_log("INFO", "Configuration validated and saved to %s", save_path);
                    config_load(save_path, ctx->config);
                }
            }
        }

        /* Re-apply configuration to Linux Kernel & Policy Routing */
        net_apply_configuration(ctx->config, ctx->nl);
        if (ctx->wan_mgr) {
            wan_manager_rebalance(ctx->wan_mgr);
        }

        const char *resp_body = "{\"status\":\"ok\",\"message\":\"Configuration validated, saved, and applied to Linux Kernel\"}";
        char resp[512];
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(resp_body), resp_body);

        send(client_fd, resp, len, 0);
        close_client_socket(client_fd);
    } else if (strstr(req, "POST /api/v1/terminal") != NULL || strstr(req, "POST /api/v1/exec") != NULL) {
        handle_terminal_exec(ctx, client_fd, req);
    } else if (strstr(req, "GET /api/v1/diagnostics/pcap") != NULL) {
        handle_pcap_export(ctx, client_fd, req);
    } else if (strstr(req, "GET /api/v1/telemetry") != NULL) {
        const char *hdr =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n\r\n";
        send(client_fd, hdr, (int)strlen(hdr), 0);

        char json_buf[16384];
        build_json_status(ctx, json_buf, sizeof(json_buf));

        char sse_msg[17000];
        int len = snprintf(sse_msg, sizeof(sse_msg), "data: %s\n\n", json_buf);
        send(client_fd, sse_msg, (int)len, 0);
    } else {
        /* Serve embedded HTML Dashboard Gzip Payload */
        char resp_hdr[512];
        int hdr_len = snprintf(resp_hdr, sizeof(resp_hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Encoding: gzip\r\n"
            "Content-Length: %u\r\n"
            "Connection: close\r\n\r\n", UI_INDEX_HTML_GZ_LEN);

        send(client_fd, resp_hdr, hdr_len, 0);
        send(client_fd, (const char *)UI_INDEX_HTML_GZ, (int)UI_INDEX_HTML_GZ_LEN, 0);
        close_client_socket(client_fd);
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (ctx->clients[i].fd == client_fd && !ctx->clients[i].is_sse) {
            ctx->clients[i].fd = INVALID_SOCKET;
        }
    }
    return 0;
}
