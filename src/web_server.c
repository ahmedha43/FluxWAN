#include "web_server.h"
#include "ui_assets.h"
#include "config.h"
#include "net_apply.h"
#include "wan_manager.h"
#include <fcntl.h>
#if !defined(_WIN32) && !defined(_WIN64)
#include <poll.h>
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
            w->config_weight, w->dynamic_weight, w->metrics.rtt_ms, w->metrics.jitter_ms,
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

    snprintf(buf + offset, max_len - offset, "  ],\n  \"sticky_count\": %u\n}\n", get_real_active_connections());
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
            "      \"expire_sec\": %llu\n"
            "    }%s\n",
            ip, leases[i].mac_str, leases[i].hostname,
            (unsigned long long)leases[i].lease_expire_sec,
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
                config_save("config/fluxwan.json", ctx->config);
                config_load("config/fluxwan.json", ctx->config);
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
                    config_save("config/fluxwan.json", ctx->config);
                    config_load("config/fluxwan.json", ctx->config);
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
                config_save("config/fluxwan.json", ctx->config);
                config_load("config/fluxwan.json", ctx->config);
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

                    config_save("config/fluxwan.json", ctx->config);
                    config_load("config/fluxwan.json", ctx->config);
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
                }

                /* Validation passed: save to real config/fluxwan.json */
                FILE *f = fopen("config/fluxwan.json", "w");
                if (f) {
                    fputs(body, f);
                    fclose(f);
                    LOG_INFO("[Web] Updated config/fluxwan.json with new validated settings from UI");
                    wan_manager_add_log("INFO", "Configuration validated and applied via Web Management");
                }
                config_load("config/fluxwan.json", ctx->config);
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
