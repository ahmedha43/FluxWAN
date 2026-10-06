#include "proxy_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#if defined(__linux__)
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <strings.h>
#elif defined(_WIN32) || defined(_WIN64)
#define strcasecmp _stricmp
#endif

struct proxy_manager_ctx {
    fluxwan_config_t *config;
    int pids[MAX_WANS];
    uint64_t last_check_ms;
};

static inline void safe_str_copy(char *dst, const char *src, size_t max_len) {
    if (!dst || max_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t slen = strlen(src);
    if (slen >= max_len) slen = max_len - 1;
    memcpy(dst, src, slen);
    dst[slen] = '\0';
}

/* URL percent-decoding helper (e.g. %2F -> /) */
static void url_decode(char *dst, const char *src, size_t max_len) {
    if (!dst || !src || max_len == 0) return;
    size_t d_idx = 0;
    while (*src && d_idx < max_len - 1) {
        if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char hex[3] = {src[1], src[2], 0};
            dst[d_idx++] = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            dst[d_idx++] = ' ';
            src++;
        } else {
            dst[d_idx++] = *src++;
        }
    }
    dst[d_idx] = '\0';
}

/* Simple Base64 decode helper */
static inline int b64_char_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static int base64_decode(const char *in, size_t in_len, char *out, size_t max_out) {
    size_t out_len = 0;
    uint32_t val = 0;
    int valb = -8;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=' || isspace(c)) continue;
        int d = b64_char_val(c);
        if (d < 0) continue;
        val = (val << 6) | (uint32_t)d;
        valb += 6;
        if (valb >= 0) {
            if (out_len < max_out - 1) {
                out[out_len++] = (char)((val >> valb) & 0xFF);
            }
            valb -= 8;
        }
    }
    out[out_len] = '\0';
    return (int)out_len;
}

/* Helper to extract a query parameter key=value from URL query string */
static void extract_query_param(const char *query, const char *key, char *out, size_t max_out) {
    if (!query || !key || !out || max_out == 0) return;
    out[0] = '\0';
    if (*query == '?') query++;
    size_t klen = strlen(key);
    const char *p = query;
    while (p && *p) {
        if ((p == query || *(p - 1) == '&') && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *val_start = p + klen + 1;
            const char *val_end = strchr(val_start, '&');
            if (!val_end) val_end = strchr(val_start, '#');
            size_t vlen = val_end ? (size_t)(val_end - val_start) : strlen(val_start);
            char raw[256];
            if (vlen >= sizeof(raw)) vlen = sizeof(raw) - 1;
            memcpy(raw, val_start, vlen);
            raw[vlen] = '\0';
            url_decode(out, raw, max_out);
            return;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
}

/* JSON key extractor for VMess JSON object */
static void json_get_string(const char *json, const char *key, char *out, size_t max_out) {
    if (!json || !key || !out || max_out == 0) return;
    out[0] = '\0';
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(json, pattern);
    if (!pos) return;
    pos = strchr(pos + strlen(pattern), ':');
    if (!pos) return;
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n')) pos++;
    if (*pos == '\"') {
        pos++;
        const char *end = strchr(pos, '\"');
        if (end) {
            size_t len = (size_t)(end - pos);
            if (len >= max_out) len = max_out - 1;
            memcpy(out, pos, len);
            out[len] = '\0';
        }
    } else {
        const char *end = pos;
        while (*end && *end != ',' && *end != '}' && *end != '\n') end++;
        size_t len = (size_t)(end - pos);
        if (len >= max_out) len = max_out - 1;
        memcpy(out, pos, len);
        out[len] = '\0';
        /* Trim trailing spaces */
        while (len > 0 && isspace((unsigned char)out[len - 1])) out[--len] = '\0';
    }
}

int proxy_manager_parse_uri(const char *uri, wan_proxy_config_t *out_proxy) {
    if (!uri || !out_proxy) return -1;
    memset(out_proxy, 0, sizeof(wan_proxy_config_t));
    safe_str_copy(out_proxy->raw_uri, uri, sizeof(out_proxy->raw_uri));
    out_proxy->enabled = true;
    safe_str_copy(out_proxy->transport, "ws", sizeof(out_proxy->transport));
    safe_str_copy(out_proxy->security, "tls", sizeof(out_proxy->security));

    /* 1. VLESS: vless://uuid@server:port?query#name */
    if (strncmp(uri, "vless://", 8) == 0) {
        out_proxy->proto = PROXY_PROTO_VLESS;
        safe_str_copy(out_proxy->proto_str, "vless", sizeof(out_proxy->proto_str));
        const char *p = uri + 8;
        const char *at = strchr(p, '@');
        if (!at) return -1;

        size_t ulen = (size_t)(at - p);
        if (ulen >= sizeof(out_proxy->uuid)) ulen = sizeof(out_proxy->uuid) - 1;
        memcpy(out_proxy->uuid, p, ulen);
        out_proxy->uuid[ulen] = '\0';

        p = at + 1;
        const char *colon = strchr(p, ':');
        const char *query = strchr(p, '?');
        if (!colon) return -1;

        size_t slen = (size_t)(colon - p);
        if (slen >= sizeof(out_proxy->server)) slen = sizeof(out_proxy->server) - 1;
        memcpy(out_proxy->server, p, slen);
        out_proxy->server[slen] = '\0';

        out_proxy->port = (uint16_t)atoi(colon + 1);

        if (query) {
            extract_query_param(query, "sni", out_proxy->sni, sizeof(out_proxy->sni));
            extract_query_param(query, "host", out_proxy->host, sizeof(out_proxy->host));
            extract_query_param(query, "path", out_proxy->path, sizeof(out_proxy->path));
            extract_query_param(query, "type", out_proxy->transport, sizeof(out_proxy->transport));
            extract_query_param(query, "security", out_proxy->security, sizeof(out_proxy->security));
        }
        if (out_proxy->sni[0] && !out_proxy->host[0]) safe_str_copy(out_proxy->host, out_proxy->sni, sizeof(out_proxy->host));
        if (out_proxy->host[0] && !out_proxy->sni[0]) safe_str_copy(out_proxy->sni, out_proxy->host, sizeof(out_proxy->sni));
        if (out_proxy->port == 80 && strcasecmp(out_proxy->security, "tls") != 0) {
            safe_str_copy(out_proxy->security, "none", sizeof(out_proxy->security));
        }
        safe_str_copy(out_proxy->raw_uri, uri, sizeof(out_proxy->raw_uri));
        return 0;
    }

    /* 2. TROJAN: trojan://password@server:port?query#name */
    if (strncmp(uri, "trojan://", 9) == 0) {
        out_proxy->proto = PROXY_PROTO_TROJAN;
        safe_str_copy(out_proxy->proto_str, "trojan", sizeof(out_proxy->proto_str));
        const char *p = uri + 9;
        const char *at = strchr(p, '@');
        if (!at) return -1;

        size_t ulen = (size_t)(at - p);
        if (ulen >= sizeof(out_proxy->uuid)) ulen = sizeof(out_proxy->uuid) - 1;
        memcpy(out_proxy->uuid, p, ulen);
        out_proxy->uuid[ulen] = '\0';

        p = at + 1;
        const char *colon = strchr(p, ':');
        const char *query = strchr(p, '?');
        if (!colon) return -1;

        size_t slen = (size_t)(colon - p);
        if (slen >= sizeof(out_proxy->server)) slen = sizeof(out_proxy->server) - 1;
        memcpy(out_proxy->server, p, slen);
        out_proxy->server[slen] = '\0';

        out_proxy->port = (uint16_t)atoi(colon + 1);

        if (query) {
            extract_query_param(query, "sni", out_proxy->sni, sizeof(out_proxy->sni));
            extract_query_param(query, "host", out_proxy->host, sizeof(out_proxy->host));
            extract_query_param(query, "path", out_proxy->path, sizeof(out_proxy->path));
            extract_query_param(query, "type", out_proxy->transport, sizeof(out_proxy->transport));
            extract_query_param(query, "security", out_proxy->security, sizeof(out_proxy->security));
        }
        if (out_proxy->sni[0] && !out_proxy->host[0]) safe_str_copy(out_proxy->host, out_proxy->sni, sizeof(out_proxy->host));
        if (out_proxy->host[0] && !out_proxy->sni[0]) safe_str_copy(out_proxy->sni, out_proxy->host, sizeof(out_proxy->sni));
        if (out_proxy->port == 80 && strcasecmp(out_proxy->security, "tls") != 0) {
            safe_str_copy(out_proxy->security, "none", sizeof(out_proxy->security));
        }
        safe_str_copy(out_proxy->raw_uri, uri, sizeof(out_proxy->raw_uri));
        return 0;
    }

    /* 3. VMESS: vmess://<base64_json> */
    if (strncmp(uri, "vmess://", 8) == 0) {
        out_proxy->proto = PROXY_PROTO_VMESS;
        safe_str_copy(out_proxy->proto_str, "vmess", sizeof(out_proxy->proto_str));
        const char *p = uri + 8;
        char json[2048] = {0};
        base64_decode(p, strlen(p), json, sizeof(json));

        json_get_string(json, "add", out_proxy->server, sizeof(out_proxy->server));
        char port_str[16] = {0};
        json_get_string(json, "port", port_str, sizeof(port_str));
        out_proxy->port = (uint16_t)atoi(port_str);
        json_get_string(json, "id", out_proxy->uuid, sizeof(out_proxy->uuid));
        json_get_string(json, "sni", out_proxy->sni, sizeof(out_proxy->sni));
        json_get_string(json, "host", out_proxy->host, sizeof(out_proxy->host));
        json_get_string(json, "path", out_proxy->path, sizeof(out_proxy->path));
        json_get_string(json, "net", out_proxy->transport, sizeof(out_proxy->transport));
        json_get_string(json, "tls", out_proxy->security, sizeof(out_proxy->security));

        if (out_proxy->sni[0] && !out_proxy->host[0]) safe_str_copy(out_proxy->host, out_proxy->sni, sizeof(out_proxy->host));
        return 0;
    }

    /* 4. Shadowsocks: ss://<base64>@server:port */
    if (strncmp(uri, "ss://", 5) == 0) {
        out_proxy->proto = PROXY_PROTO_SHADOWSOCKS;
        safe_str_copy(out_proxy->proto_str, "shadowsocks", sizeof(out_proxy->proto_str));
        const char *p = uri + 5;
        const char *at = strchr(p, '@');
        if (at) {
            char userinfo[256] = {0};
            size_t ulen = (size_t)(at - p);
            if (ulen >= sizeof(userinfo)) ulen = sizeof(userinfo) - 1;
            memcpy(userinfo, p, ulen);
            userinfo[ulen] = '\0';
            safe_str_copy(out_proxy->uuid, userinfo, sizeof(out_proxy->uuid));

            p = at + 1;
            const char *colon = strchr(p, ':');
            if (colon) {
                size_t slen = (size_t)(colon - p);
                if (slen >= sizeof(out_proxy->server)) slen = sizeof(out_proxy->server) - 1;
                memcpy(out_proxy->server, p, slen);
                out_proxy->server[slen] = '\0';
                out_proxy->port = (uint16_t)atoi(colon + 1);
                return 0;
            }
        }
    }

    return -1;
}

/* Generates JSON configuration for Sing-box / Xray-core */
static int generate_proxy_config_file(const wan_config_t *wan, int wan_idx, char *out_path, size_t max_path) {
    if (!wan || !out_path) return -1;
    snprintf(out_path, max_path, "/etc/fluxwan/proxy_wan_%u.json", wan->id > 0 ? wan->id : (uint32_t)(wan_idx + 1));

#if defined(__linux__)
    mkdir("/etc/fluxwan", 0755);
#endif

    FILE *f = fopen(out_path, "w");
    if (!f) {
        LOG_ERROR("[Proxy] Failed to create config file %s", out_path);
        return -1;
    }

    const wan_proxy_config_t *p = &wan->proxy;
    const char *tun_name = p->tun_dev[0] ? p->tun_dev : "tun_wan0";
    char tun_buf[16];
    if (!p->tun_dev[0]) {
        snprintf(tun_buf, sizeof(tun_buf), "tun_wan%u", (unsigned int)((wan->id > 0 ? wan->id : (uint32_t)(wan_idx + 1)) % 1000));
        tun_name = tun_buf;
    }

    uint32_t fwmark = 0x1000 + wan_idx;

    /* Build Sing-box Universal JSON Configuration */
    fprintf(f, "{\n");
    fprintf(f, "  \"log\": {\n    \"level\": \"warn\"\n  },\n");
    fprintf(f, "  \"inbounds\": [\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"type\": \"tun\",\n");
    fprintf(f, "      \"tag\": \"tun-in\",\n");
    fprintf(f, "      \"interface_name\": \"%s\",\n", tun_name);
    fprintf(f, "      \"inet4_address\": \"198.18.%u.1/24\",\n", (wan_idx + 10) % 250);
    fprintf(f, "      \"mtu\": 1420,\n");
    fprintf(f, "      \"auto_route\": false,\n");
    fprintf(f, "      \"strict_route\": false,\n");
    fprintf(f, "      \"sniff\": true\n");
    fprintf(f, "    }\n");
    fprintf(f, "  ],\n");

    /* Outbound proxy definition */
    fprintf(f, "  \"outbounds\": [\n");
    fprintf(f, "    {\n");
    const char *proto_type = p->proto_str[0] ? p->proto_str : "vless";
    fprintf(f, "      \"type\": \"%s\",\n", proto_type);
    fprintf(f, "      \"tag\": \"proxy-out\",\n");
    fprintf(f, "      \"server\": \"%s\",\n", p->server);
    fprintf(f, "      \"server_port\": %u,\n", p->port > 0 ? p->port : 443);
    fprintf(f, "      \"uuid\": \"%s\",\n", p->uuid);

    /* TLS / SNI configuration */
    bool has_tls = false;
    if (strcasecmp(p->security, "none") != 0 && strcasecmp(p->security, "plain") != 0) {
        if (strcasecmp(p->security, "tls") == 0 || p->port == 443 || (p->sni[0] != '\0' && p->port != 80)) {
            has_tls = true;
        }
    }
    if (has_tls) {
        fprintf(f, "      \"tls\": {\n");
        fprintf(f, "        \"enabled\": true,\n");
        if (p->sni[0]) {
            fprintf(f, "        \"server_name\": \"%s\",\n", p->sni);
        } else {
            fprintf(f, "        \"server_name\": \"%s\",\n", p->server);
        }
        fprintf(f, "        \"insecure\": true\n");
        fprintf(f, "      },\n");
    }

    /* Transport: WebSocket / HTTP / gRPC */
    if (strcasecmp(p->transport, "ws") == 0 || p->path[0] != '\0') {
        fprintf(f, "      \"transport\": {\n");
        fprintf(f, "        \"type\": \"ws\",\n");
        fprintf(f, "        \"path\": \"%s\",\n", p->path[0] ? p->path : "/");
        if (p->host[0] || p->sni[0]) {
            const char *h = p->host[0] ? p->host : p->sni;
            fprintf(f, "        \"headers\": {\n");
            fprintf(f, "          \"Host\": \"%s\"\n", h);
            fprintf(f, "        }\n");
        }
        fprintf(f, "      },\n");
    }

    /* STRICT PHYSICAL EGRESS PINNING:
     * Forces the proxy daemon to send outer encrypted packets ONLY through this physical WAN interface! */
    fprintf(f, "      \"routing_mark\": %u,\n", fwmark);
    fprintf(f, "      \"bind_interface\": \"%s\"\n", wan->name);
    fprintf(f, "    }\n");
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);

    LOG_INFO("[Proxy] Generated configuration for WAN '%s' at %s (Egress bound to %s, Mark 0x%x)",
             wan->label, out_path, wan->name, fwmark);
    return 0;
}

proxy_manager_ctx_t *proxy_manager_init(fluxwan_config_t *config) {
    proxy_manager_ctx_t *ctx = calloc(1, sizeof(proxy_manager_ctx_t));
    if (!ctx) return NULL;
    ctx->config = config;
    for (int i = 0; i < MAX_WANS; i++) ctx->pids[i] = -1;
    return ctx;
}

void proxy_manager_close(proxy_manager_ctx_t *ctx) {
    if (!ctx) return;
    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        proxy_manager_stop_wan(ctx, i);
    }
    free(ctx);
}

int proxy_manager_start_wan(proxy_manager_ctx_t *ctx, uint32_t wan_idx) {
    if (!ctx || !ctx->config || wan_idx >= ctx->config->wan_count) return -1;
    wan_config_t *wan = &ctx->config->wans[wan_idx];
    if (wan->enabled && wan->proxy.enabled && !wan->proxy.server[0] && wan->proxy.raw_uri[0]) {
        proxy_manager_parse_uri(wan->proxy.raw_uri, &wan->proxy);
    }
    if (!wan->enabled || !wan->proxy.enabled || !wan->proxy.server[0]) {
        return proxy_manager_stop_wan(ctx, wan_idx);
    }

    /* Set default TUN interface name if not set */
    if (!wan->proxy.tun_dev[0]) {
        snprintf(wan->proxy.tun_dev, sizeof(wan->proxy.tun_dev), "tun_wan%u", (unsigned int)((wan->id > 0 ? wan->id : (wan_idx + 1)) % 1000));
    }

    char conf_path[256];
    if (generate_proxy_config_file(wan, (int)wan_idx, conf_path, sizeof(conf_path)) != 0) {
        return -1;
    }

#if defined(__linux__)
    /* Stop any existing instance for this WAN */
    proxy_manager_stop_wan(ctx, wan_idx);

    char pid_file[128];
    snprintf(pid_file, sizeof(pid_file), "/var/run/fluxwan_proxy_wan_%u.pid", wan_idx);

    char log_file[128];
    snprintf(log_file, sizeof(log_file), "/var/log/fluxwan_proxy_wan_%u.log", wan_idx);

    /* Launch sing-box (or xray fallback) daemon in background */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "sh -c 'if which sing-box >/dev/null 2>&1; then "
             "  sing-box run -c %s >%s 2>&1 & echo $! > %s; "
             "elif which xray >/dev/null 2>&1; then "
             "  xray run -c %s >%s 2>&1 & echo $! > %s; "
             "fi' &",
             conf_path, log_file, pid_file,
             conf_path, log_file, pid_file);

    int rc = system(cmd);
    (void)rc;

    /* Read back PID */
    usleep(100000); /* 100ms grace period */
    FILE *pf = fopen(pid_file, "r");
    if (pf) {
        int pid = 0;
        if (fscanf(pf, "%d", &pid) == 1 && pid > 1) {
            ctx->pids[wan_idx] = pid;
            wan->proxy.pid = pid;
            wan->proxy.is_connected = true;
            LOG_INFO("[Proxy] Successfully launched proxy daemon for WAN '%s' (PID: %d, Device: %s)",
                     wan->label, pid, wan->proxy.tun_dev);
        }
        fclose(pf);
    }
#else
    ctx->pids[wan_idx] = 1000 + wan_idx;
    wan->proxy.pid = 1000 + wan_idx;
    wan->proxy.is_connected = true;
    LOG_INFO("[Proxy Simulation] Started proxy daemon for WAN '%s'", wan->label);
#endif

    return 0;
}

int proxy_manager_stop_wan(proxy_manager_ctx_t *ctx, uint32_t wan_idx) {
    if (!ctx || !ctx->config || wan_idx >= ctx->config->wan_count) return -1;
    wan_config_t *wan = &ctx->config->wans[wan_idx];

#if defined(__linux__)
    char pid_file[128];
    snprintf(pid_file, sizeof(pid_file), "/var/run/fluxwan_proxy_wan_%u.pid", wan_idx);
    FILE *pf = fopen(pid_file, "r");
    if (pf) {
        int pid = 0;
        if (fscanf(pf, "%d", &pid) == 1 && pid > 1) {
            kill(pid, SIGTERM);
            usleep(50000);
            kill(pid, SIGKILL);
        }
        fclose(pf);
        unlink(pid_file);
    }

    if (wan->proxy.tun_dev[0]) {
        char down_cmd[128];
        snprintf(down_cmd, sizeof(down_cmd), "ip link delete %s 2>/dev/null || true", wan->proxy.tun_dev);
        int r = system(down_cmd);
        (void)r;
    }
#endif

    ctx->pids[wan_idx] = -1;
    wan->proxy.pid = 0;
    wan->proxy.is_connected = false;
    wan->proxy.latency_ms = 0;
    return 0;
}

int proxy_manager_apply(proxy_manager_ctx_t *ctx) {
    if (!ctx || !ctx->config) return -1;
    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        wan_config_t *wan = &ctx->config->wans[i];
        if (wan->enabled && wan->proxy.enabled) {
            proxy_manager_start_wan(ctx, i);
        } else {
            proxy_manager_stop_wan(ctx, i);
        }
    }
    return 0;
}

int proxy_manager_test_tunnel(const wan_proxy_config_t *proxy, uint32_t *out_latency_ms) {
    if (!proxy || !out_latency_ms) return -1;
    *out_latency_ms = 0;

#if defined(__linux__)
    /* Quick TCP connect test to proxy endpoint */
    if (!proxy->server[0] || proxy->port == 0) return -1;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

    struct hostent *he = gethostbyname(proxy->server);
    if (!he) { close(s); return -1; }

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(proxy->port);
    memcpy(&saddr.sin_addr, he->h_addr_list[0], sizeof(saddr.sin_addr));

    if (connect(s, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        close(s);
        return -1;
    }
    close(s);

    clock_gettime(CLOCK_MONOTONIC, &end);
    uint32_t ms = (uint32_t)((end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000);
    *out_latency_ms = ms > 0 ? ms : 1;
    return 0;
#else
    *out_latency_ms = 42;
    return 0;
#endif
}

void proxy_manager_tick(proxy_manager_ctx_t *ctx) {
    if (!ctx || !ctx->config) return;

#if defined(__linux__)
    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        wan_config_t *wan = &ctx->config->wans[i];
        if (wan->enabled && wan->proxy.enabled) {
            if (ctx->pids[i] > 1) {
                if (kill(ctx->pids[i], 0) != 0) {
                    LOG_WARN("[Proxy] Proxy daemon for WAN '%s' died unexpectedly. Restarting...", wan->label);
                    proxy_manager_start_wan(ctx, i);
                }
            } else {
                proxy_manager_start_wan(ctx, i);
            }
        }
    }
#endif
}
