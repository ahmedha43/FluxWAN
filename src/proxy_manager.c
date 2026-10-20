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
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <net/if.h>
#elif defined(_WIN32) || defined(_WIN64)
#define strcasecmp _stricmp
#endif

struct proxy_manager_ctx {
    fluxwan_config_t *config;
    int pids[MAX_WANS];
    uint32_t fail_counts[MAX_WANS];
    uint64_t last_check_ms;
    uint64_t last_restart_ms[MAX_WANS];
    pthread_t supervisor_thread;
    bool thread_running;
    bool stop_requested;
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

int proxy_manager_parse_endpoint(const char *uri, proxy_endpoint_t *out_ep) {
    if (!uri || !out_ep) return -1;
    char uri_buf[2048];
    safe_str_copy(uri_buf, uri, sizeof(uri_buf));
    memset(out_ep, 0, sizeof(proxy_endpoint_t));
    safe_str_copy(out_ep->raw_uri, uri_buf, sizeof(out_ep->raw_uri));
    safe_str_copy(out_ep->transport, "ws", sizeof(out_ep->transport));
    safe_str_copy(out_ep->security, "tls", sizeof(out_ep->security));
    safe_str_copy(out_ep->encryption, "none", sizeof(out_ep->encryption));
    uri = uri_buf;

    /* 0. V2Box Locked Link: v2box://locked=<base64> or v2box://<base64> */
    if (strncmp(uri, "v2box://locked=", 15) == 0 || strncmp(uri, "v2box://", 8) == 0) {
        const char *b64_str = (strncmp(uri, "v2box://locked=", 15) == 0) ? (uri + 15) : (uri + 8);
        char decoded[2048] = {0};
        int dlen = base64_decode(b64_str, strlen(b64_str), decoded, sizeof(decoded));
        if (dlen > 0) {
            int res = proxy_manager_parse_endpoint(decoded, out_ep);
            if (res == 0) {
                /* Retain original user v2box URI for 1-click persistence */
                safe_str_copy(out_ep->raw_uri, uri, sizeof(out_ep->raw_uri));
            }
            return res;
        }
        return -1;
    }

    /* 1. VLESS: vless://uuid@server:port?query#name */
    if (strncmp(uri, "vless://", 8) == 0) {
        out_ep->proto = PROXY_PROTO_VLESS;
        safe_str_copy(out_ep->proto_str, "vless", sizeof(out_ep->proto_str));
        const char *p = uri + 8;
        const char *at = strchr(p, '@');
        if (!at) return -1;

        size_t ulen = (size_t)(at - p);
        if (ulen >= sizeof(out_ep->uuid)) ulen = sizeof(out_ep->uuid) - 1;
        memcpy(out_ep->uuid, p, ulen);
        out_ep->uuid[ulen] = '\0';

        p = at + 1;
        const char *colon = strchr(p, ':');
        const char *query = strchr(p, '?');
        if (!colon) return -1;

        size_t slen = (size_t)(colon - p);
        if (slen >= sizeof(out_ep->server)) slen = sizeof(out_ep->server) - 1;
        memcpy(out_ep->server, p, slen);
        out_ep->server[slen] = '\0';

        out_ep->port = (uint16_t)atoi(colon + 1);

        if (query) {
            extract_query_param(query, "encryption", out_ep->encryption, sizeof(out_ep->encryption));
            extract_query_param(query, "sni", out_ep->sni, sizeof(out_ep->sni));
            extract_query_param(query, "host", out_ep->host, sizeof(out_ep->host));
            extract_query_param(query, "path", out_ep->path, sizeof(out_ep->path));
            extract_query_param(query, "type", out_ep->transport, sizeof(out_ep->transport));
            extract_query_param(query, "security", out_ep->security, sizeof(out_ep->security));
        }
        if (!out_ep->encryption[0]) {
            safe_str_copy(out_ep->encryption, "none", sizeof(out_ep->encryption));
        }
        if (out_ep->sni[0] && !out_ep->host[0]) safe_str_copy(out_ep->host, out_ep->sni, sizeof(out_ep->host));
        if (out_ep->host[0] && !out_ep->sni[0]) safe_str_copy(out_ep->sni, out_ep->host, sizeof(out_ep->sni));
        if (out_ep->port == 80 && strcasecmp(out_ep->security, "tls") != 0) {
            safe_str_copy(out_ep->security, "none", sizeof(out_ep->security));
        }
        safe_str_copy(out_ep->raw_uri, uri, sizeof(out_ep->raw_uri));
        return 0;
    }

    /* 2. TROJAN: trojan://password@server:port?query#name */
    if (strncmp(uri, "trojan://", 9) == 0) {
        out_ep->proto = PROXY_PROTO_TROJAN;
        safe_str_copy(out_ep->proto_str, "trojan", sizeof(out_ep->proto_str));
        const char *p = uri + 9;
        const char *at = strchr(p, '@');
        if (!at) return -1;

        size_t ulen = (size_t)(at - p);
        if (ulen >= sizeof(out_ep->uuid)) ulen = sizeof(out_ep->uuid) - 1;
        memcpy(out_ep->uuid, p, ulen);
        out_ep->uuid[ulen] = '\0';

        p = at + 1;
        const char *colon = strchr(p, ':');
        const char *query = strchr(p, '?');
        if (!colon) return -1;

        size_t slen = (size_t)(colon - p);
        if (slen >= sizeof(out_ep->server)) slen = sizeof(out_ep->server) - 1;
        memcpy(out_ep->server, p, slen);
        out_ep->server[slen] = '\0';

        out_ep->port = (uint16_t)atoi(colon + 1);

        if (query) {
            extract_query_param(query, "sni", out_ep->sni, sizeof(out_ep->sni));
            extract_query_param(query, "host", out_ep->host, sizeof(out_ep->host));
            extract_query_param(query, "path", out_ep->path, sizeof(out_ep->path));
            extract_query_param(query, "type", out_ep->transport, sizeof(out_ep->transport));
            extract_query_param(query, "security", out_ep->security, sizeof(out_ep->security));
        }
        if (out_ep->sni[0] && !out_ep->host[0]) safe_str_copy(out_ep->host, out_ep->sni, sizeof(out_ep->host));
        if (out_ep->host[0] && !out_ep->sni[0]) safe_str_copy(out_ep->sni, out_ep->host, sizeof(out_ep->sni));
        if (out_ep->port == 80 && strcasecmp(out_ep->security, "tls") != 0) {
            safe_str_copy(out_ep->security, "none", sizeof(out_ep->security));
        }
        safe_str_copy(out_ep->raw_uri, uri, sizeof(out_ep->raw_uri));
        return 0;
    }

    /* 3. VMESS: vmess://<base64_json> */
    if (strncmp(uri, "vmess://", 8) == 0) {
        out_ep->proto = PROXY_PROTO_VMESS;
        safe_str_copy(out_ep->proto_str, "vmess", sizeof(out_ep->proto_str));
        const char *p = uri + 8;
        char json[2048] = {0};
        base64_decode(p, strlen(p), json, sizeof(json));

        json_get_string(json, "add", out_ep->server, sizeof(out_ep->server));
        char port_str[16] = {0};
        json_get_string(json, "port", port_str, sizeof(port_str));
        out_ep->port = (uint16_t)atoi(port_str);
        json_get_string(json, "id", out_ep->uuid, sizeof(out_ep->uuid));
        json_get_string(json, "sni", out_ep->sni, sizeof(out_ep->sni));
        json_get_string(json, "host", out_ep->host, sizeof(out_ep->host));
        json_get_string(json, "path", out_ep->path, sizeof(out_ep->path));
        json_get_string(json, "net", out_ep->transport, sizeof(out_ep->transport));
        json_get_string(json, "tls", out_ep->security, sizeof(out_ep->security));

        if (out_ep->sni[0] && !out_ep->host[0]) safe_str_copy(out_ep->host, out_ep->sni, sizeof(out_ep->host));
        return 0;
    }

    /* 4. Shadowsocks: ss://<base64>@server:port */
    if (strncmp(uri, "ss://", 5) == 0) {
        out_ep->proto = PROXY_PROTO_SHADOWSOCKS;
        safe_str_copy(out_ep->proto_str, "shadowsocks", sizeof(out_ep->proto_str));
        const char *p = uri + 5;
        const char *at = strchr(p, '@');
        if (at) {
            char userinfo[256] = {0};
            size_t ulen = (size_t)(at - p);
            if (ulen >= sizeof(userinfo)) ulen = sizeof(userinfo) - 1;
            memcpy(userinfo, p, ulen);
            userinfo[ulen] = '\0';
            safe_str_copy(out_ep->uuid, userinfo, sizeof(out_ep->uuid));

            p = at + 1;
            const char *colon = strchr(p, ':');
            if (colon) {
                size_t slen = (size_t)(colon - p);
                if (slen >= sizeof(out_ep->server)) slen = sizeof(out_ep->server) - 1;
                memcpy(out_ep->server, p, slen);
                out_ep->server[slen] = '\0';
                out_ep->port = (uint16_t)atoi(colon + 1);
                return 0;
            }
        }
    }

    return -1;
}

void proxy_manager_sync_servers(wan_proxy_config_t *p) {
    if (!p) return;
    if (p->servers[0].raw_uri[0] == '\0' && p->raw_uri[0] != '\0') {
        safe_str_copy(p->servers[0].raw_uri, p->raw_uri, sizeof(p->servers[0].raw_uri));
    }
    if (p->servers[0].server[0] == '\0' && p->server[0] != '\0') {
        p->servers[0].proto = p->proto;
        safe_str_copy(p->servers[0].proto_str, p->proto_str, sizeof(p->servers[0].proto_str));
        safe_str_copy(p->servers[0].server, p->server, sizeof(p->servers[0].server));
        p->servers[0].port = p->port;
        safe_str_copy(p->servers[0].uuid, p->uuid, sizeof(p->servers[0].uuid));
        safe_str_copy(p->servers[0].sni, p->sni, sizeof(p->servers[0].sni));
        safe_str_copy(p->servers[0].host, p->host, sizeof(p->servers[0].host));
        safe_str_copy(p->servers[0].path, p->path, sizeof(p->servers[0].path));
        safe_str_copy(p->servers[0].transport, p->transport, sizeof(p->servers[0].transport));
        safe_str_copy(p->servers[0].security, p->security, sizeof(p->servers[0].security));
        safe_str_copy(p->servers[0].encryption, p->encryption, sizeof(p->servers[0].encryption));
        safe_str_copy(p->servers[0].raw_uri, p->raw_uri, sizeof(p->servers[0].raw_uri));
    }

    uint32_t count = 0;
    for (int i = 0; i < MAX_PROXY_SERVERS; i++) {
        if (p->servers[i].raw_uri[0] != '\0') {
            if (p->servers[i].server[0] == '\0') {
                proxy_manager_parse_endpoint(p->servers[i].raw_uri, &p->servers[i]);
            }
        }
        if (p->servers[i].server[0] != '\0') {
            count++;
        }
    }
    p->server_count = count > 0 ? count : (p->server[0] ? 1 : 0);
    if (count > 0 && p->servers[0].server[0] != '\0') {
        p->proto = p->servers[0].proto;
        safe_str_copy(p->proto_str, p->servers[0].proto_str, sizeof(p->proto_str));
        safe_str_copy(p->server, p->servers[0].server, sizeof(p->server));
        p->port = p->servers[0].port;
        safe_str_copy(p->uuid, p->servers[0].uuid, sizeof(p->uuid));
        safe_str_copy(p->sni, p->servers[0].sni, sizeof(p->sni));
        safe_str_copy(p->host, p->servers[0].host, sizeof(p->host));
        safe_str_copy(p->path, p->servers[0].path, sizeof(p->path));
        safe_str_copy(p->transport, p->servers[0].transport, sizeof(p->transport));
        safe_str_copy(p->security, p->servers[0].security, sizeof(p->security));
        safe_str_copy(p->encryption, p->servers[0].encryption, sizeof(p->encryption));
        safe_str_copy(p->raw_uri, p->servers[0].raw_uri, sizeof(p->raw_uri));
    }
}

int proxy_manager_parse_uri(const char *uri, wan_proxy_config_t *out_proxy) {
    if (!uri || !out_proxy) return -1;
    memset(out_proxy, 0, sizeof(wan_proxy_config_t));
    safe_str_copy(out_proxy->raw_uri, uri, sizeof(out_proxy->raw_uri));
    out_proxy->enabled = true;
    int rc = proxy_manager_parse_endpoint(uri, &out_proxy->servers[0]);
    if (rc == 0) {
        out_proxy->server_count = 1;
        proxy_manager_sync_servers(out_proxy);
    }
    return rc;
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

    /* Resolve server domain to IPv4 if needed to avoid DNS loops on Zero-Rating SIMs */
    char resolved_server[128];
    safe_str_copy(resolved_server, p->server, sizeof(resolved_server));
    struct in_addr test_addr;
    if (inet_pton(AF_INET, p->server, &test_addr) <= 0) {
        struct hostent *he = gethostbyname(p->server);
        if (he && he->h_addr_list && he->h_addr_list[0]) {
            inet_ntop(AF_INET, he->h_addr_list[0], resolved_server, sizeof(resolved_server));
            LOG_INFO("[Proxy] Resolved server domain '%s' -> IP '%s' for zero-rating offline robustness",
                     p->server, resolved_server);
        }
    }

    uint32_t fwmark = 0x1000 + wan_idx;

    /* Build Sing-box Universal JSON Configuration */
    fprintf(f, "{\n");
    fprintf(f, "  \"log\": {\n    \"level\": \"warn\"\n  },\n");
    fprintf(f, "  \"dns\": {\n");
    fprintf(f, "    \"servers\": [\n");
    fprintf(f, "      {\"tag\": \"local-dns\", \"address\": \"local\", \"detour\": \"direct\"}\n");
    fprintf(f, "    ]\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"inbounds\": [\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"type\": \"tun\",\n");
    fprintf(f, "      \"tag\": \"tun-in\",\n");
    fprintf(f, "      \"interface_name\": \"%s\",\n", tun_name);
    fprintf(f, "      \"address\": [\n        \"198.18.%u.1/24\"\n      ],\n", (wan_idx + 10) % 250);
    fprintf(f, "      \"mtu\": 1420,\n");
    fprintf(f, "      \"stack\": \"system\",\n");
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
    fprintf(f, "      \"server\": \"%s\",\n", resolved_server);
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
    fprintf(f, "    },\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"type\": \"direct\",\n");
    fprintf(f, "      \"tag\": \"direct\",\n");
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

/* Helper to detect if a binary exists and is executable in standard search paths */
static bool check_binary_available(const char *name) {
#if defined(__linux__)
    char path[128];
    snprintf(path, sizeof(path), "/usr/bin/%s", name);
    if (access(path, X_OK) == 0) return true;
    snprintf(path, sizeof(path), "/usr/local/bin/%s", name);
    if (access(path, X_OK) == 0) return true;
    snprintf(path, sizeof(path), "/bin/%s", name);
    if (access(path, X_OK) == 0) return true;
    return false;
#else
    (void)name;
    return true;
#endif
}

/* Returns true if the proxy configuration strictly requires Xray-core (e.g. ML-KEM post-quantum or Multi-Server balancer) */
static bool is_xray_required(const wan_proxy_config_t *p) {
    if (!p) return false;
    if (p->server_count > 1) {
        return true;
    }
    for (int i = 0; i < MAX_PROXY_SERVERS; i++) {
        if (p->servers[i].encryption[0] && strcmp(p->servers[i].encryption, "none") != 0) {
            return true;
        }
        if (strstr(p->servers[i].raw_uri, "v2box://") != NULL ||
            strstr(p->servers[i].raw_uri, "mlkem") != NULL ||
            strstr(p->servers[i].raw_uri, "x25519plus") != NULL) {
            return true;
        }
    }
    if (p->encryption[0] && strcmp(p->encryption, "none") != 0) {
        return true;
    }
    if (strstr(p->raw_uri, "v2box://") != NULL ||
        strstr(p->raw_uri, "mlkem") != NULL ||
        strstr(p->raw_uri, "x25519plus") != NULL) {
        return true;
    }
    return false;
}

/* Helper to format and write a single Xray outbound element */
static void write_xray_single_outbound(FILE *f, const proxy_endpoint_t *ep, const char *tag, const wan_config_t *wan, uint32_t fwmark) {
    if (!f || !ep || !tag || !wan) return;

    char resolved_server[128];
    safe_str_copy(resolved_server, ep->server, sizeof(resolved_server));
    struct in_addr test_addr;
    if (inet_pton(AF_INET, ep->server, &test_addr) <= 0) {
        struct hostent *he = gethostbyname(ep->server);
        if (he && he->h_addr_list && he->h_addr_list[0]) {
            inet_ntop(AF_INET, he->h_addr_list[0], resolved_server, sizeof(resolved_server));
            LOG_INFO("[Proxy] Resolved server domain '%s' -> IP '%s'", ep->server, resolved_server);
        }
    }

    const char *proto = ep->proto_str[0] ? ep->proto_str : "vless";
    const char *enc = ep->encryption[0] ? ep->encryption : "none";

    fprintf(f, "    {\n");
    fprintf(f, "      \"tag\": \"%s\",\n", tag);
    fprintf(f, "      \"protocol\": \"%s\",\n", proto);
    fprintf(f, "      \"settings\": {\n");

    if (strcmp(proto, "vless") == 0) {
        fprintf(f, "        \"vnext\": [\n");
        fprintf(f, "          {\n");
        fprintf(f, "            \"address\": \"%s\",\n", resolved_server);
        fprintf(f, "            \"port\": %u,\n", ep->port > 0 ? ep->port : 443);
        fprintf(f, "            \"users\": [\n");
        fprintf(f, "              {\n");
        fprintf(f, "                \"id\": \"%s\",\n", ep->uuid);
        fprintf(f, "                \"encryption\": \"%s\",\n", enc);
        fprintf(f, "                \"level\": 0\n");
        fprintf(f, "              }\n");
        fprintf(f, "            ]\n");
        fprintf(f, "          }\n");
        fprintf(f, "        ]\n");
    } else if (strcmp(proto, "vmess") == 0) {
        fprintf(f, "        \"vnext\": [\n");
        fprintf(f, "          {\n");
        fprintf(f, "            \"address\": \"%s\",\n", resolved_server);
        fprintf(f, "            \"port\": %u,\n", ep->port > 0 ? ep->port : 443);
        fprintf(f, "            \"users\": [\n");
        fprintf(f, "              {\n");
        fprintf(f, "                \"id\": \"%s\",\n", ep->uuid);
        fprintf(f, "                \"alterId\": 0,\n");
        fprintf(f, "                \"security\": \"auto\"\n");
        fprintf(f, "              }\n");
        fprintf(f, "            ]\n");
        fprintf(f, "          }\n");
        fprintf(f, "        ]\n");
    } else if (strcmp(proto, "trojan") == 0) {
        fprintf(f, "        \"servers\": [\n");
        fprintf(f, "          {\n");
        fprintf(f, "            \"address\": \"%s\",\n", resolved_server);
        fprintf(f, "            \"port\": %u,\n", ep->port > 0 ? ep->port : 443);
        fprintf(f, "            \"password\": \"%s\"\n", ep->uuid);
        fprintf(f, "          }\n");
        fprintf(f, "        ]\n");
    } else if (strcmp(proto, "shadowsocks") == 0) {
        fprintf(f, "        \"servers\": [\n");
        fprintf(f, "          {\n");
        fprintf(f, "            \"address\": \"%s\",\n", resolved_server);
        fprintf(f, "            \"port\": %u,\n", ep->port > 0 ? ep->port : 8388);
        fprintf(f, "            \"password\": \"%s\",\n", ep->uuid);
        fprintf(f, "            \"method\": \"chacha20-ietf-poly1305\"\n");
        fprintf(f, "          }\n");
        fprintf(f, "        ]\n");
    }

    fprintf(f, "      },\n");

    /* Stream settings (TLS, WebSocket, physical binding) */
    bool has_tls = false;
    if (strcasecmp(ep->security, "none") != 0 && strcasecmp(ep->security, "plain") != 0) {
        if (strcasecmp(ep->security, "tls") == 0 || ep->port == 443 || (ep->sni[0] != '\0' && ep->port != 80)) {
            has_tls = true;
        }
    }

    const char *network = (strcasecmp(ep->transport, "ws") == 0 || ep->path[0] != '\0') ? "ws" : "tcp";

    fprintf(f, "      \"streamSettings\": {\n");
    fprintf(f, "        \"network\": \"%s\",\n", network);
    fprintf(f, "        \"security\": \"%s\",\n", has_tls ? "tls" : "none");

    if (has_tls) {
        const char *s_sni = ep->sni[0] ? ep->sni : (ep->host[0] ? ep->host : resolved_server);
        fprintf(f, "        \"tlsSettings\": {\n");
        fprintf(f, "          \"serverName\": \"%s\",\n", s_sni);
        fprintf(f, "          \"allowInsecure\": true\n");
        fprintf(f, "        },\n");
    }

    if (strcmp(network, "ws") == 0) {
        const char *h = ep->host[0] ? ep->host : ep->sni;
        fprintf(f, "        \"wsSettings\": {\n");
        fprintf(f, "          \"path\": \"%s\",\n", ep->path[0] ? ep->path : "/");
        if (h && h[0]) {
            fprintf(f, "          \"headers\": {\n");
            fprintf(f, "            \"Host\": \"%s\"\n", h);
            fprintf(f, "          }\n");
        }
        fprintf(f, "        },\n");
    }

    /* Sockopt: strict physical WAN binding & fwmark */
    fprintf(f, "        \"sockopt\": {\n");
    fprintf(f, "          \"mark\": %u,\n", fwmark);
    fprintf(f, "          \"interface\": \"%s\"\n", wan->name);
    fprintf(f, "        }\n");
    fprintf(f, "      }\n");
    fprintf(f, "    },\n");
}

/* Generates Xray-core JSON configuration with native TUN inbound, Multi-Server Balancer/Failover, and VLESS Post-Quantum Encryption */
static int generate_xray_config_file(const wan_config_t *wan, int wan_idx, char *out_path, size_t max_path) {
    if (!wan || !out_path) return -1;
    snprintf(out_path, max_path, "/etc/fluxwan/proxy_wan_%u.json", wan->id > 0 ? wan->id : (uint32_t)(wan_idx + 1));

#if defined(__linux__)
    mkdir("/etc/fluxwan", 0755);
#endif

    FILE *f = fopen(out_path, "w");
    if (!f) {
        LOG_ERROR("[Proxy] Failed to create Xray config file %s", out_path);
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

    fprintf(f, "{\n");
    fprintf(f, "  \"log\": {\n    \"loglevel\": \"warning\"\n  },\n");
    fprintf(f, "  \"inbounds\": [\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"tag\": \"tun-in\",\n");
    fprintf(f, "      \"protocol\": \"tun\",\n");
    fprintf(f, "      \"settings\": {\n");
    fprintf(f, "        \"name\": \"%s\",\n", tun_name);
    fprintf(f, "        \"mtu\": 1420,\n");
    fprintf(f, "        \"gateway\": [\n          \"198.18.%u.1/24\"\n        ]\n", (wan_idx + 10) % 250);
    fprintf(f, "      }\n");
    fprintf(f, "    }\n");
    fprintf(f, "  ],\n");

    /* Outbounds */
    fprintf(f, "  \"outbounds\": [\n");

    uint32_t active_servers = 0;
    for (int i = 0; i < MAX_PROXY_SERVERS; i++) {
        if (p->servers[i].server[0] != '\0') {
            active_servers++;
        }
    }

    if (active_servers > 1) {
        for (int i = 0; i < MAX_PROXY_SERVERS; i++) {
            if (p->servers[i].server[0] != '\0') {
                char tag[32];
                snprintf(tag, sizeof(tag), "proxy-out-%d", i);
                write_xray_single_outbound(f, &p->servers[i], tag, wan, fwmark);
            }
        }
    } else {
        /* Single server outbound */
        const proxy_endpoint_t *ep = (p->servers[0].server[0] != '\0') ? &p->servers[0] : (const proxy_endpoint_t *)p;
        write_xray_single_outbound(f, ep, "proxy-out", wan, fwmark);
    }

    /* Direct freedom outbound with egress interface pinning */
    fprintf(f, "    {\n");
    fprintf(f, "      \"tag\": \"direct\",\n");
    fprintf(f, "      \"protocol\": \"freedom\",\n");
    fprintf(f, "      \"streamSettings\": {\n");
    fprintf(f, "        \"sockopt\": {\n");
    fprintf(f, "          \"mark\": %u,\n", fwmark);
    fprintf(f, "          \"interface\": \"%s\"\n", wan->name);
    fprintf(f, "        }\n");
    fprintf(f, "      }\n");
    fprintf(f, "    }\n");
    fprintf(f, "  ]");

    if (active_servers > 1) {
        const char *strategy_str = (p->strategy == PROXY_STRATEGY_ROUND_ROBIN) ? "roundRobin" : "leastPing";
        fprintf(f, ",\n");
        fprintf(f, "  \"observatory\": {\n");
        fprintf(f, "    \"subjectSelector\": [\"proxy-out-\"],\n");
        fprintf(f, "    \"probeURL\": \"http://1.1.1.1\",\n");
        fprintf(f, "    \"probeInterval\": \"3s\",\n");
        fprintf(f, "    \"enableConcurrency\": true\n");
        fprintf(f, "  },\n");
        fprintf(f, "  \"routing\": {\n");
        fprintf(f, "    \"domainStrategy\": \"AsIs\",\n");
        fprintf(f, "    \"balancers\": [\n");
        fprintf(f, "      {\n");
        fprintf(f, "        \"tag\": \"wan_balancer\",\n");
        fprintf(f, "        \"selector\": [\"proxy-out-\"],\n");
        fprintf(f, "        \"strategy\": {\n");
        fprintf(f, "          \"type\": \"%s\"\n", strategy_str);
        fprintf(f, "        }\n");
        fprintf(f, "      }\n");
        fprintf(f, "    ],\n");
        fprintf(f, "    \"rules\": [\n");
        fprintf(f, "      {\n");
        fprintf(f, "        \"type\": \"field\",\n");
        fprintf(f, "        \"inboundTag\": [\"tun-in\"],\n");
        fprintf(f, "        \"balancerTag\": \"wan_balancer\"\n");
        fprintf(f, "      },\n");
        fprintf(f, "      {\n");
        fprintf(f, "        \"type\": \"field\",\n");
        fprintf(f, "        \"outboundTag\": \"direct\"\n");
        fprintf(f, "      }\n");
        fprintf(f, "    ]\n");
        fprintf(f, "  }\n");
    } else {
        fprintf(f, ",\n");
        fprintf(f, "  \"routing\": {\n");
        fprintf(f, "    \"domainStrategy\": \"AsIs\",\n");
        fprintf(f, "    \"rules\": [\n");
        fprintf(f, "      {\n");
        fprintf(f, "        \"type\": \"field\",\n");
        fprintf(f, "        \"inboundTag\": [\"tun-in\"],\n");
        fprintf(f, "        \"outboundTag\": \"proxy-out\"\n");
        fprintf(f, "      },\n");
        fprintf(f, "      {\n");
        fprintf(f, "        \"type\": \"field\",\n");
        fprintf(f, "        \"outboundTag\": \"direct\"\n");
        fprintf(f, "      }\n");
        fprintf(f, "    ]\n");
        fprintf(f, "  }\n");
    }

    fprintf(f, "}\n");
    fclose(f);

    LOG_INFO("[Proxy] Generated Xray-core configuration for WAN '%s' at %s (Servers: %u, Strategy: %s, Device %s, Mark 0x%x)",
             wan->label, out_path, active_servers,
             (p->strategy == PROXY_STRATEGY_ROUND_ROBIN) ? "roundRobin" : "leastPing",
             wan->name, fwmark);
    return 0;
}

#if defined(__linux__)
static void proxy_manager_supervise_tick(proxy_manager_ctx_t *ctx);
static void *proxy_supervisor_worker(void *arg) {
    proxy_manager_ctx_t *ctx = (proxy_manager_ctx_t *)arg;
    while (!ctx->stop_requested) {
        /* Sleep in 100ms slices for 4 seconds for immediate clean shutdown */
        for (int k = 0; k < 40 && !ctx->stop_requested; k++) {
            usleep(100000);
        }
        if (ctx->stop_requested) break;

        proxy_manager_supervise_tick(ctx);
    }
    return NULL;
}
#endif

proxy_manager_ctx_t *proxy_manager_init(fluxwan_config_t *config) {
    proxy_manager_ctx_t *ctx = calloc(1, sizeof(proxy_manager_ctx_t));
    if (!ctx) return NULL;
    ctx->config = config;
    for (int i = 0; i < MAX_WANS; i++) {
        ctx->pids[i] = -1;
        ctx->last_restart_ms[i] = 0;
    }

#if defined(__linux__)
    ctx->stop_requested = false;
    if (pthread_create(&ctx->supervisor_thread, NULL, proxy_supervisor_worker, ctx) == 0) {
        ctx->thread_running = true;
        LOG_INFO("[Proxy Supervisor] Dedicated asynchronous proxy supervisor thread started successfully.");
    }
#endif
    return ctx;
}

void proxy_manager_close(proxy_manager_ctx_t *ctx) {
    if (!ctx) return;
#if defined(__linux__)
    if (ctx->thread_running) {
        ctx->stop_requested = true;
        pthread_join(ctx->supervisor_thread, NULL);
        ctx->thread_running = false;
    }
#endif
    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        proxy_manager_stop_wan(ctx, i);
    }
    free(ctx);
}

int proxy_manager_generate_config(const wan_config_t *wan, int wan_idx, char *out_path, size_t max_path) {
    if (!wan || !out_path) return -1;
    bool use_xray = check_binary_available("xray");
    if (!use_xray && is_xray_required(&wan->proxy)) {
        use_xray = true;
    }
    return use_xray ? generate_xray_config_file(wan, wan_idx, out_path, max_path)
                    : generate_proxy_config_file(wan, wan_idx, out_path, max_path);
}

int proxy_manager_start_wan(proxy_manager_ctx_t *ctx, uint32_t wan_idx) {
    if (!ctx || !ctx->config || wan_idx >= ctx->config->wan_count) return -1;
    wan_config_t *wan = &ctx->config->wans[wan_idx];
    /* Synchronize and parse all configured proxy server endpoints */
    if (wan->enabled && wan->proxy.enabled) {
        proxy_manager_sync_servers(&wan->proxy);
    }
    if (!wan->enabled || !wan->proxy.enabled || (!wan->proxy.server[0] && wan->proxy.server_count == 0)) {
        return proxy_manager_stop_wan(ctx, wan_idx);
    }

    /* Set default TUN interface name if not set */
    if (!wan->proxy.tun_dev[0]) {
        snprintf(wan->proxy.tun_dev, sizeof(wan->proxy.tun_dev), "tun_wan%u", (unsigned int)((wan->id > 0 ? wan->id : (wan_idx + 1)) % 1000));
    }

    char conf_path[256];
    int gen_rc = proxy_manager_generate_config(wan, (int)wan_idx, conf_path, sizeof(conf_path));
    if (gen_rc != 0) {
        return -1;
    }

    bool use_xray = check_binary_available("xray") || is_xray_required(&wan->proxy);

#if defined(__linux__)
    /* Stop any existing instance for this WAN */
    proxy_manager_stop_wan(ctx, wan_idx);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ctx->last_restart_ms[wan_idx] = (uint64_t)ts.tv_sec * 1000ULL + (ts.tv_nsec / 1000000ULL);

    char pid_file[128];
    snprintf(pid_file, sizeof(pid_file), "/var/run/fluxwan_proxy_wan_%u.pid", wan_idx);

    /* Launch selected daemon (Xray or Sing-box) in background with zero-disk-bloat output */
    char cmd[2048];
    if (use_xray) {
        snprintf(cmd, sizeof(cmd),
                 "sh -c 'xray run -c %s >/dev/null 2>&1 & echo $! > %s' &",
                 conf_path, pid_file);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "sh -c 'export ENABLE_DEPRECATED_TUN_ADDRESS_X=true; sing-box run -c %s >/dev/null 2>&1 & echo $! > %s' &",
                 conf_path, pid_file);
    }

    int rc = system(cmd);
    (void)rc;

    /* Read back PID without blocking on latency probe */
    usleep(100000); /* 100ms initial grace period for PID file write */
    FILE *pf = fopen(pid_file, "r");
    if (pf) {
        int pid = 0;
        if (fscanf(pf, "%d", &pid) == 1 && pid > 1) {
            ctx->pids[wan_idx] = pid;
            wan->proxy.pid = pid;
            wan->proxy.is_connected = true;

            /* Wait up to 2.5s for Xray/sing-box to create the kernel TUN interface before adding routes */
            for (int wait_i = 0; wait_i < 25; wait_i++) {
                if (if_nametoindex(wan->proxy.tun_dev) > 0) break;
                usleep(100000);
            }

            /* Ensure the tun interface route is set in the WAN table and table main */
            uint32_t main_metric = (wan_idx == 1) ? 10 : ((wan_idx == 2) ? 15 : (50 + ((unsigned int)wan_idx * 5)));
            char tun_route_cmd[640];
            snprintf(tun_route_cmd, sizeof(tun_route_cmd),
                     "ip link set %s up 2>/dev/null || true; "
                     "ip addr replace 198.18.%u.1/24 dev %s 2>/dev/null || true; "
                     "ip rule del oif %s table %u 2>/dev/null || true; "
                     "ip rule add oif %s table %u pref 90 2>/dev/null || true; "
                     "ip route replace default dev %s table %u proto static 2>/dev/null || true; "
                     "ip route add default dev %s metric %u 2>/dev/null || ip route replace default dev %s metric %u 2>/dev/null || true",
                     wan->proxy.tun_dev,
                     (unsigned int)((wan_idx + 10) % 250), wan->proxy.tun_dev,
                     wan->proxy.tun_dev, wan->table_id,
                     wan->proxy.tun_dev, wan->table_id,
                     wan->proxy.tun_dev, wan->table_id,
                     wan->proxy.tun_dev, main_metric,
                     wan->proxy.tun_dev, main_metric);
            safe_system(tun_route_cmd);
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
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;

    /* If the TUN interface is active and proxy daemon is running,
     * perform an end-to-end tunnel probe through the TUN interface. */
    if (proxy->is_connected && proxy->tun_dev[0] != '\0') {
#ifdef SO_BINDTODEVICE
        setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, proxy->tun_dev, strlen(proxy->tun_dev));
#endif
        saddr.sin_port = htons(80);
        inet_pton(AF_INET, "1.0.0.1", &saddr.sin_addr);
    } else {
        if (!proxy->server[0] || proxy->port == 0) { close(s); return -1; }
#ifdef SO_BINDTODEVICE
        if (proxy->bind_interface[0]) {
            setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, proxy->bind_interface, strlen(proxy->bind_interface));
        }
#endif
        if (inet_pton(AF_INET, proxy->server, &saddr.sin_addr) <= 0) {
            struct hostent *he = gethostbyname(proxy->server);
            if (!he || !he->h_addr_list[0]) { close(s); return -1; }
            memcpy(&saddr.sin_addr, he->h_addr_list[0], sizeof(saddr.sin_addr));
        }
        saddr.sin_port = htons(proxy->port);
    }

    /* Non-blocking connect with 2.5s timeout to tolerate heavy download bufferbloat */
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(s, (struct sockaddr *)&saddr, sizeof(saddr));
    if (rc < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK)) {
        struct pollfd pfd;
        pfd.fd = s;
        pfd.events = POLLOUT;
        int poll_rc = poll(&pfd, 1, 2500);
        if (poll_rc > 0 && (pfd.revents & POLLOUT)) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                rc = 0;
            } else {
                rc = -1;
            }
        } else {
            rc = -1;
        }
    }
    close(s);

    /* Fallback: if in-tunnel 1.0.0.1:80 probe timed out during heavy download saturation,
     * verify physical WAN -> proxy server TCP reachability before declaring failure */
    if (rc != 0 && proxy->is_connected && proxy->server[0] && proxy->port > 0) {
        int s2 = socket(AF_INET, SOCK_STREAM, 0);
        if (s2 >= 0) {
#ifdef SO_BINDTODEVICE
            if (proxy->bind_interface[0]) {
                setsockopt(s2, SOL_SOCKET, SO_BINDTODEVICE, proxy->bind_interface, strlen(proxy->bind_interface));
            }
#endif
            struct sockaddr_in saddr2;
            memset(&saddr2, 0, sizeof(saddr2));
            saddr2.sin_family = AF_INET;
            saddr2.sin_port = htons(proxy->port);
            if (inet_pton(AF_INET, proxy->server, &saddr2.sin_addr) > 0) {
                int fl2 = fcntl(s2, F_GETFL, 0);
                if (fl2 >= 0) fcntl(s2, F_SETFL, fl2 | O_NONBLOCK);
                int rc2 = connect(s2, (struct sockaddr *)&saddr2, sizeof(saddr2));
                if (rc2 < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK)) {
                    struct pollfd pfd2 = { .fd = s2, .events = POLLOUT };
                    if (poll(&pfd2, 1, 2000) > 0 && (pfd2.revents & POLLOUT)) {
                        int err2 = 0;
                        socklen_t len2 = sizeof(err2);
                        if (getsockopt(s2, SOL_SOCKET, SO_ERROR, &err2, &len2) == 0 && err2 == 0) {
                            rc = 0;
                        }
                    }
                } else if (rc2 == 0) {
                    rc = 0;
                }
            }
            close(s2);
        }
    }

    if (rc != 0) return -1;

    clock_gettime(CLOCK_MONOTONIC, &end);
    uint32_t ms = (uint32_t)((end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000);
    *out_latency_ms = ms > 0 ? ms : 1;
    return 0;
#else
    *out_latency_ms = 42;
    return 0;
#endif
}

#if defined(__linux__)
static void proxy_manager_supervise_tick(proxy_manager_ctx_t *ctx) {
    if (!ctx || !ctx->config) return;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ms = (uint64_t)ts.tv_sec * 1000ULL + (ts.tv_nsec / 1000000ULL);

    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        wan_config_t *wan = &ctx->config->wans[i];
        if (!wan->enabled || !wan->proxy.enabled) continue;

        if (wan->proxy.bind_interface[0] == '\0' && wan->name[0]) {
            safe_str_copy(wan->proxy.bind_interface, wan->name, sizeof(wan->proxy.bind_interface));
        }

        bool alive = false;
        if (ctx->pids[i] > 1 && kill(ctx->pids[i], 0) == 0) {
            alive = true;
        }

        if (!alive) {
            /* Enforce minimum 5-second backoff between restart attempts */
            if (now_ms - ctx->last_restart_ms[i] >= 5000) {
                LOG_WARN("[Proxy Supervisor] Proxy daemon for WAN '%s' died or stopped. Auto-restarting...", wan->label);
                ctx->last_restart_ms[i] = now_ms;
                proxy_manager_start_wan(ctx, i);
            }
            wan->proxy.is_connected = false;
            wan->metrics.packet_loss_pct = 100.0f;
            wan->proxy.latency_ms = 0;
            wan->metrics.rtt_ms = 0;
            continue;
        }

        /* Ensure physical proxy table and TUN routes are active without deleting existing rules */
        if (wan->proxy.tun_dev[0] && if_nametoindex(wan->proxy.tun_dev) > 0) {
            uint32_t fwmark = 0x1000 + i;
            uint32_t phys_table = 1000 + wan->table_id;
            uint32_t main_metric = (i == 1) ? 10 : ((i == 2) ? 15 : (50 + ((unsigned int)i * 5)));
            char wan_gw[32] = {0};
            if (wan->gateway != 0) {
                ip_to_str(wan->gateway, wan_gw, sizeof(wan_gw));
            }
            char chk_route[768];
            if (wan_gw[0]) {
                snprintf(chk_route, sizeof(chk_route),
                         "ip route del default dev %s 2>/dev/null || true; "
                         "ip route replace default via %s dev %s table %u proto static 2>/dev/null || true; "
                         "ip rule show | grep -q 'fwmark 0x%x lookup %u' || ip rule add fwmark 0x%x table %u pref 40 2>/dev/null || true; "
                         "ip link set %s up 2>/dev/null || true; "
                         "ip rule show | grep -q 'oif %s lookup %u' || ip rule add oif %s table %u pref 90 2>/dev/null || true; "
                         "ip route replace default dev %s table %u proto static 2>/dev/null || true; "
                         "ip route replace default dev %s metric %u 2>/dev/null || true",
                         wan->name,
                         wan_gw, wan->name, phys_table,
                         fwmark, phys_table, fwmark, phys_table,
                         wan->proxy.tun_dev,
                         wan->proxy.tun_dev, wan->table_id, wan->proxy.tun_dev, wan->table_id,
                         wan->proxy.tun_dev, wan->table_id,
                         wan->proxy.tun_dev, main_metric);
            } else {
                snprintf(chk_route, sizeof(chk_route),
                         "ip link set %s up 2>/dev/null || true; "
                         "ip rule show | grep -q 'oif %s lookup %u' || ip rule add oif %s table %u pref 90 2>/dev/null || true; "
                         "ip route replace default dev %s table %u proto static 2>/dev/null || true; "
                         "ip route replace default dev %s metric %u 2>/dev/null || true",
                         wan->proxy.tun_dev,
                         wan->proxy.tun_dev, wan->table_id, wan->proxy.tun_dev, wan->table_id,
                         wan->proxy.tun_dev, wan->table_id,
                         wan->proxy.tun_dev, main_metric);
            }
            safe_system(chk_route);
        }

        /* Alive: test tunnel latency asynchronously in background worker thread */
        uint32_t lat_ms = 0;
        if (proxy_manager_test_tunnel(&wan->proxy, &lat_ms) == 0 && lat_ms > 0) {
            wan->proxy.latency_ms = lat_ms;
            wan->metrics.rtt_ms = lat_ms;
            wan->metrics.packet_loss_pct = 0.0f;
            wan->state = WAN_STATE_HEALTHY;
            ctx->fail_counts[i] = 0;
        } else {
            ctx->fail_counts[i]++;
            LOG_WARN("[Proxy Supervisor] Tunnel probe delayed/failed for WAN '%s' (%s:%u, strike %u)",
                     wan->label, wan->proxy.server, wan->proxy.port, ctx->fail_counts[i]);
            /* Only restart if the TUN device actually disappeared; never kill an active TUN under load */
            if (wan->proxy.tun_dev[0] && if_nametoindex(wan->proxy.tun_dev) == 0) {
                if (now_ms - ctx->last_restart_ms[i] >= 10000) {
                    LOG_WARN("[Proxy Self-Healing] TUN interface %s missing for WAN '%s'. Auto-restarting proxy daemon...",
                             wan->proxy.tun_dev, wan->label);
                    ctx->fail_counts[i] = 0;
                    ctx->last_restart_ms[i] = now_ms;
                    proxy_manager_start_wan(ctx, i);
                }
            }
        }
    }
}
#endif

void proxy_manager_tick(proxy_manager_ctx_t *ctx) {
    (void)ctx;
    /* Handled asynchronously by dedicated proxy_supervisor_worker thread.
     * Guaranteed ZERO latency jitter or stalling on the core routing engine! */
}
