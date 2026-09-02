#include "config.h"
#include <ctype.h>

static char *read_file_to_string(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (length <= 0) {
        fclose(f);
        return NULL;
    }

    char *buffer = malloc(length + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    size_t read_bytes = fread(buffer, 1, length, f);
    buffer[read_bytes] = '\0';
    fclose(f);
    return buffer;
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

static float extract_json_float(const char *json, const char *key, float default_val) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return default_val;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return (float)atof(p);
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

static const char *find_matching_bracket(const char *start) {
    if (!start || *start != '[') return NULL;
    int depth = 0;
    for (const char *p = start; *p; p++) {
        if (*p == '[') depth++;
        else if (*p == ']') {
            depth--;
            if (depth == 0) return p;
        }
    }
    return NULL;
}

int config_load(const char *config_path, fluxwan_config_t *out_config) {
    if (!config_path || !out_config) return -1;
    memset(out_config, 0, sizeof(fluxwan_config_t));

    char *json = read_file_to_string(config_path);
    if (!json) {
        LOG_ERROR("Failed to read configuration file: %s", config_path);
        return -1;
    }

    /* Parse LAN block */
    const char *lan_pos = strstr(json, "\"lan\"");
    if (lan_pos) {
        char val[64];
        if (extract_json_string(lan_pos, "interface", val, sizeof(val))) {
            strncpy(out_config->lan.name, val, sizeof(out_config->lan.name) - 1);
        } else {
            strncpy(out_config->lan.name, "eth0", sizeof(out_config->lan.name) - 1);
        }

        if (extract_json_string(lan_pos, "ip", val, sizeof(val))) {
            out_config->lan.ip_addr = str_to_ip(val);
        }
        if (extract_json_string(lan_pos, "netmask", val, sizeof(val))) {
            out_config->lan.netmask = str_to_ip(val);
        }
        out_config->lan.dhcp_enabled = extract_json_bool(lan_pos, "dhcp_enabled", true);
        if (extract_json_string(lan_pos, "dhcp_start", val, sizeof(val))) {
            out_config->lan.dhcp_start = str_to_ip(val);
        }
        if (extract_json_string(lan_pos, "dhcp_end", val, sizeof(val))) {
            out_config->lan.dhcp_end = str_to_ip(val);
        }
        out_config->lan.dhcp_lease_time = extract_json_int(lan_pos, "dhcp_lease_time", 43200);
    }

    /* Parse WANS array */
    const char *wans_pos = strstr(json, "\"wans\"");
    if (wans_pos) {
        const char *array_start = strchr(wans_pos, '[');
        const char *array_end = find_matching_bracket(array_start);
        if (array_start && array_end) {
            const char *p = array_start;
            uint32_t idx = 0;
            while (p < array_end && idx < MAX_WANS) {
                const char *obj_start = strchr(p, '{');
                if (!obj_start || obj_start > array_end) break;
                const char *obj_end = strchr(obj_start, '}');
                if (!obj_end || obj_end > array_end) break;

                /* Temporary string slice for object */
                size_t obj_len = obj_end - obj_start + 1;
                char *obj_str = malloc(obj_len + 1);
                if (obj_str) {
                    strncpy(obj_str, obj_start, obj_len);
                    obj_str[obj_len] = '\0';

                    wan_config_t *w = &out_config->wans[idx];
                    w->id = extract_json_int(obj_str, "id", idx + 1);
                    
                    char val[64];
                    if (extract_json_string(obj_str, "name", val, sizeof(val))) {
                        strncpy(w->name, val, sizeof(w->name) - 1);
                    }
                    if (extract_json_string(obj_str, "label", val, sizeof(val))) {
                        strncpy(w->label, val, sizeof(w->label) - 1);
                    }
                    
                    if (extract_json_string(obj_str, "type", val, sizeof(val))) {
                        if (strcmp(val, "static") == 0) w->type = WAN_TYPE_STATIC;
                        else if (strcmp(val, "dhcp") == 0) w->type = WAN_TYPE_DHCP;
                        else if (strcmp(val, "pppoe") == 0) w->type = WAN_TYPE_PPPOE;
                    }

                    if (extract_json_string(obj_str, "ip", val, sizeof(val))) {
                        w->ip_addr = str_to_ip(val);
                    }
                    if (extract_json_string(obj_str, "netmask", val, sizeof(val))) {
                        w->netmask = str_to_ip(val);
                    }
                    if (extract_json_string(obj_str, "gateway", val, sizeof(val))) {
                        w->gateway = str_to_ip(val);
                    }

                    if (extract_json_string(obj_str, "username", val, sizeof(val))) {
                        strncpy(w->ppp_username, val, sizeof(w->ppp_username) - 1);
                    }
                    if (extract_json_string(obj_str, "password", val, sizeof(val))) {
                        strncpy(w->ppp_password, val, sizeof(w->ppp_password) - 1);
                    }

                    uint32_t weight = (uint32_t)extract_json_int(obj_str, "weight", 100);
                    w->config_weight = weight;
                    w->dynamic_weight = weight;
                    w->table_id = (uint32_t)extract_json_int(obj_str, "table_id", 100 + idx + 1);
                    w->mss_clamping = (uint16_t)extract_json_int(obj_str, "mss_clamping", 1452);

                    if (extract_json_string(obj_str, "probe_target", val, sizeof(val))) {
                        strncpy(w->probe_target, val, sizeof(w->probe_target) - 1);
                        w->probe_target_ip = str_to_ip(val);
                    }

                    w->enabled = extract_json_bool(obj_str, "enabled", true);
                    w->state = w->enabled ? WAN_STATE_HEALTHY : WAN_STATE_DOWN;
                    if (!w->enabled) w->dynamic_weight = 0;
                    free(obj_str);
                    idx++;
                }
                p = obj_end + 1;
            }
            out_config->wan_count = idx;
        }
    }

    /* Parse Prober block */
    const char *prober_pos = strstr(json, "\"prober\"");
    if (prober_pos) {
        out_config->prober.interval_ms = extract_json_int(prober_pos, "interval_ms", 500);
        out_config->prober.timeout_ms = extract_json_int(prober_pos, "timeout_ms", 1000);
        out_config->prober.loss_window = extract_json_int(prober_pos, "loss_window", 20);
        out_config->prober.max_acceptable_rtt_ms = extract_json_int(prober_pos, "max_acceptable_rtt_ms", 250);
        out_config->prober.max_acceptable_loss_pct = extract_json_float(prober_pos, "max_acceptable_loss_pct", 20.0f);
    } else {
        out_config->prober.interval_ms = 500;
        out_config->prober.timeout_ms = 1000;
        out_config->prober.loss_window = 20;
        out_config->prober.max_acceptable_rtt_ms = 250;
        out_config->prober.max_acceptable_loss_pct = 20.0f;
    }

    /* Parse Sticky block */
    const char *sticky_pos = strstr(json, "\"sticky\"");
    if (sticky_pos) {
        out_config->sticky.enabled = extract_json_bool(sticky_pos, "enabled", true);
        out_config->sticky.timeout_seconds = extract_json_int(sticky_pos, "timeout_seconds", 300);
    } else {
        out_config->sticky.enabled = true;
        out_config->sticky.timeout_seconds = 300;
    }

    /* Parse Web block */
    const char *web_pos = strstr(json, "\"web\"");
    if (web_pos) {
        char val[64];
        if (extract_json_string(web_pos, "bind_ip", val, sizeof(val))) {
            strncpy(out_config->web.bind_ip, val, sizeof(out_config->web.bind_ip) - 1);
        } else {
            strncpy(out_config->web.bind_ip, "0.0.0.0", sizeof(out_config->web.bind_ip) - 1);
        }
        out_config->web.port = (uint16_t)extract_json_int(web_pos, "port", 8080);
    } else {
        strncpy(out_config->web.bind_ip, "0.0.0.0", sizeof(out_config->web.bind_ip) - 1);
        out_config->web.port = 8080;
    }

    /* Parse Auth block */
    const char *auth_pos = strstr(json, "\"auth\"");
    if (auth_pos) {
        out_config->auth.enabled = extract_json_bool(auth_pos, "enabled", true);
        char val[64];
        if (extract_json_string(auth_pos, "username", val, sizeof(val))) {
            strncpy(out_config->auth.username, val, sizeof(out_config->auth.username) - 1);
        } else {
            strncpy(out_config->auth.username, "admin", sizeof(out_config->auth.username) - 1);
        }
        if (extract_json_string(auth_pos, "password", val, sizeof(val))) {
            strncpy(out_config->auth.password, val, sizeof(out_config->auth.password) - 1);
        } else {
            strncpy(out_config->auth.password, "admin", sizeof(out_config->auth.password) - 1);
        }
        if (extract_json_string(auth_pos, "session_token", val, sizeof(val))) {
            strncpy(out_config->auth.session_token, val, sizeof(out_config->auth.session_token) - 1);
        } else {
            strncpy(out_config->auth.session_token, "flux_sec_token_987", sizeof(out_config->auth.session_token) - 1);
        }
    } else {
        out_config->auth.enabled = true;
        strncpy(out_config->auth.username, "admin", sizeof(out_config->auth.username) - 1);
        strncpy(out_config->auth.password, "admin", sizeof(out_config->auth.password) - 1);
        strncpy(out_config->auth.session_token, "flux_sec_token_987", sizeof(out_config->auth.session_token) - 1);
    }

    free(json);
    LOG_INFO("Configuration loaded successfully from %s (%u WANs configured)", config_path, out_config->wan_count);
    return 0;
}

int config_save(const char *config_path, const fluxwan_config_t *config) {
    if (!config_path || !config) return -1;
    FILE *f = fopen(config_path, "w");
    if (!f) return -1;

    char lan_ip[32], lan_mask[32], dhcp_start[32], dhcp_end[32];
    ip_to_str(config->lan.ip_addr, lan_ip, sizeof(lan_ip));
    ip_to_str(config->lan.netmask, lan_mask, sizeof(lan_mask));
    ip_to_str(config->lan.dhcp_start, dhcp_start, sizeof(dhcp_start));
    ip_to_str(config->lan.dhcp_end, dhcp_end, sizeof(dhcp_end));

    fprintf(f, "{\n");
    fprintf(f, "  \"lan\": {\n");
    fprintf(f, "    \"interface\": \"%s\",\n", config->lan.name);
    fprintf(f, "    \"ip\": \"%s\",\n", lan_ip);
    fprintf(f, "    \"netmask\": \"%s\",\n", lan_mask);
    fprintf(f, "    \"dhcp_enabled\": %s,\n", config->lan.dhcp_enabled ? "true" : "false");
    fprintf(f, "    \"dhcp_start\": \"%s\",\n", dhcp_start);
    fprintf(f, "    \"dhcp_end\": \"%s\",\n", dhcp_end);
    fprintf(f, "    \"dhcp_lease_time\": %u\n", config->lan.dhcp_lease_time);
    fprintf(f, "  },\n");

    fprintf(f, "  \"wans\": [\n");
    for (uint32_t i = 0; i < config->wan_count; i++) {
        const wan_config_t *w = &config->wans[i];
        char ip[32], mask[32], gw[32];
        ip_to_str(w->ip_addr, ip, sizeof(ip));
        ip_to_str(w->netmask, mask, sizeof(mask));
        ip_to_str(w->gateway, gw, sizeof(gw));

        const char *type_str = "static";
        if (w->type == WAN_TYPE_DHCP) type_str = "dhcp";
        else if (w->type == WAN_TYPE_PPPOE) type_str = "pppoe";

        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": %u,\n", w->id);
        fprintf(f, "      \"name\": \"%s\",\n", w->name);
        fprintf(f, "      \"label\": \"%s\",\n", w->label);
        fprintf(f, "      \"type\": \"%s\",\n", type_str);
        fprintf(f, "      \"ip\": \"%s\",\n", ip);
        fprintf(f, "      \"netmask\": \"%s\",\n", mask);
        fprintf(f, "      \"gateway\": \"%s\",\n", gw);
        fprintf(f, "      \"weight\": %u,\n", w->config_weight);
        fprintf(f, "      \"enabled\": %s,\n", w->enabled ? "true" : "false");
        fprintf(f, "      \"probe_target\": \"%s\",\n", w->probe_target);
        fprintf(f, "      \"table_id\": %u\n", w->table_id);
        fprintf(f, "    }%s\n", (i == config->wan_count - 1) ? "" : ",");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"prober\": {\n");
    fprintf(f, "    \"interval_ms\": %u,\n", config->prober.interval_ms);
    fprintf(f, "    \"timeout_ms\": %u,\n", config->prober.timeout_ms);
    fprintf(f, "    \"loss_window\": %u,\n", config->prober.loss_window);
    fprintf(f, "    \"max_acceptable_rtt_ms\": %u,\n", config->prober.max_acceptable_rtt_ms);
    fprintf(f, "    \"max_acceptable_loss_pct\": %.1f\n", config->prober.max_acceptable_loss_pct);
    fprintf(f, "  },\n");

    fprintf(f, "  \"sticky\": {\n");
    fprintf(f, "    \"enabled\": %s,\n", config->sticky.enabled ? "true" : "false");
    fprintf(f, "    \"timeout_seconds\": %u\n", config->sticky.timeout_seconds);
    fprintf(f, "  },\n");

    fprintf(f, "  \"web\": {\n");
    fprintf(f, "    \"bind_ip\": \"%s\",\n", config->web.bind_ip);
    fprintf(f, "    \"port\": %u\n", config->web.port);
    fprintf(f, "  },\n");

    fprintf(f, "  \"auth\": {\n");
    fprintf(f, "    \"enabled\": %s,\n", config->auth.enabled ? "true" : "false");
    fprintf(f, "    \"username\": \"%s\",\n", config->auth.username);
    fprintf(f, "    \"password\": \"%s\",\n", config->auth.password);
    fprintf(f, "    \"session_token\": \"%s\"\n", config->auth.session_token);
    fprintf(f, "  }\n");
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

void config_print(const fluxwan_config_t *config) {
    if (!config) return;
    char ip[32], mask[32];
    ip_to_str(config->lan.ip_addr, ip, sizeof(ip));
    ip_to_str(config->lan.netmask, mask, sizeof(mask));

    printf("================ FLUXWAN CONFIGURATION ================\n");
    printf("LAN Interface : %s (%s / %s)\n", config->lan.name, ip, mask);
    printf("Multi-WAN Uplinks (%u active):\n", config->wan_count);
    for (uint32_t i = 0; i < config->wan_count; i++) {
        const wan_config_t *w = &config->wans[i];
        ip_to_str(w->ip_addr, ip, sizeof(ip));
        printf("  [%u] %s (%s) - Type: %d, IP: %s, Weight: %u, Table: %u, Probe: %s\n",
               w->id, w->name, w->label, w->type, ip, w->config_weight, w->table_id, w->probe_target);
    }
    printf("Prober Interval : %ums | Timeout: %ums | Max RTT: %ums\n",
             config->prober.interval_ms, config->prober.timeout_ms, config->prober.max_acceptable_rtt_ms);
    printf("Sticky Sessions : %s (Timeout: %us)\n", config->sticky.enabled ? "ENABLED" : "DISABLED", config->sticky.timeout_seconds);
    printf("Web Management  : http://%s:%u (Auth: %s)\n", config->web.bind_ip, config->web.port, config->auth.enabled ? "ENABLED" : "DISABLED");
    printf("=======================================================\n");
}

bool config_validate_wan_attachments(const fluxwan_config_t *config, char *err_msg, size_t err_size) {
    if (!config) return false;

    /* 1. LAN interface must not be used as any WAN interface */
    for (uint32_t i = 0; i < config->wan_count; i++) {
        if (config->wans[i].name[0] && strcmp(config->wans[i].name, config->lan.name) == 0) {
            if (err_msg && err_size > 0) {
                snprintf(err_msg, err_size,
                         "Interface '%s' is dedicated to LAN Gateway and cannot be used for WAN '%s'.",
                         config->lan.name, config->wans[i].label);
            }
            return false;
        }
    }

    /* 2. Check WAN physical port allocations:
     *    - DHCP: 1 max per physical port (Exclusive L3 broadcast)
     *    - Static: 1 max per physical port (Exclusive L3 subnet/gateway)
     *    - DHCP + Static on same port: NOT allowed
     *    - PPPoE: N sessions allowed on the same physical port (PPP encapsulation)
     *    - DHCP/Static + PPPoE on same port: NOT allowed (avoids untagged IP collisions)
     */
    for (uint32_t i = 0; i < config->wan_count; i++) {
        const wan_config_t *w1 = &config->wans[i];
        if (!w1->name[0]) continue;

        int dhcp_count = 0;
        int static_count = 0;
        int pppoe_count = 0;

        for (uint32_t j = 0; j < config->wan_count; j++) {
            const wan_config_t *w2 = &config->wans[j];
            if (strcmp(w1->name, w2->name) == 0) {
                if (w2->type == WAN_TYPE_DHCP) dhcp_count++;
                else if (w2->type == WAN_TYPE_STATIC) static_count++;
                else if (w2->type == WAN_TYPE_PPPOE) pppoe_count++;
            }
        }

        if (dhcp_count > 1) {
            if (err_msg && err_size > 0) {
                snprintf(err_msg, err_size,
                         "Physical interface '%s' has %d DHCP clients configured. A physical port can only host 1 DHCP client.",
                         w1->name, dhcp_count);
            }
            return false;
        }

        if (static_count > 1) {
            if (err_msg && err_size > 0) {
                snprintf(err_msg, err_size,
                         "Physical interface '%s' has multiple Static IP WANs configured. A physical port requires an exclusive IP configuration.",
                         w1->name);
            }
            return false;
        }

        if ((dhcp_count > 0 && static_count > 0) ||
            ((dhcp_count > 0 || static_count > 0) && pppoe_count > 0)) {
            if (err_msg && err_size > 0) {
                snprintf(err_msg, err_size,
                         "Physical interface '%s' mixes exclusive IP modes (DHCP/Static) with other WANs. DHCP and Static require dedicated 1:1 physical ports.",
                         w1->name);
            }
            return false;
        }
    }

    return true;
}
