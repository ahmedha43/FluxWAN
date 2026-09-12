/*
 * FluxWAN - High-Performance Multi-WAN Load Balancing OS
 *
 * Copyright (C) 2026 Ahmed Al-Dulaimi (أحمد الدليمي). All rights reserved.
 * Author: Ahmed Al-Dulaimi (أحمد الدليمي)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

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

static inline void safe_str_copy(char *dst, const char *src, size_t max_len) {
    if (!dst || max_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t slen = strlen(src);
    if (slen >= max_len) slen = max_len - 1;
    memcpy(dst, src, slen);
    dst[slen] = '\0';
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

static const char *find_matching_brace(const char *start) {
    if (!start || *start != '{') return NULL;
    int depth = 0;
    bool in_str = false;
    bool escape = false;
    for (const char *p = start; *p; p++) {
        if (escape) {
            escape = false;
            continue;
        }
        if (*p == '\\') {
            escape = true;
            continue;
        }
        if (*p == '"') {
            in_str = !in_str;
            continue;
        }
        if (!in_str) {
            if (*p == '{') depth++;
            else if (*p == '}') {
                depth--;
                if (depth == 0) return p;
            }
        }
    }
    return NULL;
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

int config_load(const char *config_path, fluxwan_config_t *out_config) {
    if (!out_config) return -1;

    char local_path[MAX_PATH_LEN] = {0};
    if (config_path && config_path[0]) {
        safe_str_copy(local_path, config_path, sizeof(local_path));
    } else if (out_config->config_file_path[0]) {
        safe_str_copy(local_path, out_config->config_file_path, sizeof(local_path));
    } else {
        safe_str_copy(local_path, "/opt/fluxwan/config/fluxwan.json", sizeof(local_path));
    }

    char *json = read_file_to_string(local_path);
    if (!json) {
        LOG_ERROR("Failed to read configuration file: %s", local_path);
        return -1;
    }

    memset(out_config, 0, sizeof(fluxwan_config_t));
    safe_str_copy(out_config->config_file_path, local_path, sizeof(out_config->config_file_path));

    /* Parse LAN block */
    const char *lan_pos = strstr(json, "\"lan\"");
    if (lan_pos) {
        char val[64];
        if (extract_json_string(lan_pos, "interface", val, sizeof(val)) && val[0] != '\0') {
            safe_str_copy(out_config->lan.name, val, sizeof(out_config->lan.name));
        } else {
            safe_str_copy(out_config->lan.name, "eth0", sizeof(out_config->lan.name));
        }

        if (extract_json_string(lan_pos, "ip", val, sizeof(val)) && val[0] != '\0' && strcmp(val, "0.0.0.0") != 0) {
            out_config->lan.ip_addr = str_to_ip(val);
        } else {
            out_config->lan.ip_addr = str_to_ip("192.168.90.1");
        }

        if (extract_json_string(lan_pos, "netmask", val, sizeof(val)) && val[0] != '\0' && strcmp(val, "0.0.0.0") != 0) {
            out_config->lan.netmask = str_to_ip(val);
        } else {
            out_config->lan.netmask = str_to_ip("255.255.255.0");
        }
        out_config->lan.dhcp_enabled = extract_json_bool(lan_pos, "dhcp_enabled", true);
        if (extract_json_string(lan_pos, "dhcp_start", val, sizeof(val)) && val[0] != '\0' && strcmp(val, "0.0.0.0") != 0) {
            out_config->lan.dhcp_start = str_to_ip(val);
        } else {
            out_config->lan.dhcp_start = str_to_ip("192.168.90.100");
        }
        if (extract_json_string(lan_pos, "dhcp_end", val, sizeof(val)) && val[0] != '\0' && strcmp(val, "0.0.0.0") != 0) {
            out_config->lan.dhcp_end = str_to_ip(val);
        } else {
            out_config->lan.dhcp_end = str_to_ip("192.168.90.200");
        }
        out_config->lan.dhcp_lease_time = extract_json_int(lan_pos, "dhcp_lease_time", 43200);

        /* Parse LAN Policy Routes */
        const char *policy_pos = strstr(lan_pos, "\"policy_routes\"");
        if (policy_pos) {
            const char *array_start = strchr(policy_pos, '[');
            const char *array_end = find_matching_bracket(array_start);
            if (array_start && array_end) {
                const char *p = array_start;
                uint32_t pr_idx = 0;
                while (p < array_end && pr_idx < MAX_POLICY_ROUTES) {
                    const char *obj_start = strchr(p, '{');
                    if (!obj_start || obj_start > array_end) break;
                    const char *obj_end = strchr(obj_start, '}');
                    if (!obj_end || obj_end > array_end) break;

                    size_t obj_len = obj_end - obj_start + 1;
                    char *obj_str = malloc(obj_len + 1);
                    if (obj_str) {
                        strncpy(obj_str, obj_start, obj_len);
                        obj_str[obj_len] = '\0';

                        policy_route_t *pr = &out_config->lan.policy_routes[pr_idx];
                        pr->enabled = extract_json_bool(obj_str, "enabled", true);

                        char pval[64];
                        if (extract_json_string(obj_str, "subnet", pval, sizeof(pval))) {
                            safe_str_copy(pr->subnet_str, pval, sizeof(pr->subnet_str));
                            parse_cidr_subnet(pval, &pr->subnet_ip, &pr->netmask, &pr->prefix_len);
                        }
                        if (extract_json_string(obj_str, "gateway_ip", pval, sizeof(pval))) {
                            safe_str_copy(pr->gateway_ip_str, pval, sizeof(pr->gateway_ip_str));
                            pr->gateway_ip = str_to_ip(pval);
                        }
                        if (extract_json_string(obj_str, "target_group", pval, sizeof(pval))) {
                            safe_str_copy(pr->target_group, pval, sizeof(pr->target_group));
                        }
                        if (extract_json_string(obj_str, "description", pval, sizeof(pval))) {
                            safe_str_copy(pr->description, pval, sizeof(pr->description));
                        }

                        free(obj_str);
                        pr_idx++;
                    }
                    p = obj_end + 1;
                }
                out_config->lan.policy_route_count = pr_idx;
            }
        }

        /* Parse LAN Static DHCP Leases */
        const char *sl_pos = strstr(lan_pos, "\"static_leases\"");
        if (sl_pos) {
            const char *array_start = strchr(sl_pos, '[');
            const char *array_end = find_matching_bracket(array_start);
            if (array_start && array_end) {
                const char *p = array_start;
                uint32_t sl_idx = 0;
                while (p < array_end && sl_idx < MAX_STATIC_LEASES) {
                    const char *obj_start = strchr(p, '{');
                    if (!obj_start || obj_start > array_end) break;
                    const char *obj_end = strchr(obj_start, '}');
                    if (!obj_end || obj_end > array_end) break;

                    size_t obj_len = obj_end - obj_start + 1;
                    char *obj_str = malloc(obj_len + 1);
                    if (obj_str) {
                        strncpy(obj_str, obj_start, obj_len);
                        obj_str[obj_len] = '\0';

                        static_lease_t *sl = &out_config->lan.static_leases[sl_idx];
                        char mval[64] = {0}, ipval[64] = {0}, hval[64] = {0};
                        extract_json_string(obj_str, "mac", mval, sizeof(mval));
                        extract_json_string(obj_str, "ip", ipval, sizeof(ipval));
                        extract_json_string(obj_str, "hostname", hval, sizeof(hval));
                        safe_str_copy(sl->mac_str, mval, sizeof(sl->mac_str));
                        parse_mac_str(mval, sl->mac_addr);
                        sl->ip_addr = str_to_ip(ipval);
                        safe_str_copy(sl->hostname, hval, sizeof(sl->hostname));
                        sl->enabled = extract_json_bool(obj_str, "enabled", true);

                        free(obj_str);
                        sl_idx++;
                    }
                    p = obj_end + 1;
                }
                out_config->lan.static_lease_count = sl_idx;
            }
        }

        /* Parse LAN Per-IP Rate Limits */
        const char *rl_pos = strstr(lan_pos, "\"rate_limits\"");
        if (rl_pos) {
            const char *array_start = strchr(rl_pos, '[');
            const char *array_end = find_matching_bracket(array_start);
            if (array_start && array_end) {
                const char *p = array_start;
                uint32_t rl_idx = 0;
                while (p < array_end && rl_idx < MAX_RATE_LIMITS) {
                    const char *obj_start = strchr(p, '{');
                    if (!obj_start || obj_start > array_end) break;
                    const char *obj_end = strchr(obj_start, '}');
                    if (!obj_end || obj_end > array_end) break;

                    size_t obj_len = obj_end - obj_start + 1;
                    char *obj_str = malloc(obj_len + 1);
                    if (obj_str) {
                        strncpy(obj_str, obj_start, obj_len);
                        obj_str[obj_len] = '\0';

                        rate_limit_t *rl = &out_config->lan.rate_limits[rl_idx];
                        char ipval[64] = {0}, dval[64] = {0};
                        extract_json_string(obj_str, "ip", ipval, sizeof(ipval));
                        extract_json_string(obj_str, "description", dval, sizeof(dval));
                        safe_str_copy(rl->ip_str, ipval, sizeof(rl->ip_str));
                        rl->ip_addr = str_to_ip(ipval);
                        safe_str_copy(rl->description, dval, sizeof(rl->description));
                        rl->max_down_mbps = (uint32_t)extract_json_int(obj_str, "max_down_mbps", 50);
                        rl->max_up_mbps = (uint32_t)extract_json_int(obj_str, "max_up_mbps", 10);
                        rl->enabled = extract_json_bool(obj_str, "enabled", true);

                        free(obj_str);
                        rl_idx++;
                    }
                    p = obj_end + 1;
                }
                out_config->lan.rate_limit_count = rl_idx;
            }
        }

        /* Parse Smart Queue Management (QoS / CAKE) */
        const char *qos_pos = strstr(lan_pos, "\"qos\"");
        if (qos_pos) {
            out_config->lan.qos.enabled = extract_json_bool(qos_pos, "enabled", false);
            char algo[32] = {0};
            if (extract_json_string(qos_pos, "algorithm", algo, sizeof(algo)) && algo[0]) {
                safe_str_copy(out_config->lan.qos.algorithm, algo, sizeof(out_config->lan.qos.algorithm));
            } else {
                safe_str_copy(out_config->lan.qos.algorithm, "cake", sizeof(out_config->lan.qos.algorithm));
            }
            out_config->lan.qos.bandwidth_down_mbps = (uint32_t)extract_json_int(qos_pos, "bandwidth_down_mbps", 100);
            out_config->lan.qos.bandwidth_up_mbps = (uint32_t)extract_json_int(qos_pos, "bandwidth_up_mbps", 20);
            out_config->lan.qos.diffserv4 = extract_json_bool(qos_pos, "diffserv4", true);
        } else {
            safe_str_copy(out_config->lan.qos.algorithm, "cake", sizeof(out_config->lan.qos.algorithm));
            out_config->lan.qos.bandwidth_down_mbps = 100;
            out_config->lan.qos.bandwidth_up_mbps = 20;
            out_config->lan.qos.diffserv4 = true;
        }

        /* Parse DNS Ad-blocking & Privacy */
        const char *dns_pos = strstr(lan_pos, "\"dns\"");
        if (dns_pos) {
            out_config->lan.dns.adblock_enabled = extract_json_bool(dns_pos, "adblock_enabled", false);
            out_config->lan.dns.fast_dns_enabled = extract_json_bool(dns_pos, "fast_dns_enabled", true);
            char dns1[32] = {0}, dns2[32] = {0};
            extract_json_string(dns_pos, "primary_dns", dns1, sizeof(dns1));
            extract_json_string(dns_pos, "secondary_dns", dns2, sizeof(dns2));
            safe_str_copy(out_config->lan.dns.primary_dns, dns1[0] ? dns1 : "1.1.1.1", sizeof(out_config->lan.dns.primary_dns));
            safe_str_copy(out_config->lan.dns.secondary_dns, dns2[0] ? dns2 : "8.8.8.8", sizeof(out_config->lan.dns.secondary_dns));
        } else {
            out_config->lan.dns.adblock_enabled = false;
            out_config->lan.dns.fast_dns_enabled = true;
            safe_str_copy(out_config->lan.dns.primary_dns, "1.1.1.1", sizeof(out_config->lan.dns.primary_dns));
            safe_str_copy(out_config->lan.dns.secondary_dns, "8.8.8.8", sizeof(out_config->lan.dns.secondary_dns));
        }
    }

    /* Parse WANS array (find top-level array containing objects) */
    const char *wans_pos = json;
    const char *array_start = NULL;
    const char *array_end = NULL;
    while ((wans_pos = strstr(wans_pos, "\"wans\"")) != NULL) {
        array_start = strchr(wans_pos, '[');
        array_end = find_matching_bracket(array_start);
        if (array_start && array_end) {
            const char *obj_check = strchr(array_start, '{');
            if (obj_check && obj_check < array_end) {
                break; /* Found top-level wans array of objects */
            }
        }
        wans_pos += 6;
    }
    if (wans_pos && array_start && array_end) {
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
                        safe_str_copy(w->name, val, sizeof(w->name));
                    }
                    if (extract_json_string(obj_str, "label", val, sizeof(val))) {
                        safe_str_copy(w->label, val, sizeof(w->label));
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
                        safe_str_copy(w->ppp_username, val, sizeof(w->ppp_username));
                    }
                    if (extract_json_string(obj_str, "password", val, sizeof(val))) {
                        safe_str_copy(w->ppp_password, val, sizeof(w->ppp_password));
                    }

                    uint32_t weight = (uint32_t)extract_json_int(obj_str, "weight", 100);
                    w->config_weight = weight;
                    w->dynamic_weight = weight;
                    w->bandwidth_down_mbps = (uint32_t)extract_json_int(obj_str, "bandwidth_down_mbps", 100);
                    w->bandwidth_up_mbps = (uint32_t)extract_json_int(obj_str, "bandwidth_up_mbps", 20);
                    w->table_id = (uint32_t)extract_json_int(obj_str, "table_id", 100 + idx + 1);
                    w->mss_clamping = (uint16_t)extract_json_int(obj_str, "mss_clamping", 1452);
                    w->mtu = (uint32_t)extract_json_int(obj_str, "mtu", 1500);
                    w->link_mtu = (uint16_t)w->mtu;

                    if (extract_json_string(obj_str, "probe_target", val, sizeof(val))) {
                        safe_str_copy(w->probe_target, val, sizeof(w->probe_target));
                        w->probe_target_ip = str_to_ip(val);
                    }

                    w->enabled = extract_json_bool(obj_str, "enabled", true);
                    char state_val[32] = {0};
                    if (extract_json_string(obj_str, "state", state_val, sizeof(state_val))) {
                        if (strcmp(state_val, "DRAINING") == 0) w->state = WAN_STATE_DRAINING;
                        else if (strcmp(state_val, "DOWN") == 0) w->state = WAN_STATE_DOWN;
                        else if (strcmp(state_val, "DEGRADED") == 0) w->state = WAN_STATE_DEGRADED;
                        else w->state = WAN_STATE_HEALTHY;
                    } else {
                        w->state = w->enabled ? WAN_STATE_HEALTHY : WAN_STATE_DOWN;
                    }
                    if (!w->enabled) w->dynamic_weight = 0;
                    else if (w->state == WAN_STATE_DRAINING) w->dynamic_weight = 0;
                    free(obj_str);
                    idx++;
                }
                p = obj_end + 1;
            }
            out_config->wan_count = idx;
    }

    /* Parse Prober block */
    const char *prober_pos = strstr(json, "\"prober\"");
    if (prober_pos) {
        out_config->prober.interval_ms = extract_json_int(prober_pos, "interval_ms", 500);
        out_config->prober.timeout_ms = extract_json_int(prober_pos, "timeout_ms", 1000);
        out_config->prober.loss_window = extract_json_int(prober_pos, "loss_window", 20);
        out_config->prober.max_acceptable_rtt_ms = extract_json_int(prober_pos, "max_acceptable_rtt_ms", 250);
        out_config->prober.max_acceptable_loss_pct = extract_json_float(prober_pos, "max_acceptable_loss_pct", 20.0f);
        out_config->prober.dynamic_latency_steering = extract_json_bool(prober_pos, "dynamic_latency_steering", true);
    } else {
        out_config->prober.interval_ms = 500;
        out_config->prober.timeout_ms = 1000;
        out_config->prober.loss_window = 20;
        out_config->prober.max_acceptable_rtt_ms = 250;
        out_config->prober.max_acceptable_loss_pct = 20.0f;
        out_config->prober.dynamic_latency_steering = true;
    }

    /* Parse Sticky block */
    const char *sticky_pos = strstr(json, "\"sticky\"");
    if (sticky_pos) {
        out_config->sticky.enabled = extract_json_bool(sticky_pos, "enabled", true);
        out_config->sticky.timeout_seconds = extract_json_int(sticky_pos, "timeout_seconds", 300);
        out_config->sticky.strict_banking_enabled = extract_json_bool(sticky_pos, "strict_banking_enabled", true);
    } else {
        out_config->sticky.enabled = true;
        out_config->sticky.timeout_seconds = 300;
        out_config->sticky.strict_banking_enabled = true;
    }

    /* Parse Web block */
    const char *web_pos = strstr(json, "\"web\"");
    if (web_pos) {
        char val[64];
        if (extract_json_string(web_pos, "bind_ip", val, sizeof(val))) {
            safe_str_copy(out_config->web.bind_ip, val, sizeof(out_config->web.bind_ip));
        } else {
            safe_str_copy(out_config->web.bind_ip, "0.0.0.0", sizeof(out_config->web.bind_ip));
        }
        out_config->web.port = (uint16_t)extract_json_int(web_pos, "port", 8080);
    } else {
        safe_str_copy(out_config->web.bind_ip, "0.0.0.0", sizeof(out_config->web.bind_ip));
        out_config->web.port = 8080;
    }

    /* Parse Auth block */
    const char *auth_pos = strstr(json, "\"auth\"");
    if (auth_pos) {
        out_config->auth.enabled = extract_json_bool(auth_pos, "enabled", true);
        char val[64];
        if (extract_json_string(auth_pos, "username", val, sizeof(val))) {
            safe_str_copy(out_config->auth.username, val, sizeof(out_config->auth.username));
        } else {
            safe_str_copy(out_config->auth.username, "admin", sizeof(out_config->auth.username));
        }
        if (extract_json_string(auth_pos, "password", val, sizeof(val))) {
            safe_str_copy(out_config->auth.password, val, sizeof(out_config->auth.password));
        } else {
            safe_str_copy(out_config->auth.password, "admin", sizeof(out_config->auth.password));
        }
        if (extract_json_string(auth_pos, "session_token", val, sizeof(val))) {
            safe_str_copy(out_config->auth.session_token, val, sizeof(out_config->auth.session_token));
        } else {
            safe_str_copy(out_config->auth.session_token, "flux_sec_token_987", sizeof(out_config->auth.session_token));
        }
    } else {
        out_config->auth.enabled = true;
        safe_str_copy(out_config->auth.username, "admin", sizeof(out_config->auth.username));
        safe_str_copy(out_config->auth.password, "admin", sizeof(out_config->auth.password));
        safe_str_copy(out_config->auth.session_token, "flux_sec_token_987", sizeof(out_config->auth.session_token));
    }

    /* Parse NAT46 block */
    const char *nat46_pos = strstr(json, "\"nat46\"");
    if (nat46_pos) {
        out_config->nat46.enabled = extract_json_bool(nat46_pos, "enabled", true);
        char val[64];
        if (extract_json_string(nat46_pos, "synthetic_prefix", val, sizeof(val))) {
            safe_str_copy(out_config->nat46.synthetic_prefix, val, sizeof(out_config->nat46.synthetic_prefix));
        } else {
            safe_str_copy(out_config->nat46.synthetic_prefix, "198.18.0.0/15", sizeof(out_config->nat46.synthetic_prefix));
        }
        if (extract_json_string(nat46_pos, "upstream_dns", val, sizeof(val))) {
            safe_str_copy(out_config->nat46.upstream_dns, val, sizeof(out_config->nat46.upstream_dns));
        } else {
            safe_str_copy(out_config->nat46.upstream_dns, "1.1.1.1", sizeof(out_config->nat46.upstream_dns));
        }
        if (extract_json_string(nat46_pos, "starlink_wan_name", val, sizeof(val))) {
            safe_str_copy(out_config->nat46.starlink_wan_name, val, sizeof(out_config->nat46.starlink_wan_name));
        } else {
            safe_str_copy(out_config->nat46.starlink_wan_name, "veth_wan2", sizeof(out_config->nat46.starlink_wan_name));
        }
    } else {
        out_config->nat46.enabled = true;
        safe_str_copy(out_config->nat46.synthetic_prefix, "198.18.0.0/15", sizeof(out_config->nat46.synthetic_prefix));
        safe_str_copy(out_config->nat46.upstream_dns, "1.1.1.1", sizeof(out_config->nat46.upstream_dns));
        safe_str_copy(out_config->nat46.starlink_wan_name, "veth_wan2", sizeof(out_config->nat46.starlink_wan_name));
    }

    /* Parse Application-Based Smart Steering block */
    const char *as_pos = strstr(json, "\"app_steering\"");
    if (as_pos) {
        out_config->app_steering.gaming_steering_enabled = extract_json_bool(as_pos, "gaming_steering_enabled", true);
        out_config->app_steering.voip_steering_enabled = extract_json_bool(as_pos, "voip_steering_enabled", true);
        out_config->app_steering.bulk_balancing_enabled = extract_json_bool(as_pos, "bulk_balancing_enabled", true);
        out_config->app_steering.primary_gaming_wan_id = (uint32_t)extract_json_int(as_pos, "primary_gaming_wan_id", 0);
        out_config->app_steering.primary_voip_wan_id = (uint32_t)extract_json_int(as_pos, "primary_voip_wan_id", 0);
    } else {
        out_config->app_steering.gaming_steering_enabled = true;
        out_config->app_steering.voip_steering_enabled = true;
        out_config->app_steering.bulk_balancing_enabled = true;
    }

    /* Parse Telegram Bot Alerts block */
    const char *tg_pos = strstr(json, "\"telegram\"");
    if (tg_pos) {
        out_config->telegram.enabled = extract_json_bool(tg_pos, "enabled", false);
        extract_json_string(tg_pos, "bot_token", out_config->telegram.bot_token, sizeof(out_config->telegram.bot_token));
        extract_json_string(tg_pos, "chat_id", out_config->telegram.chat_id, sizeof(out_config->telegram.chat_id));
        out_config->telegram.notify_on_failover = extract_json_bool(tg_pos, "notify_on_failover", true);
        out_config->telegram.notify_on_recovery = extract_json_bool(tg_pos, "notify_on_recovery", true);
    } else {
        out_config->telegram.notify_on_failover = true;
        out_config->telegram.notify_on_recovery = true;
    }

    /* Parse Groups array */
    const char *groups_pos = strstr(json, "\"groups\"");
    if (groups_pos) {
        const char *array_start = strchr(groups_pos, '[');
        const char *array_end = find_matching_bracket(array_start);
        if (array_start && array_end) {
            const char *p = array_start;
            uint32_t grp_idx = 0;
            while (p < array_end && grp_idx < MAX_WAN_GROUPS) {
                const char *obj_start = strchr(p, '{');
                if (!obj_start || obj_start > array_end) break;
                const char *obj_end = strchr(obj_start, '}');
                if (!obj_end || obj_end > array_end) break;

                size_t obj_len = obj_end - obj_start + 1;
                char *obj_str = malloc(obj_len + 1);
                if (obj_str) {
                    strncpy(obj_str, obj_start, obj_len);
                    obj_str[obj_len] = '\0';

                    wan_group_t *g = &out_config->groups[grp_idx];
                    g->id = (uint32_t)extract_json_int(obj_str, "id", grp_idx + 1);
                    g->enabled = extract_json_bool(obj_str, "enabled", true);

                    char gval[64];
                    if (extract_json_string(obj_str, "name", gval, sizeof(gval))) {
                        safe_str_copy(g->name, gval, sizeof(g->name));
                    } else {
                        snprintf(g->name, sizeof(g->name), "Group_%u", g->id);
                    }
                    if (extract_json_string(obj_str, "description", gval, sizeof(gval))) {
                        safe_str_copy(g->description, gval, sizeof(g->description));
                    }

                    /* Parse WANs list in group: "wans": ["WAN1_Earthlink", "WAN2_Zain"] */
                    const char *gwans_pos = strstr(obj_str, "\"wans\"");
                    if (gwans_pos) {
                        const char *gw_start = strchr(gwans_pos, '[');
                        const char *gw_end = strchr(gwans_pos, ']');
                        if (gw_start && gw_end && gw_end > gw_start) {
                            const char *gp = gw_start;
                            uint32_t w_idx = 0;
                            while (gp < gw_end && w_idx < MAX_GROUP_MEMBERS) {
                                const char *q1 = strchr(gp, '"');
                                if (!q1 || q1 >= gw_end) break;
                                const char *q2 = strchr(q1 + 1, '"');
                                if (!q2 || q2 > gw_end) break;
                                size_t wlen = q2 - (q1 + 1);
                                if (wlen >= sizeof(g->wan_names[w_idx])) wlen = sizeof(g->wan_names[w_idx]) - 1;
                                strncpy(g->wan_names[w_idx], q1 + 1, wlen);
                                g->wan_names[w_idx][wlen] = '\0';
                                w_idx++;
                                gp = q2 + 1;
                            }
                            g->wan_count = w_idx;
                        }
                    }

                    free(obj_str);
                    grp_idx++;
                }
                p = obj_end + 1;
            }
            out_config->group_count = grp_idx;
        }
    }

    /* Resolve Group IDs and WAN Member Indices */
    for (uint32_t i = 0; i < out_config->group_count; i++) {
        wan_group_t *g = &out_config->groups[i];
        uint32_t active_members = 0;
        for (uint32_t m = 0; m < g->wan_count; m++) {
            for (uint32_t w = 0; w < out_config->wan_count; w++) {
                if (strcmp(g->wan_names[m], out_config->wans[w].label) == 0 ||
                    strcmp(g->wan_names[m], out_config->wans[w].name) == 0) {
                    g->wan_member_indices[active_members++] = w;
                    break;
                }
            }
        }
        g->active_wan_count = active_members;
    }

    /* Resolve Policy Route Target Group IDs */
    for (uint32_t p = 0; p < out_config->lan.policy_route_count; p++) {
        policy_route_t *pr = &out_config->lan.policy_routes[p];
        pr->target_group_id = 0; /* Default: Group 0 (All WANs) */
        for (uint32_t g = 0; g < out_config->group_count; g++) {
            if (strcmp(pr->target_group, out_config->groups[g].name) == 0) {
                pr->target_group_id = out_config->groups[g].id;
                break;
            }
        }
    }

    free(json);
    LOG_INFO("Configuration loaded successfully from %s (%u WANs, %u Groups, %u Policy Routes)",
             config_path, out_config->wan_count, out_config->group_count, out_config->lan.policy_route_count);
    return 0;
}

int config_save(const char *config_path, const fluxwan_config_t *config) {
    if (!config) return -1;
    const char *path = config_path;
    if (!path || !path[0]) {
        if (config->config_file_path[0]) path = config->config_file_path;
        else path = "/opt/fluxwan/config/fluxwan.json";
    }
    FILE *f = fopen(path, "w");
    if (!f && strcmp(path, "/opt/fluxwan/config/fluxwan.json") != 0) {
        f = fopen("/opt/fluxwan/config/fluxwan.json", "w");
        if (f) path = "/opt/fluxwan/config/fluxwan.json";
    }
    if (!f && strcmp(path, "config/fluxwan.json") != 0) {
        f = fopen("config/fluxwan.json", "w");
        if (f) path = "config/fluxwan.json";
    }
    if (!f) {
        LOG_ERROR("Failed to open config file for saving: %s", path ? path : "(null)");
        return -1;
    }

    char lan_name[MAX_IFNAME_LEN];
    safe_str_copy(lan_name, config->lan.name[0] ? config->lan.name : "eth0", sizeof(lan_name));

    uint32_t lan_ip_bin = config->lan.ip_addr ? config->lan.ip_addr : str_to_ip("192.168.90.1");
    uint32_t lan_mask_bin = config->lan.netmask ? config->lan.netmask : str_to_ip("255.255.255.0");
    uint32_t dhcp_start_bin = config->lan.dhcp_start ? config->lan.dhcp_start : str_to_ip("192.168.90.100");
    uint32_t dhcp_end_bin = config->lan.dhcp_end ? config->lan.dhcp_end : str_to_ip("192.168.90.200");

    char lan_ip[32], lan_mask[32], dhcp_start[32], dhcp_end[32];
    ip_to_str(lan_ip_bin, lan_ip, sizeof(lan_ip));
    ip_to_str(lan_mask_bin, lan_mask, sizeof(lan_mask));
    ip_to_str(dhcp_start_bin, dhcp_start, sizeof(dhcp_start));
    ip_to_str(dhcp_end_bin, dhcp_end, sizeof(dhcp_end));

    fprintf(f, "{\n");
    fprintf(f, "  \"lan\": {\n");
    fprintf(f, "    \"interface\": \"%s\",\n", lan_name);
    fprintf(f, "    \"ip\": \"%s\",\n", lan_ip);
    fprintf(f, "    \"netmask\": \"%s\",\n", lan_mask);
    fprintf(f, "    \"dhcp_enabled\": %s,\n", config->lan.dhcp_enabled ? "true" : "false");
    fprintf(f, "    \"dhcp_start\": \"%s\",\n", dhcp_start);
    fprintf(f, "    \"dhcp_end\": \"%s\",\n", dhcp_end);
    fprintf(f, "    \"dhcp_lease_time\": %u", config->lan.dhcp_lease_time);

    if (config->lan.policy_route_count > 0) {
        fprintf(f, ",\n    \"policy_routes\": [\n");
        for (uint32_t p = 0; p < config->lan.policy_route_count; p++) {
            const policy_route_t *pr = &config->lan.policy_routes[p];
            fprintf(f, "      {\n");
            fprintf(f, "        \"subnet\": \"%s\",\n", pr->subnet_str);
            fprintf(f, "        \"gateway_ip\": \"%s\",\n", pr->gateway_ip_str);
            fprintf(f, "        \"target_group\": \"%s\",\n", pr->target_group);
            fprintf(f, "        \"description\": \"%s\",\n", pr->description);
            fprintf(f, "        \"enabled\": %s\n", pr->enabled ? "true" : "false");
            fprintf(f, "      }%s\n", (p == config->lan.policy_route_count - 1) ? "" : ",");
        }
        fprintf(f, "    ]");
    }

    if (config->lan.static_lease_count > 0) {
        fprintf(f, ",\n    \"static_leases\": [\n");
        for (uint32_t s = 0; s < config->lan.static_lease_count; s++) {
            const static_lease_t *sl = &config->lan.static_leases[s];
            char slip[32];
            ip_to_str(sl->ip_addr, slip, sizeof(slip));
            fprintf(f, "      {\n");
            fprintf(f, "        \"mac\": \"%s\",\n", sl->mac_str);
            fprintf(f, "        \"ip\": \"%s\",\n", slip);
            fprintf(f, "        \"hostname\": \"%s\",\n", sl->hostname);
            fprintf(f, "        \"enabled\": %s\n", sl->enabled ? "true" : "false");
            fprintf(f, "      }%s\n", (s == config->lan.static_lease_count - 1) ? "" : ",");
        }
        fprintf(f, "    ]");
    }

    if (config->lan.rate_limit_count > 0) {
        fprintf(f, ",\n    \"rate_limits\": [\n");
        for (uint32_t r = 0; r < config->lan.rate_limit_count; r++) {
            const rate_limit_t *rl = &config->lan.rate_limits[r];
            fprintf(f, "      {\n");
            fprintf(f, "        \"ip\": \"%s\",\n", rl->ip_str);
            fprintf(f, "        \"max_down_mbps\": %u,\n", rl->max_down_mbps);
            fprintf(f, "        \"max_up_mbps\": %u,\n", rl->max_up_mbps);
            fprintf(f, "        \"description\": \"%s\",\n", rl->description);
            fprintf(f, "        \"enabled\": %s\n", rl->enabled ? "true" : "false");
            fprintf(f, "      }%s\n", (r == config->lan.rate_limit_count - 1) ? "" : ",");
        }
        fprintf(f, "    ]");
    }

    fprintf(f, ",\n    \"qos\": {\n");
    fprintf(f, "      \"enabled\": %s,\n", config->lan.qos.enabled ? "true" : "false");
    fprintf(f, "      \"algorithm\": \"%s\",\n", config->lan.qos.algorithm[0] ? config->lan.qos.algorithm : "cake");
    fprintf(f, "      \"bandwidth_down_mbps\": %u,\n", config->lan.qos.bandwidth_down_mbps);
    fprintf(f, "      \"bandwidth_up_mbps\": %u,\n", config->lan.qos.bandwidth_up_mbps);
    fprintf(f, "      \"diffserv4\": %s\n", config->lan.qos.diffserv4 ? "true" : "false");
    fprintf(f, "    },\n");

    fprintf(f, "    \"dns\": {\n");
    fprintf(f, "      \"adblock_enabled\": %s,\n", config->lan.dns.adblock_enabled ? "true" : "false");
    fprintf(f, "      \"fast_dns_enabled\": %s,\n", config->lan.dns.fast_dns_enabled ? "true" : "false");
    fprintf(f, "      \"primary_dns\": \"%s\",\n", config->lan.dns.primary_dns[0] ? config->lan.dns.primary_dns : "1.1.1.1");
    fprintf(f, "      \"secondary_dns\": \"%s\"\n", config->lan.dns.secondary_dns[0] ? config->lan.dns.secondary_dns : "8.8.8.8");
    fprintf(f, "    }\n");
    fprintf(f, "  },\n");

    if (config->group_count > 0) {
        fprintf(f, "  \"groups\": [\n");
        for (uint32_t g = 0; g < config->group_count; g++) {
            const wan_group_t *grp = &config->groups[g];
            fprintf(f, "    {\n");
            fprintf(f, "      \"id\": %u,\n", grp->id);
            fprintf(f, "      \"name\": \"%s\",\n", grp->name);
            fprintf(f, "      \"description\": \"%s\",\n", grp->description);
            fprintf(f, "      \"wans\": [");
            for (uint32_t w = 0; w < grp->wan_count; w++) {
                fprintf(f, "\"%s\"%s", grp->wan_names[w], (w == grp->wan_count - 1) ? "" : ", ");
            }
            fprintf(f, "],\n");
            fprintf(f, "      \"enabled\": %s\n", grp->enabled ? "true" : "false");
            fprintf(f, "    }%s\n", (g == config->group_count - 1) ? "" : ",");
        }
        fprintf(f, "  ],\n");
    }

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
        fprintf(f, "      \"bandwidth_down_mbps\": %u,\n", w->bandwidth_down_mbps);
        fprintf(f, "      \"bandwidth_up_mbps\": %u,\n", w->bandwidth_up_mbps);
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
    fprintf(f, "    \"max_acceptable_loss_pct\": %.1f,\n", config->prober.max_acceptable_loss_pct);
    fprintf(f, "    \"dynamic_latency_steering\": %s\n", config->prober.dynamic_latency_steering ? "true" : "false");
    fprintf(f, "  },\n");

    fprintf(f, "  \"sticky\": {\n");
    fprintf(f, "    \"enabled\": %s,\n", config->sticky.enabled ? "true" : "false");
    fprintf(f, "    \"timeout_seconds\": %u,\n", config->sticky.timeout_seconds);
    fprintf(f, "    \"strict_banking_enabled\": %s\n", config->sticky.strict_banking_enabled ? "true" : "false");
    fprintf(f, "  },\n");

    fprintf(f, "  \"app_steering\": {\n");
    fprintf(f, "    \"gaming_steering_enabled\": %s,\n", config->app_steering.gaming_steering_enabled ? "true" : "false");
    fprintf(f, "    \"voip_steering_enabled\": %s,\n", config->app_steering.voip_steering_enabled ? "true" : "false");
    fprintf(f, "    \"bulk_balancing_enabled\": %s,\n", config->app_steering.bulk_balancing_enabled ? "true" : "false");
    fprintf(f, "    \"primary_gaming_wan_id\": %u,\n", config->app_steering.primary_gaming_wan_id);
    fprintf(f, "    \"primary_voip_wan_id\": %u\n", config->app_steering.primary_voip_wan_id);
    fprintf(f, "  },\n");

    fprintf(f, "  \"telegram\": {\n");
    fprintf(f, "    \"enabled\": %s,\n", config->telegram.enabled ? "true" : "false");
    fprintf(f, "    \"bot_token\": \"%s\",\n", config->telegram.bot_token);
    fprintf(f, "    \"chat_id\": \"%s\",\n", config->telegram.chat_id);
    fprintf(f, "    \"notify_on_failover\": %s,\n", config->telegram.notify_on_failover ? "true" : "false");
    fprintf(f, "    \"notify_on_recovery\": %s\n", config->telegram.notify_on_recovery ? "true" : "false");
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
    fprintf(f, "  },\n");
    fprintf(f, "  \"nat46\": {\n");
    fprintf(f, "    \"enabled\": %s,\n", config->nat46.enabled ? "true" : "false");
    fprintf(f, "    \"synthetic_prefix\": \"%s\",\n", config->nat46.synthetic_prefix);
    fprintf(f, "    \"upstream_dns\": \"%s\",\n", config->nat46.upstream_dns);
    fprintf(f, "    \"starlink_wan_name\": \"%s\"\n", config->nat46.starlink_wan_name);
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
    printf("DNS64 / NAT46   : %s (Prefix: %s -> Starlink: %s)\n",
             config->nat46.enabled ? "ENABLED" : "DISABLED", config->nat46.synthetic_prefix, config->nat46.starlink_wan_name);
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

uint32_t config_calc_checksum(const char *data) {
    if (!data) return 0;
    uint32_t hash = 5381;
    int c;
    while ((c = *data++)) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            hash = ((hash << 5) + hash) + (uint32_t)c;
        }
    }
    return hash;
}

int config_export_backup(const fluxwan_config_t *config, char *out_json, size_t max_len) {
    if (!config || !out_json || max_len < 2048) return -1;

    const char *tmp_path = "/tmp/fluxwan_export_tmp.json";
#if defined(_WIN32) || defined(_WIN64)
    tmp_path = "fluxwan_export_tmp.json";
#endif

    if (config_save(tmp_path, config) != 0) {
        return -1;
    }

    char *cfg_str = read_file_to_string(tmp_path);
    remove(tmp_path);
    if (!cfg_str) return -1;

    uint32_t csum = config_calc_checksum(cfg_str);
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char iso_time[64] = {0};
    if (tm_info) {
        strftime(iso_time, sizeof(iso_time), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    }

    char hostname[64] = "FluxWAN-Router";
#if defined(__linux__)
    gethostname(hostname, sizeof(hostname));
#endif

    int len = snprintf(out_json, max_len,
        "{\n"
        "  \"fluxwan_backup\": {\n"
        "    \"version\": \"%s\",\n"
        "    \"author\": \"%s\",\n"
        "    \"license\": \"%s\",\n"
        "    \"created_at\": %lld,\n"
        "    \"created_at_iso\": \"%s\",\n"
        "    \"hostname\": \"%s\",\n"
        "    \"architecture\": \"x86_64\",\n"
        "    \"wan_count\": %u,\n"
        "    \"checksum\": %u,\n"
        "    \"type\": \"full_system_configuration\"\n"
        "  },\n"
        "  \"config\": %s\n"
        "}\n",
        FLUXWAN_VERSION,
        FLUXWAN_AUTHOR,
        FLUXWAN_LICENSE,
        (long long)now,
        iso_time[0] ? iso_time : "2026-09-12T13:00:00Z",
        hostname,
        config->wan_count,
        csum,
        cfg_str);

    free(cfg_str);
    return (len > 0 && (size_t)len < max_len) ? 0 : -1;
}

int config_import_backup(const char *backup_json, fluxwan_config_t *out_config, char *err_msg, size_t err_size) {
    if (!backup_json || !out_config) {
        if (err_msg && err_size > 0) snprintf(err_msg, err_size, "Empty backup data received");
        return -1;
    }

    /* Save current config_file_path and session_token to preserve them after restore */
    char saved_path[MAX_PATH_LEN] = {0};
    if (out_config->config_file_path[0]) {
        safe_str_copy(saved_path, out_config->config_file_path, sizeof(saved_path));
    } else {
        safe_str_copy(saved_path, "/opt/fluxwan/config/fluxwan.json", sizeof(saved_path));
    }

    char saved_token[64] = {0};
    if (out_config->auth.session_token[0]) {
        safe_str_copy(saved_token, out_config->auth.session_token, sizeof(saved_token));
    }

    const char *cfg_body = NULL;
    size_t cfg_body_len = 0;

    const char *cfg_key = strstr(backup_json, "\"config\"");
    if (cfg_key) {
        const char *brace = strchr(cfg_key, '{');
        if (brace) {
            const char *brace_end = find_matching_brace(brace);
            if (brace_end && brace_end >= brace) {
                cfg_body = brace;
                cfg_body_len = (size_t)(brace_end - brace + 1);
            }
        }
    }

    if (!cfg_body) {
        /* User might have uploaded raw fluxwan.json */
        const char *brace = strchr(backup_json, '{');
        if (brace) {
            const char *brace_end = find_matching_brace(brace);
            if (brace_end && brace_end >= brace) {
                cfg_body = brace;
                cfg_body_len = (size_t)(brace_end - brace + 1);
            }
        }
    }

    if (!cfg_body || cfg_body_len == 0) {
        if (err_msg && err_size > 0) snprintf(err_msg, err_size, "Invalid or missing JSON object in backup");
        return -1;
    }

    const char *tmp_path = "/tmp/fluxwan_restore_tmp.json";
#if defined(_WIN32) || defined(_WIN64)
    tmp_path = "fluxwan_restore_tmp.json";
#endif

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        if (err_msg && err_size > 0) snprintf(err_msg, err_size, "Unable to write temporary restore file");
        return -1;
    }
    fwrite(cfg_body, 1, cfg_body_len, f);
    fclose(f);

    /* Allocate test_cfg on HEAP to avoid massive stack overflow (>2.15 MB struct) */
    fluxwan_config_t *test_cfg = calloc(1, sizeof(fluxwan_config_t));
    if (!test_cfg) {
        remove(tmp_path);
        if (err_msg && err_size > 0) snprintf(err_msg, err_size, "Out of memory during configuration restore");
        return -1;
    }

    if (config_load(tmp_path, test_cfg) != 0) {
        remove(tmp_path);
        free(test_cfg);
        if (err_msg && err_size > 0) snprintf(err_msg, err_size, "Invalid or corrupted JSON configuration syntax");
        return -1;
    }
    remove(tmp_path);

    if (test_cfg->lan.ip_addr == 0) {
        free(test_cfg);
        if (err_msg && err_size > 0) snprintf(err_msg, err_size, "Backup is missing valid LAN IP configuration");
        return -1;
    }

    char validate_err[256] = {0};
    if (!config_validate_wan_attachments(test_cfg, validate_err, sizeof(validate_err))) {
        free(test_cfg);
        if (err_msg && err_size > 0) snprintf(err_msg, err_size, "%s", validate_err);
        return -1;
    }

    /* Restore file path and active session token */
    safe_str_copy(test_cfg->config_file_path, saved_path, sizeof(test_cfg->config_file_path));
    if (saved_token[0]) {
        safe_str_copy(test_cfg->auth.session_token, saved_token, sizeof(test_cfg->auth.session_token));
    }

    memcpy(out_config, test_cfg, sizeof(fluxwan_config_t));
    free(test_cfg);

    if (err_msg && err_size > 0) snprintf(err_msg, err_size, "Configuration validated successfully");
    return 0;
}

int config_reset_to_defaults(fluxwan_config_t *out_config) {
    if (!out_config) return -1;
    memset(out_config, 0, sizeof(fluxwan_config_t));

    /* 1. LAN Default */
    safe_str_copy(out_config->lan.name, "eth0", sizeof(out_config->lan.name));
    out_config->lan.ip_addr = str_to_ip("192.168.90.1");
    out_config->lan.netmask = str_to_ip("255.255.255.0");
    out_config->lan.dhcp_enabled = true;
    out_config->lan.dhcp_start = str_to_ip("192.168.90.100");
    out_config->lan.dhcp_end = str_to_ip("192.168.90.200");
    out_config->lan.dhcp_lease_time = 43200;
    out_config->lan.policy_route_count = 0;
    out_config->lan.static_lease_count = 0;
    out_config->lan.rate_limit_count = 0;

    /* QoS Default */
    out_config->lan.qos.enabled = false;
    safe_str_copy(out_config->lan.qos.algorithm, "cake", sizeof(out_config->lan.qos.algorithm));
    out_config->lan.qos.bandwidth_down_mbps = 0;
    out_config->lan.qos.bandwidth_up_mbps = 0;
    out_config->lan.qos.diffserv4 = true;

    /* DNS Default */
    out_config->lan.dns.adblock_enabled = false;
    out_config->lan.dns.fast_dns_enabled = true;
    safe_str_copy(out_config->lan.dns.primary_dns, "1.1.1.1", sizeof(out_config->lan.dns.primary_dns));
    safe_str_copy(out_config->lan.dns.secondary_dns, "8.8.8.8", sizeof(out_config->lan.dns.secondary_dns));

    /* 2. WAN Defaults: Two DHCP WANs (eth1, eth2) */
    out_config->wan_count = 2;
    out_config->wans[0].id = 1;
    safe_str_copy(out_config->wans[0].name, "eth1", sizeof(out_config->wans[0].name));
    safe_str_copy(out_config->wans[0].label, "WAN1_Primary", sizeof(out_config->wans[0].label));
    out_config->wans[0].type = WAN_TYPE_DHCP;
    out_config->wans[0].config_weight = 100;
    out_config->wans[0].dynamic_weight = 100;
    out_config->wans[0].bandwidth_down_mbps = 100;
    out_config->wans[0].bandwidth_up_mbps = 20;
    out_config->wans[0].table_id = 101;
    out_config->wans[0].mtu = 1500;
    out_config->wans[0].mss_clamping = 1452;
    out_config->wans[0].enabled = true;
    safe_str_copy(out_config->wans[0].probe_target, "8.8.8.8", sizeof(out_config->wans[0].probe_target));

    out_config->wans[1].id = 2;
    safe_str_copy(out_config->wans[1].name, "eth2", sizeof(out_config->wans[1].name));
    safe_str_copy(out_config->wans[1].label, "WAN2_Secondary", sizeof(out_config->wans[1].label));
    out_config->wans[1].type = WAN_TYPE_DHCP;
    out_config->wans[1].config_weight = 100;
    out_config->wans[1].dynamic_weight = 100;
    out_config->wans[1].bandwidth_down_mbps = 100;
    out_config->wans[1].bandwidth_up_mbps = 20;
    out_config->wans[1].table_id = 102;
    out_config->wans[1].mtu = 1500;
    out_config->wans[1].mss_clamping = 1452;
    out_config->wans[1].enabled = true;
    safe_str_copy(out_config->wans[1].probe_target, "1.1.1.1", sizeof(out_config->wans[1].probe_target));

    /* Groups Default */
    out_config->group_count = 1;
    out_config->groups[0].id = 1;
    safe_str_copy(out_config->groups[0].name, "Default_Balance", sizeof(out_config->groups[0].name));
    safe_str_copy(out_config->groups[0].description, "Default Multi-WAN Load Balancing Pool", sizeof(out_config->groups[0].description));
    out_config->groups[0].enabled = true;
    out_config->groups[0].wan_count = 2;
    safe_str_copy(out_config->groups[0].wan_names[0], "WAN1_Primary", sizeof(out_config->groups[0].wan_names[0]));
    safe_str_copy(out_config->groups[0].wan_names[1], "WAN2_Secondary", sizeof(out_config->groups[0].wan_names[1]));
    out_config->groups[0].wan_member_indices[0] = 0;
    out_config->groups[0].wan_member_indices[1] = 1;
    out_config->groups[0].active_wan_count = 2;

    /* Prober Defaults */
    out_config->prober.interval_ms = 500;
    out_config->prober.timeout_ms = 1000;
    out_config->prober.loss_window = 20;
    out_config->prober.max_acceptable_rtt_ms = 250;
    out_config->prober.max_acceptable_loss_pct = 20.0f;
    out_config->prober.dynamic_latency_steering = true;

    /* Sticky Defaults */
    out_config->sticky.enabled = true;
    out_config->sticky.timeout_seconds = 300;
    out_config->sticky.strict_banking_enabled = true;

    /* App Steering Defaults */
    out_config->app_steering.gaming_steering_enabled = true;
    out_config->app_steering.voip_steering_enabled = true;
    out_config->app_steering.bulk_balancing_enabled = true;
    out_config->app_steering.primary_gaming_wan_id = 1;
    out_config->app_steering.primary_voip_wan_id = 1;

    /* Telegram Defaults */
    out_config->telegram.enabled = false;
    out_config->telegram.notify_on_failover = true;
    out_config->telegram.notify_on_recovery = true;

    /* Web & Auth Defaults */
    safe_str_copy(out_config->web.bind_ip, "0.0.0.0", sizeof(out_config->web.bind_ip));
    out_config->web.port = 8080;
    out_config->auth.enabled = true;
    safe_str_copy(out_config->auth.username, "admin", sizeof(out_config->auth.username));
    safe_str_copy(out_config->auth.password, "admin", sizeof(out_config->auth.password));
    safe_str_copy(out_config->auth.session_token, "flux_token_admin_default", sizeof(out_config->auth.session_token));

    /* NAT46 */
    out_config->nat46.enabled = true;
    safe_str_copy(out_config->nat46.synthetic_prefix, "198.18.0.0/15", sizeof(out_config->nat46.synthetic_prefix));
    safe_str_copy(out_config->nat46.upstream_dns, "1.1.1.1", sizeof(out_config->nat46.upstream_dns));
    safe_str_copy(out_config->nat46.starlink_wan_name, "veth_wan2", sizeof(out_config->nat46.starlink_wan_name));

    return 0;
}
