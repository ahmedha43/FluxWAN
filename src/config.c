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

static void unescape_json_inplace(char *str) {
    if (!str) return;
    char *src = str;
    char *dst = str;
    while (*src) {
        if (*src == '\\') {
            src++;
            if (*src == 'n') { *dst++ = '\n'; src++; }
            else if (*src == 'r') { *dst++ = '\r'; src++; }
            else if (*src == 't') { *dst++ = '\t'; src++; }
            else if (*src == '"') { *dst++ = '"'; src++; }
            else if (*src == '\\') { *dst++ = '\\'; src++; }
            else if (*src) { *dst++ = *src++; }
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
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
        const char *end = NULL;
        bool esc = false;
        for (const char *s = p; *s; s++) {
            if (esc) { esc = false; continue; }
            if (*s == '\\') { esc = true; continue; }
            if (*s == '"') { end = s; break; }
        }
        if (end) {
            size_t len = end - p;
            if (len >= max_len) len = max_len - 1;
            strncpy(out_val, p, len);
            out_val[len] = '\0';
            unescape_json_inplace(out_val);
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

static uint64_t extract_json_uint64(const char *json, const char *key, uint64_t default_val) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return default_val;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (!*p || (!isdigit((unsigned char)*p) && *p != '-')) return default_val;
    return (uint64_t)strtoull(p, NULL, 10);
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
                        else if (strcmp(val, "wifi") == 0) w->type = WAN_TYPE_WIFI;
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

                    if (extract_json_string(obj_str, "ppp_username", val, sizeof(val)) ||
                        extract_json_string(obj_str, "username", val, sizeof(val))) {
                        safe_str_copy(w->ppp_username, val, sizeof(w->ppp_username));
                    }
                    if (extract_json_string(obj_str, "ppp_password", val, sizeof(val)) ||
                        extract_json_string(obj_str, "password", val, sizeof(val))) {
                        safe_str_copy(w->ppp_password, val, sizeof(w->ppp_password));
                    }

                    if (extract_json_string(obj_str, "mac", val, sizeof(val)) ||
                        extract_json_string(obj_str, "custom_mac", val, sizeof(val))) {
                        safe_str_copy(w->custom_mac, val, sizeof(w->custom_mac));
                    }

                    if (extract_json_string(obj_str, "wifi_ssid", val, sizeof(val)) ||
                        extract_json_string(obj_str, "ssid", val, sizeof(val))) {
                        safe_str_copy(w->wifi_ssid, val, sizeof(w->wifi_ssid));
                    }
                    if (extract_json_string(obj_str, "wifi_password", val, sizeof(val))) {
                        safe_str_copy(w->wifi_password, val, sizeof(w->wifi_password));
                    }
                    if (extract_json_string(obj_str, "wifi_security", val, sizeof(val))) {
                        safe_str_copy(w->wifi_security, val, sizeof(w->wifi_security));
                    } else if (w->type == WAN_TYPE_WIFI && !w->wifi_security[0]) {
                        safe_str_copy(w->wifi_security, "WPA2-PSK", sizeof(w->wifi_security));
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

    /* Parse L7 Deep Packet Inspection (DPI) block */
    const char *dpi_pos = strstr(json, "\"dpi\"");
    if (dpi_pos) {
        out_config->dpi.enabled = extract_json_bool(dpi_pos, "enabled", true);
        out_config->dpi.p2p_throttle_enabled = extract_json_bool(dpi_pos, "p2p_throttle_enabled", false);
        out_config->dpi.p2p_throttle_rate_kbps = (uint32_t)extract_json_int(dpi_pos, "p2p_throttle_rate_kbps", 512);
        out_config->dpi.voip_priority_enabled = extract_json_bool(dpi_pos, "voip_priority_enabled", true);
        out_config->dpi.gaming_priority_enabled = extract_json_bool(dpi_pos, "gaming_priority_enabled", true);
        out_config->dpi.streaming_balance_enabled = extract_json_bool(dpi_pos, "streaming_balance_enabled", true);
    } else {
        out_config->dpi.enabled = true;
        out_config->dpi.p2p_throttle_enabled = false;
        out_config->dpi.p2p_throttle_rate_kbps = 512;
        out_config->dpi.voip_priority_enabled = true;
        out_config->dpi.gaming_priority_enabled = true;
        out_config->dpi.streaming_balance_enabled = true;
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

    /* Parse Carrier Stealth Shield block */
    const char *stealth_pos = strstr(json, "\"stealth\"");
    if (stealth_pos) {
        out_config->stealth.enabled = extract_json_bool(stealth_pos, "enabled", true);
        out_config->stealth.ttl_value = (uint8_t)extract_json_int(stealth_pos, "ttl_value", 64);
        out_config->stealth.cloak_traceroute = extract_json_bool(stealth_pos, "cloak_traceroute", true);
        out_config->stealth.block_wan_probes = extract_json_bool(stealth_pos, "block_wan_probes", true);
    } else {
        out_config->stealth.enabled = true;
        out_config->stealth.ttl_value = 64;
        out_config->stealth.cloak_traceroute = true;
        out_config->stealth.block_wan_probes = true;
    }

    /* Parse Broadband PPPoE Server block */
    pppoe_server_config_t *pppoe = &out_config->pppoe_server;
    const char *pppoe_pos = strstr(json, "\"pppoe_server\"");
    if (pppoe_pos) {
        pppoe->enabled = extract_json_bool(pppoe_pos, "enabled", false);
        char sval[64];
        if (extract_json_string(pppoe_pos, "lan_mode", sval, sizeof(sval))) {
            safe_str_copy(pppoe->lan_mode, sval, sizeof(pppoe->lan_mode));
        } else {
            safe_str_copy(pppoe->lan_mode, "dual", sizeof(pppoe->lan_mode));
        }
        if (extract_json_string(pppoe_pos, "interface", sval, sizeof(sval))) {
            safe_str_copy(pppoe->interface, sval, sizeof(pppoe->interface));
        } else {
            safe_str_copy(pppoe->interface, out_config->lan.name[0] ? out_config->lan.name : "eth0", sizeof(pppoe->interface));
        }
        if (extract_json_string(pppoe_pos, "service_name", sval, sizeof(sval))) {
            safe_str_copy(pppoe->service_name, sval, sizeof(pppoe->service_name));
        } else {
            safe_str_copy(pppoe->service_name, "FluxWAN-Broadband", sizeof(pppoe->service_name));
        }
        if (extract_json_string(pppoe_pos, "ac_name", sval, sizeof(sval))) {
            safe_str_copy(pppoe->ac_name, sval, sizeof(pppoe->ac_name));
        } else {
            safe_str_copy(pppoe->ac_name, "FluxWAN-BRAS", sizeof(pppoe->ac_name));
        }
        if (extract_json_string(pppoe_pos, "local_ip", sval, sizeof(sval))) {
            safe_str_copy(pppoe->local_ip, sval, sizeof(pppoe->local_ip));
        } else {
            safe_str_copy(pppoe->local_ip, "10.100.0.1", sizeof(pppoe->local_ip));
        }
        if (extract_json_string(pppoe_pos, "pool_start", sval, sizeof(sval))) {
            safe_str_copy(pppoe->pool_start, sval, sizeof(pppoe->pool_start));
        } else {
            safe_str_copy(pppoe->pool_start, "10.100.0.2", sizeof(pppoe->pool_start));
        }
        if (extract_json_string(pppoe_pos, "pool_end", sval, sizeof(sval))) {
            safe_str_copy(pppoe->pool_end, sval, sizeof(pppoe->pool_end));
        } else {
            safe_str_copy(pppoe->pool_end, "10.100.0.254", sizeof(pppoe->pool_end));
        }
        pppoe->pool_count = (uint32_t)extract_json_int(pppoe_pos, "max_sessions", 250);
        if (extract_json_string(pppoe_pos, "dns1", sval, sizeof(sval))) {
            safe_str_copy(pppoe->dns1, sval, sizeof(pppoe->dns1));
        } else {
            safe_str_copy(pppoe->dns1, "1.1.1.1", sizeof(pppoe->dns1));
        }
        if (extract_json_string(pppoe_pos, "dns2", sval, sizeof(sval))) {
            safe_str_copy(pppoe->dns2, sval, sizeof(pppoe->dns2));
        } else {
            safe_str_copy(pppoe->dns2, "8.8.8.8", sizeof(pppoe->dns2));
        }
        pppoe->mru = (uint16_t)extract_json_int(pppoe_pos, "mru", 1492);
        pppoe->mss = (uint16_t)extract_json_int(pppoe_pos, "mss", 1452);

        /* Parse RADIUS / RadSec AAA block */
        const char *rad_pos = strstr(pppoe_pos, "\"radius\"");
        if (rad_pos) {
            pppoe->radius.enabled = extract_json_bool(rad_pos, "enabled", false);
            char pval[32] = {0};
            if (extract_json_string(rad_pos, "proto", pval, sizeof(pval))) {
                if (strcasecmp(pval, "radsec") == 0 || strcasecmp(pval, "tls") == 0) {
                    pppoe->radius.proto = RADIUS_PROTO_RADSEC;
                } else {
                    pppoe->radius.proto = RADIUS_PROTO_UDP;
                }
            } else {
                pppoe->radius.proto = RADIUS_PROTO_RADSEC;
            }
            extract_json_string(rad_pos, "server", pppoe->radius.server, sizeof(pppoe->radius.server));
            extract_json_string(rad_pos, "secret", pppoe->radius.secret, sizeof(pppoe->radius.secret));
            if (!pppoe->radius.secret[0] && pppoe->radius.proto == RADIUS_PROTO_RADSEC) {
                safe_str_copy(pppoe->radius.secret, "radsec", sizeof(pppoe->radius.secret));
            }
            pppoe->radius.auth_port = (uint16_t)extract_json_int(rad_pos, "auth_port", pppoe->radius.proto == RADIUS_PROTO_RADSEC ? 2083 : 1812);
            pppoe->radius.acct_port = (uint16_t)extract_json_int(rad_pos, "acct_port", pppoe->radius.proto == RADIUS_PROTO_RADSEC ? 2083 : 1813);
            pppoe->radius.coa_port = (uint16_t)extract_json_int(rad_pos, "coa_port", 3799);
            pppoe->radius.interim_interval = (uint32_t)extract_json_int(rad_pos, "interim_interval", 300);
            if (!extract_json_string(rad_pos, "nas_identifier", pppoe->radius.nas_identifier, sizeof(pppoe->radius.nas_identifier))) {
                safe_str_copy(pppoe->radius.nas_identifier, "FluxWAN-BRAS-01", sizeof(pppoe->radius.nas_identifier));
            }
            pppoe->radius.tls_verify_cert = extract_json_bool(rad_pos, "tls_verify_cert", false);
            extract_json_string(rad_pos, "ca_cert_path", pppoe->radius.ca_cert_path, sizeof(pppoe->radius.ca_cert_path));
            extract_json_string(rad_pos, "client_cert_path", pppoe->radius.client_cert_path, sizeof(pppoe->radius.client_cert_path));
            extract_json_string(rad_pos, "client_key_path", pppoe->radius.client_key_path, sizeof(pppoe->radius.client_key_path));
            extract_json_string(rad_pos, "sni_hostname", pppoe->radius.sni_hostname, sizeof(pppoe->radius.sni_hostname));
        } else {
            pppoe->radius.enabled = false;
            pppoe->radius.proto = RADIUS_PROTO_RADSEC;
            safe_str_copy(pppoe->radius.secret, "radsec", sizeof(pppoe->radius.secret));
            pppoe->radius.auth_port = 2083;
            pppoe->radius.acct_port = 2083;
            pppoe->radius.coa_port = 3799;
            pppoe->radius.interim_interval = 300;
            safe_str_copy(pppoe->radius.nas_identifier, "FluxWAN-BRAS-01", sizeof(pppoe->radius.nas_identifier));
        }

        /* Parse Profiles */
        const char *prof_pos = strstr(pppoe_pos, "\"profiles\"");
        if (prof_pos) {
            const char *p_arr_start = strchr(prof_pos, '[');
            const char *p_arr_end = find_matching_bracket(p_arr_start);
            if (p_arr_start && p_arr_end) {
                const char *p = p_arr_start;
                uint32_t p_idx = 0;
                while (p < p_arr_end && p_idx < MAX_PPPOE_PROFILES) {
                    const char *obj_start = strchr(p, '{');
                    if (!obj_start || obj_start > p_arr_end) break;
                    const char *obj_end = strchr(obj_start, '}');
                    if (!obj_end || obj_end > p_arr_end) break;

                    size_t obj_len = obj_end - obj_start + 1;
                    char *obj_str = malloc(obj_len + 1);
                    if (obj_str) {
                        strncpy(obj_str, obj_start, obj_len);
                        obj_str[obj_len] = '\0';
                        pppoe_profile_t *prof = &pppoe->profiles[p_idx];
                        extract_json_string(obj_str, "name", prof->name, sizeof(prof->name));
                        prof->rate_down_kbps = (uint32_t)extract_json_int(obj_str, "rate_down_kbps", 0);
                        prof->rate_up_kbps = (uint32_t)extract_json_int(obj_str, "rate_up_kbps", 0);
                        prof->validity_days = (uint32_t)extract_json_int(obj_str, "validity_days", 30);
                        extract_json_string(obj_str, "description", prof->description, sizeof(prof->description));
                        free(obj_str);
                        p_idx++;
                    }
                    p = obj_end + 1;
                }
                pppoe->profile_count = p_idx;
            }
        }
        if (pppoe->profile_count == 0) {
            safe_str_copy(pppoe->profiles[0].name, "Economy_10M", sizeof(pppoe->profiles[0].name));
            pppoe->profiles[0].rate_down_kbps = 10240;
            pppoe->profiles[0].rate_up_kbps = 5120;
            pppoe->profiles[0].validity_days = 30;
            safe_str_copy(pppoe->profiles[0].description, "10 Mbps Down / 5 Mbps Up (30 Days)", sizeof(pppoe->profiles[0].description));

            safe_str_copy(pppoe->profiles[1].name, "Standard_25M", sizeof(pppoe->profiles[1].name));
            pppoe->profiles[1].rate_down_kbps = 25600;
            pppoe->profiles[1].rate_up_kbps = 10240;
            pppoe->profiles[1].validity_days = 30;
            safe_str_copy(pppoe->profiles[1].description, "25 Mbps Down / 10 Mbps Up (30 Days)", sizeof(pppoe->profiles[1].description));

            safe_str_copy(pppoe->profiles[2].name, "Ultra_50M", sizeof(pppoe->profiles[2].name));
            pppoe->profiles[2].rate_down_kbps = 51200;
            pppoe->profiles[2].rate_up_kbps = 20480;
            pppoe->profiles[2].validity_days = 30;
            safe_str_copy(pppoe->profiles[2].description, "50 Mbps Down / 20 Mbps Up (30 Days)", sizeof(pppoe->profiles[2].description));

            safe_str_copy(pppoe->profiles[3].name, "Unlimited", sizeof(pppoe->profiles[3].name));
            pppoe->profiles[3].rate_down_kbps = 0;
            pppoe->profiles[3].rate_up_kbps = 0;
            pppoe->profiles[3].validity_days = 0;
            safe_str_copy(pppoe->profiles[3].description, "Max Line Speed (No Shaping / Unlimited)", sizeof(pppoe->profiles[3].description));
            pppoe->profile_count = 4;
        }

        /* Parse Users */
        const char *user_pos = strstr(pppoe_pos, "\"users\"");
        if (user_pos) {
            const char *u_arr_start = strchr(user_pos, '[');
            const char *u_arr_end = find_matching_bracket(u_arr_start);
            if (u_arr_start && u_arr_end) {
                const char *p = u_arr_start;
                uint32_t u_idx = 0;
                while (p < u_arr_end && u_idx < MAX_PPPOE_USERS) {
                    const char *obj_start = strchr(p, '{');
                    if (!obj_start || obj_start > u_arr_end) break;
                    const char *obj_end = strchr(obj_start, '}');
                    if (!obj_end || obj_end > u_arr_end) break;

                    size_t obj_len = obj_end - obj_start + 1;
                    char *obj_str = malloc(obj_len + 1);
                    if (obj_str) {
                        strncpy(obj_str, obj_start, obj_len);
                        obj_str[obj_len] = '\0';
                        pppoe_user_t *usr = &pppoe->users[u_idx];
                        extract_json_string(obj_str, "username", usr->username, sizeof(usr->username));
                        extract_json_string(obj_str, "password", usr->password, sizeof(usr->password));
                        extract_json_string(obj_str, "profile", usr->profile, sizeof(usr->profile));
                        extract_json_string(obj_str, "static_ip", usr->static_ip, sizeof(usr->static_ip));
                        extract_json_string(obj_str, "comment", usr->comment, sizeof(usr->comment));
                        usr->enabled = extract_json_bool(obj_str, "enabled", true);
                        usr->created_at = extract_json_uint64(obj_str, "created_at", (uint64_t)time(NULL));
                        usr->expires_at = extract_json_uint64(obj_str, "expires_at", 0);
                        free(obj_str);
                        u_idx++;
                    }
                    p = obj_end + 1;
                }
                pppoe->user_count = u_idx;
            }
        }
    } else {
        safe_str_copy(pppoe->lan_mode, "dual", sizeof(pppoe->lan_mode));
        safe_str_copy(pppoe->interface, out_config->lan.name[0] ? out_config->lan.name : "eth0", sizeof(pppoe->interface));
        safe_str_copy(pppoe->service_name, "FluxWAN-Broadband", sizeof(pppoe->service_name));
        safe_str_copy(pppoe->ac_name, "FluxWAN-BRAS", sizeof(pppoe->ac_name));
        safe_str_copy(pppoe->local_ip, "10.100.0.1", sizeof(pppoe->local_ip));
        safe_str_copy(pppoe->pool_start, "10.100.0.2", sizeof(pppoe->pool_start));
        safe_str_copy(pppoe->pool_end, "10.100.0.254", sizeof(pppoe->pool_end));
        pppoe->pool_count = 250;
        safe_str_copy(pppoe->dns1, "1.1.1.1", sizeof(pppoe->dns1));
        safe_str_copy(pppoe->dns2, "8.8.8.8", sizeof(pppoe->dns2));
        pppoe->mru = 1492;
        pppoe->mss = 1452;

        safe_str_copy(pppoe->profiles[0].name, "Economy_10M", sizeof(pppoe->profiles[0].name));
        pppoe->profiles[0].rate_down_kbps = 10240;
        pppoe->profiles[0].rate_up_kbps = 5120;
        pppoe->profiles[0].validity_days = 30;
        safe_str_copy(pppoe->profiles[0].description, "10 Mbps Down / 5 Mbps Up (30 Days)", sizeof(pppoe->profiles[0].description));

        safe_str_copy(pppoe->profiles[1].name, "Standard_25M", sizeof(pppoe->profiles[1].name));
        pppoe->profiles[1].rate_down_kbps = 25600;
        pppoe->profiles[1].rate_up_kbps = 10240;
        pppoe->profiles[1].validity_days = 30;
        safe_str_copy(pppoe->profiles[1].description, "25 Mbps Down / 10 Mbps Up (30 Days)", sizeof(pppoe->profiles[1].description));

        safe_str_copy(pppoe->profiles[2].name, "Ultra_50M", sizeof(pppoe->profiles[2].name));
        pppoe->profiles[2].rate_down_kbps = 51200;
        pppoe->profiles[2].rate_up_kbps = 20480;
        pppoe->profiles[2].validity_days = 30;
        safe_str_copy(pppoe->profiles[2].description, "50 Mbps Down / 20 Mbps Up (30 Days)", sizeof(pppoe->profiles[2].description));

        safe_str_copy(pppoe->profiles[3].name, "Unlimited", sizeof(pppoe->profiles[3].name));
        pppoe->profiles[3].rate_down_kbps = 0;
        pppoe->profiles[3].rate_up_kbps = 0;
        pppoe->profiles[3].validity_days = 0;
        safe_str_copy(pppoe->profiles[3].description, "Max Line Speed (No Shaping / Unlimited)", sizeof(pppoe->profiles[3].description));
        pppoe->profile_count = 4;

        safe_str_copy(pppoe->users[0].username, "fluxwan", sizeof(pppoe->users[0].username));
        safe_str_copy(pppoe->users[0].password, "123456", sizeof(pppoe->users[0].password));
        safe_str_copy(pppoe->users[0].profile, "Standard_25M", sizeof(pppoe->users[0].profile));
        pppoe->users[0].enabled = true;
        pppoe->users[0].created_at = (uint64_t)time(NULL);
        pppoe->users[0].expires_at = 0;
        safe_str_copy(pppoe->users[0].comment, "Default Broadband User", sizeof(pppoe->users[0].comment));
        pppoe->user_count = 1;
    }

    /* Parse VPN Configuration (WireGuard & ZeroTier) */
    vpn_config_t *vpn = &out_config->vpn;
    vpn->wireguard.enabled = false;
    safe_str_copy(vpn->wireguard.interface, "wg0", sizeof(vpn->wireguard.interface));
    vpn->wireguard.listen_port = 51820;
    safe_str_copy(vpn->wireguard.address, "10.250.0.1/24", sizeof(vpn->wireguard.address));
    vpn->wireguard.allow_remote_mgmt = true;
    vpn->wireguard.peer_count = 0;
    vpn->zerotier.enabled = false;
    vpn->zerotier.allow_remote_mgmt = true;
    vpn->zerotier.network_count = 0;

    const char *vpn_pos = strstr(json, "\"vpn\"");
    if (vpn_pos) {
        const char *vpn_start = strchr(vpn_pos, '{');
        const char *vpn_end = find_matching_brace(vpn_start);
        if (vpn_start && vpn_end) {
            size_t vpn_len = vpn_end - vpn_start + 1;
            char *vpn_str = malloc(vpn_len + 1);
            if (vpn_str) {
                strncpy(vpn_str, vpn_start, vpn_len);
                vpn_str[vpn_len] = '\0';

                /* Parse WireGuard */
                const char *wg_pos = strstr(vpn_str, "\"wireguard\"");
                if (wg_pos) {
                    const char *wg_start = strchr(wg_pos, '{');
                    const char *wg_end = find_matching_brace(wg_start);
                    if (wg_start && wg_end) {
                        size_t wg_len = wg_end - wg_start + 1;
                        char *wg_str = malloc(wg_len + 1);
                        if (wg_str) {
                            strncpy(wg_str, wg_start, wg_len);
                            wg_str[wg_len] = '\0';

                            vpn->wireguard.enabled = extract_json_bool(wg_str, "enabled", false);
                            vpn->wireguard.allow_remote_mgmt = extract_json_bool(wg_str, "allow_remote_mgmt", true);
                            vpn->wireguard.listen_port = (uint16_t)extract_json_int(wg_str, "listen_port", 51820);

                            char sval[128];
                            if (extract_json_string(wg_str, "interface", sval, sizeof(sval))) safe_str_copy(vpn->wireguard.interface, sval, sizeof(vpn->wireguard.interface));
                            if (extract_json_string(wg_str, "address", sval, sizeof(sval))) safe_str_copy(vpn->wireguard.address, sval, sizeof(vpn->wireguard.address));
                            if (extract_json_string(wg_str, "private_key", sval, sizeof(sval))) safe_str_copy(vpn->wireguard.private_key, sval, sizeof(vpn->wireguard.private_key));
                            if (extract_json_string(wg_str, "public_key", sval, sizeof(sval))) safe_str_copy(vpn->wireguard.public_key, sval, sizeof(vpn->wireguard.public_key));

                            /* Parse WG Peers */
                            const char *peers_pos = strstr(wg_str, "\"peers\"");
                            if (peers_pos) {
                                const char *p_arr_start = strchr(peers_pos, '[');
                                const char *p_arr_end = find_matching_bracket(p_arr_start);
                                if (p_arr_start && p_arr_end) {
                                    const char *p = p_arr_start;
                                    uint32_t p_idx = 0;
                                    while (p < p_arr_end && p_idx < MAX_WG_PEERS) {
                                        const char *obj_start = strchr(p, '{');
                                        if (!obj_start || obj_start > p_arr_end) break;
                                        const char *obj_end = find_matching_brace(obj_start);
                                        if (!obj_end || obj_end > p_arr_end) break;

                                        size_t obj_len = obj_end - obj_start + 1;
                                        char *obj_str = malloc(obj_len + 1);
                                        if (obj_str) {
                                            strncpy(obj_str, obj_start, obj_len);
                                            obj_str[obj_len] = '\0';
                                            wireguard_peer_t *peer = &vpn->wireguard.peers[p_idx];
                                            memset(peer, 0, sizeof(wireguard_peer_t));

                                            extract_json_string(obj_str, "name", peer->name, sizeof(peer->name));
                                            extract_json_string(obj_str, "public_key", peer->public_key, sizeof(peer->public_key));
                                            extract_json_string(obj_str, "client_private_key", peer->client_private_key, sizeof(peer->client_private_key));
                                            extract_json_string(obj_str, "preshared_key", peer->preshared_key, sizeof(peer->preshared_key));
                                            extract_json_string(obj_str, "allowed_ips", peer->allowed_ips, sizeof(peer->allowed_ips));
                                            extract_json_string(obj_str, "endpoint", peer->endpoint, sizeof(peer->endpoint));
                                            peer->persistent_keepalive = (uint16_t)extract_json_int(obj_str, "persistent_keepalive", 25);
                                            peer->enabled = extract_json_bool(obj_str, "enabled", true);

                                            if (peer->public_key[0]) {
                                                p_idx++;
                                            }
                                            free(obj_str);
                                        }
                                        p = obj_end + 1;
                                    }
                                    vpn->wireguard.peer_count = p_idx;
                                }
                            }

                            free(wg_str);
                        }
                    }
                }

                /* Parse ZeroTier */
                const char *zt_pos = strstr(vpn_str, "\"zerotier\"");
                if (zt_pos) {
                    const char *zt_start = strchr(zt_pos, '{');
                    const char *zt_end = find_matching_brace(zt_start);
                    if (zt_start && zt_end) {
                        size_t zt_len = zt_end - zt_start + 1;
                        char *zt_str = malloc(zt_len + 1);
                        if (zt_str) {
                            strncpy(zt_str, zt_start, zt_len);
                            zt_str[zt_len] = '\0';

                            vpn->zerotier.enabled = extract_json_bool(zt_str, "enabled", false);
                            vpn->zerotier.allow_remote_mgmt = extract_json_bool(zt_str, "allow_remote_mgmt", true);

                            char sval[64];
                            if (extract_json_string(zt_str, "node_id", sval, sizeof(sval))) safe_str_copy(vpn->zerotier.node_id, sval, sizeof(vpn->zerotier.node_id));

                            /* Parse ZT Networks */
                            const char *nets_pos = strstr(zt_str, "\"networks\"");
                            if (nets_pos) {
                                const char *n_arr_start = strchr(nets_pos, '[');
                                const char *n_arr_end = find_matching_bracket(n_arr_start);
                                if (n_arr_start && n_arr_end) {
                                    const char *np = n_arr_start;
                                    uint32_t n_idx = 0;
                                    while (np < n_arr_end && n_idx < MAX_ZT_NETWORKS) {
                                        const char *obj_start = strchr(np, '{');
                                        if (!obj_start || obj_start > n_arr_end) break;
                                        const char *obj_end = find_matching_brace(obj_start);
                                        if (!obj_end || obj_end > n_arr_end) break;

                                        size_t obj_len = obj_end - obj_start + 1;
                                        char *obj_str = malloc(obj_len + 1);
                                        if (obj_str) {
                                            strncpy(obj_str, obj_start, obj_len);
                                            obj_str[obj_len] = '\0';
                                            zerotier_network_t *net = &vpn->zerotier.networks[n_idx];
                                            memset(net, 0, sizeof(zerotier_network_t));

                                            extract_json_string(obj_str, "nwid", net->nwid, sizeof(net->nwid));
                                            extract_json_string(obj_str, "name", net->name, sizeof(net->name));
                                            net->enabled = extract_json_bool(obj_str, "enabled", true);

                                            if (net->nwid[0]) {
                                                n_idx++;
                                            }
                                            free(obj_str);
                                        }
                                        np = obj_end + 1;
                                    }
                                    vpn->zerotier.network_count = n_idx;
                                }
                            }

                            free(zt_str);
                        }
                    }
                }

                free(vpn_str);
            }
        }
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

    /* Parse Address Lists array */
    const char *al_pos = strstr(json, "\"address_lists\"");
    if (al_pos) {
        const char *array_start = strchr(al_pos, '[');
        const char *array_end = find_matching_bracket(array_start);
        if (array_start && array_end) {
            const char *p = array_start;
            uint32_t al_idx = 0;
            while (p < array_end && al_idx < MAX_ADDRESS_LISTS) {
                const char *obj_start = strchr(p, '{');
                if (!obj_start || obj_start > array_end) break;
                const char *obj_end = find_matching_brace(obj_start);
                if (!obj_end || obj_end > array_end) break;

                size_t obj_len = obj_end - obj_start + 1;
                char *obj_str = malloc(obj_len + 1);
                if (obj_str) {
                    strncpy(obj_str, obj_start, obj_len);
                    obj_str[obj_len] = '\0';

                    address_list_t *al = &out_config->address_lists[al_idx];
                    al->enabled = extract_json_bool(obj_str, "enabled", true);
                    al->target_id = (uint32_t)extract_json_int(obj_str, "target_id", 0);

                    char sval[128];
                    if (extract_json_string(obj_str, "name", sval, sizeof(sval))) {
                        safe_str_copy(al->name, sval, sizeof(al->name));
                    }
                    if (extract_json_string(obj_str, "description", sval, sizeof(sval))) {
                        safe_str_copy(al->description, sval, sizeof(al->description));
                    }
                    if (extract_json_string(obj_str, "target_type", sval, sizeof(sval))) {
                        safe_str_copy(al->target_type, sval, sizeof(al->target_type));
                    } else {
                        safe_str_copy(al->target_type, "group", sizeof(al->target_type));
                    }
                    if (extract_json_string(obj_str, "target_name", sval, sizeof(sval))) {
                        safe_str_copy(al->target_name, sval, sizeof(al->target_name));
                    }

                    /* Parse entries array */
                    const char *ent_pos = strstr(obj_str, "\"entries\"");
                    if (ent_pos) {
                        const char *e_start = strchr(ent_pos, '[');
                        const char *e_end = find_matching_bracket(e_start);
                        if (e_start && e_end) {
                            const char *ep = e_start;
                            uint32_t e_idx = 0;
                            while (ep < e_end && e_idx < MAX_ENTRIES_PER_LIST) {
                                const char *q1 = strchr(ep, '"');
                                if (!q1 || q1 >= e_end) break;
                                const char *q2 = strchr(q1 + 1, '"');
                                if (!q2 || q2 > e_end) break;

                                size_t vlen = q2 - (q1 + 1);
                                if (vlen > 0) {
                                    if (vlen >= MAX_ENTRY_STR_LEN) vlen = MAX_ENTRY_STR_LEN - 1;
                                    address_list_entry_t *entry = &al->entries[e_idx];
                                    strncpy(entry->value, q1 + 1, vlen);
                                    entry->value[vlen] = '\0';

                                    /* Determine if value is IP/CIDR or Domain */
                                    bool is_domain = false;
                                    for (size_t c = 0; c < vlen; c++) {
                                        if (isalpha((unsigned char)entry->value[c])) {
                                            is_domain = true;
                                            break;
                                        }
                                    }
                                    entry->type = is_domain ? ADDR_ENTRY_DOMAIN : ADDR_ENTRY_IP;
                                    e_idx++;
                                }
                                ep = q2 + 1;
                            }
                            al->entry_count = e_idx;
                        }
                    }

                    free(obj_str);
                    al_idx++;
                }
                p = obj_end + 1;
            }
            out_config->address_list_count = al_idx;
        }
    }

    /* Resolve Address List Targets */
    for (uint32_t a = 0; a < out_config->address_list_count; a++) {
        address_list_t *al = &out_config->address_lists[a];
        if (strcmp(al->target_type, "wan") == 0) {
            for (uint32_t w = 0; w < out_config->wan_count; w++) {
                if (al->target_id == out_config->wans[w].id ||
                    (al->target_name[0] && (strcmp(al->target_name, out_config->wans[w].label) == 0 ||
                                            strcmp(al->target_name, out_config->wans[w].name) == 0))) {
                    al->target_id = out_config->wans[w].id;
                    safe_str_copy(al->target_name, out_config->wans[w].label, sizeof(al->target_name));
                    break;
                }
            }
        } else {
            /* Group */
            for (uint32_t g = 0; g < out_config->group_count; g++) {
                if (al->target_id == out_config->groups[g].id ||
                    (al->target_name[0] && strcmp(al->target_name, out_config->groups[g].name) == 0)) {
                    al->target_id = out_config->groups[g].id;
                    safe_str_copy(al->target_name, out_config->groups[g].name, sizeof(al->target_name));
                    break;
                }
            }
        }
    }

    free(json);
    LOG_INFO("Configuration loaded successfully from %s (%u WANs, %u Groups, %u Policy Routes, %u Address Lists)",
             config_path, out_config->wan_count, out_config->group_count, out_config->lan.policy_route_count, out_config->address_list_count);
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

    fprintf(f, "  \"groups\": [");
    if (config->group_count > 0) {
        fprintf(f, "\n");
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
    } else {
        fprintf(f, "],\n");
    }

    fprintf(f, "  \"wans\": [");
    if (config->wan_count > 0) {
        fprintf(f, "\n");
        for (uint32_t i = 0; i < config->wan_count; i++) {
            const wan_config_t *w = &config->wans[i];
            char ip[32], mask[32], gw[32];
            ip_to_str(w->ip_addr, ip, sizeof(ip));
            ip_to_str(w->netmask, mask, sizeof(mask));
            ip_to_str(w->gateway, gw, sizeof(gw));

            const char *type_str = "static";
            if (w->type == WAN_TYPE_DHCP) type_str = "dhcp";
            else if (w->type == WAN_TYPE_PPPOE) type_str = "pppoe";
            else if (w->type == WAN_TYPE_WIFI) type_str = "wifi";

            fprintf(f, "    {\n");
            fprintf(f, "      \"id\": %u,\n", w->id);
            fprintf(f, "      \"name\": \"%s\",\n", w->name);
            fprintf(f, "      \"label\": \"%s\",\n", w->label);
            fprintf(f, "      \"type\": \"%s\",\n", type_str);
            if (w->type == WAN_TYPE_PPPOE || w->ppp_username[0] || w->ppp_password[0]) {
                fprintf(f, "      \"username\": \"%s\",\n", w->ppp_username);
                fprintf(f, "      \"password\": \"%s\",\n", w->ppp_password);
            }
            if (w->type == WAN_TYPE_WIFI || w->wifi_ssid[0]) {
                fprintf(f, "      \"wifi_ssid\": \"%s\",\n", w->wifi_ssid);
                fprintf(f, "      \"wifi_password\": \"%s\",\n", w->wifi_password);
                fprintf(f, "      \"wifi_security\": \"%s\",\n", w->wifi_security[0] ? w->wifi_security : "WPA2-PSK");
            }
            if (w->custom_mac[0]) {
                fprintf(f, "      \"mac\": \"%s\",\n", w->custom_mac);
            }
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
    } else {
        fprintf(f, "],\n");
    }

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
    fprintf(f, "  },\n");
    fprintf(f, "  \"dpi\": {\n");
    fprintf(f, "    \"enabled\": %s,\n", config->dpi.enabled ? "true" : "false");
    fprintf(f, "    \"p2p_throttle_enabled\": %s,\n", config->dpi.p2p_throttle_enabled ? "true" : "false");
    fprintf(f, "    \"p2p_throttle_rate_kbps\": %u,\n", config->dpi.p2p_throttle_rate_kbps);
    fprintf(f, "    \"voip_priority_enabled\": %s,\n", config->dpi.voip_priority_enabled ? "true" : "false");
    fprintf(f, "    \"gaming_priority_enabled\": %s,\n", config->dpi.gaming_priority_enabled ? "true" : "false");
    fprintf(f, "    \"streaming_balance_enabled\": %s\n", config->dpi.streaming_balance_enabled ? "true" : "false");
    fprintf(f, "  },\n");

    /* Serialize Carrier Stealth Shield */
    fprintf(f, "  \"stealth\": {\n");
    fprintf(f, "    \"enabled\": %s,\n", config->stealth.enabled ? "true" : "false");
    fprintf(f, "    \"ttl_value\": %u,\n", config->stealth.ttl_value > 0 ? config->stealth.ttl_value : 64);
    fprintf(f, "    \"cloak_traceroute\": %s,\n", config->stealth.cloak_traceroute ? "true" : "false");
    fprintf(f, "    \"block_wan_probes\": %s\n", config->stealth.block_wan_probes ? "true" : "false");
    fprintf(f, "  },\n");

    /* Serialize Broadband PPPoE Server */
    fprintf(f, "  \"pppoe_server\": {\n");
    fprintf(f, "    \"enabled\": %s,\n", config->pppoe_server.enabled ? "true" : "false");
    fprintf(f, "    \"lan_mode\": \"%s\",\n", config->pppoe_server.lan_mode[0] ? config->pppoe_server.lan_mode : "dual");
    fprintf(f, "    \"interface\": \"%s\",\n", config->pppoe_server.interface[0] ? config->pppoe_server.interface : "eth0");
    fprintf(f, "    \"service_name\": \"%s\",\n", config->pppoe_server.service_name[0] ? config->pppoe_server.service_name : "FluxWAN-Broadband");
    fprintf(f, "    \"ac_name\": \"%s\",\n", config->pppoe_server.ac_name[0] ? config->pppoe_server.ac_name : "FluxWAN-BRAS");
    fprintf(f, "    \"local_ip\": \"%s\",\n", config->pppoe_server.local_ip[0] ? config->pppoe_server.local_ip : "10.100.0.1");
    fprintf(f, "    \"pool_start\": \"%s\",\n", config->pppoe_server.pool_start[0] ? config->pppoe_server.pool_start : "10.100.0.2");
    fprintf(f, "    \"pool_end\": \"%s\",\n", config->pppoe_server.pool_end[0] ? config->pppoe_server.pool_end : "10.100.0.254");
    fprintf(f, "    \"max_sessions\": %u,\n", config->pppoe_server.pool_count > 0 ? config->pppoe_server.pool_count : 250);
    fprintf(f, "    \"dns1\": \"%s\",\n", config->pppoe_server.dns1[0] ? config->pppoe_server.dns1 : "1.1.1.1");
    fprintf(f, "    \"dns2\": \"%s\",\n", config->pppoe_server.dns2[0] ? config->pppoe_server.dns2 : "8.8.8.8");
    fprintf(f, "    \"mru\": %u,\n", config->pppoe_server.mru > 0 ? config->pppoe_server.mru : 1492);
    fprintf(f, "    \"mss\": %u,\n", config->pppoe_server.mss > 0 ? config->pppoe_server.mss : 1452);

    /* RADIUS / RadSec AAA Client */
    fprintf(f, "    \"radius\": {\n");
    fprintf(f, "      \"enabled\": %s,\n", config->pppoe_server.radius.enabled ? "true" : "false");
    fprintf(f, "      \"proto\": \"%s\",\n", config->pppoe_server.radius.proto == RADIUS_PROTO_RADSEC ? "radsec" : "udp");
    fprintf(f, "      \"server\": \"%s\",\n", config->pppoe_server.radius.server);
    fprintf(f, "      \"secret\": \"%s\",\n", config->pppoe_server.radius.secret);
    fprintf(f, "      \"auth_port\": %u,\n", config->pppoe_server.radius.auth_port > 0 ? config->pppoe_server.radius.auth_port : (config->pppoe_server.radius.proto == RADIUS_PROTO_RADSEC ? 2083 : 1812));
    fprintf(f, "      \"acct_port\": %u,\n", config->pppoe_server.radius.acct_port > 0 ? config->pppoe_server.radius.acct_port : (config->pppoe_server.radius.proto == RADIUS_PROTO_RADSEC ? 2083 : 1813));
    fprintf(f, "      \"coa_port\": %u,\n", config->pppoe_server.radius.coa_port > 0 ? config->pppoe_server.radius.coa_port : 3799);
    fprintf(f, "      \"interim_interval\": %u,\n", config->pppoe_server.radius.interim_interval > 0 ? config->pppoe_server.radius.interim_interval : 300);
    fprintf(f, "      \"nas_identifier\": \"%s\",\n", config->pppoe_server.radius.nas_identifier[0] ? config->pppoe_server.radius.nas_identifier : "FluxWAN-BRAS-01");
    fprintf(f, "      \"tls_verify_cert\": %s,\n", config->pppoe_server.radius.tls_verify_cert ? "true" : "false");
    fprintf(f, "      \"ca_cert_path\": \"%s\",\n", config->pppoe_server.radius.ca_cert_path);
    fprintf(f, "      \"client_cert_path\": \"%s\",\n", config->pppoe_server.radius.client_cert_path);
    fprintf(f, "      \"client_key_path\": \"%s\",\n", config->pppoe_server.radius.client_key_path);
    fprintf(f, "      \"sni_hostname\": \"%s\"\n", config->pppoe_server.radius.sni_hostname);
    fprintf(f, "    }");

    /* Profiles */
    fprintf(f, ",\n    \"profiles\": [\n");
    for (uint32_t p = 0; p < config->pppoe_server.profile_count; p++) {
        const pppoe_profile_t *prof = &config->pppoe_server.profiles[p];
        fprintf(f, "      {\n");
        fprintf(f, "        \"name\": \"%s\",\n", prof->name);
        fprintf(f, "        \"rate_down_kbps\": %u,\n", prof->rate_down_kbps);
        fprintf(f, "        \"rate_up_kbps\": %u,\n", prof->rate_up_kbps);
        fprintf(f, "        \"validity_days\": %u,\n", prof->validity_days);
        fprintf(f, "        \"description\": \"%s\"\n", prof->description);
        fprintf(f, "      }%s\n", (p == config->pppoe_server.profile_count - 1) ? "" : ",");
    }
    fprintf(f, "    ],\n");

    /* Users */
    fprintf(f, "    \"users\": [\n");
    for (uint32_t u = 0; u < config->pppoe_server.user_count; u++) {
        const pppoe_user_t *usr = &config->pppoe_server.users[u];
        fprintf(f, "      {\n");
        fprintf(f, "        \"username\": \"%s\",\n", usr->username);
        fprintf(f, "        \"password\": \"%s\",\n", usr->password);
        fprintf(f, "        \"profile\": \"%s\",\n", usr->profile);
        fprintf(f, "        \"static_ip\": \"%s\",\n", usr->static_ip);
        fprintf(f, "        \"comment\": \"%s\",\n", usr->comment);
        fprintf(f, "        \"created_at\": %llu,\n", (unsigned long long)usr->created_at);
        fprintf(f, "        \"expires_at\": %llu,\n", (unsigned long long)usr->expires_at);
        fprintf(f, "        \"enabled\": %s\n", usr->enabled ? "true" : "false");
        fprintf(f, "      }%s\n", (u == config->pppoe_server.user_count - 1) ? "" : ",");
    }
    fprintf(f, "    ]\n");
    fprintf(f, "  },\n");

    /* Serialize VPN (WireGuard & ZeroTier) */
    fprintf(f, "  \"vpn\": {\n");
    fprintf(f, "    \"wireguard\": {\n");
    fprintf(f, "      \"enabled\": %s,\n", config->vpn.wireguard.enabled ? "true" : "false");
    fprintf(f, "      \"interface\": \"%s\",\n", config->vpn.wireguard.interface[0] ? config->vpn.wireguard.interface : "wg0");
    fprintf(f, "      \"listen_port\": %u,\n", config->vpn.wireguard.listen_port > 0 ? config->vpn.wireguard.listen_port : 51820);
    fprintf(f, "      \"address\": \"%s\",\n", config->vpn.wireguard.address[0] ? config->vpn.wireguard.address : "10.250.0.1/24");
    fprintf(f, "      \"private_key\": \"%s\",\n", config->vpn.wireguard.private_key);
    fprintf(f, "      \"public_key\": \"%s\",\n", config->vpn.wireguard.public_key);
    fprintf(f, "      \"allow_remote_mgmt\": %s,\n", config->vpn.wireguard.allow_remote_mgmt ? "true" : "false");
    fprintf(f, "      \"peers\": [\n");
    for (uint32_t p = 0; p < config->vpn.wireguard.peer_count; p++) {
        const wireguard_peer_t *peer = &config->vpn.wireguard.peers[p];
        fprintf(f, "        {\n");
        fprintf(f, "          \"name\": \"%s\",\n", peer->name);
        fprintf(f, "          \"public_key\": \"%s\",\n", peer->public_key);
        if (peer->client_private_key[0]) {
            fprintf(f, "          \"client_private_key\": \"%s\",\n", peer->client_private_key);
        }
        fprintf(f, "          \"preshared_key\": \"%s\",\n", peer->preshared_key);
        fprintf(f, "          \"allowed_ips\": \"%s\",\n", peer->allowed_ips);
        fprintf(f, "          \"endpoint\": \"%s\",\n", peer->endpoint);
        fprintf(f, "          \"persistent_keepalive\": %u,\n", peer->persistent_keepalive);
        fprintf(f, "          \"enabled\": %s\n", peer->enabled ? "true" : "false");
        fprintf(f, "        }%s\n", (p == config->vpn.wireguard.peer_count - 1) ? "" : ",");
    }
    fprintf(f, "      ]\n");
    fprintf(f, "    },\n");
    fprintf(f, "    \"zerotier\": {\n");
    fprintf(f, "      \"enabled\": %s,\n", config->vpn.zerotier.enabled ? "true" : "false");
    fprintf(f, "      \"node_id\": \"%s\",\n", config->vpn.zerotier.node_id);
    fprintf(f, "      \"allow_remote_mgmt\": %s,\n", config->vpn.zerotier.allow_remote_mgmt ? "true" : "false");
    fprintf(f, "      \"networks\": [\n");
    for (uint32_t n = 0; n < config->vpn.zerotier.network_count; n++) {
        const zerotier_network_t *net = &config->vpn.zerotier.networks[n];
        fprintf(f, "        {\n");
        fprintf(f, "          \"nwid\": \"%s\",\n", net->nwid);
        fprintf(f, "          \"name\": \"%s\",\n", net->name);
        fprintf(f, "          \"enabled\": %s\n", net->enabled ? "true" : "false");
        fprintf(f, "        }%s\n", (n == config->vpn.zerotier.network_count - 1) ? "" : ",");
    }
    fprintf(f, "      ]\n");
    fprintf(f, "    }\n");
    fprintf(f, "  }");

    if (config->address_list_count > 0) {
        fprintf(f, ",\n  \"address_lists\": [\n");
        for (uint32_t a = 0; a < config->address_list_count; a++) {
            const address_list_t *al = &config->address_lists[a];
            fprintf(f, "    {\n");
            fprintf(f, "      \"name\": \"%s\",\n", al->name);
            fprintf(f, "      \"description\": \"%s\",\n", al->description);
            fprintf(f, "      \"target_type\": \"%s\",\n", al->target_type[0] ? al->target_type : "group");
            fprintf(f, "      \"target_id\": %u,\n", al->target_id);
            fprintf(f, "      \"target_name\": \"%s\",\n", al->target_name);
            fprintf(f, "      \"enabled\": %s,\n", al->enabled ? "true" : "false");
            fprintf(f, "      \"entries\": [\n");
            for (uint32_t e = 0; e < al->entry_count; e++) {
                fprintf(f, "        \"%s\"%s\n", al->entries[e].value, (e == al->entry_count - 1) ? "" : ",");
            }
            fprintf(f, "      ]\n");
            fprintf(f, "    }%s\n", (a == config->address_list_count - 1) ? "" : ",");
        }
        fprintf(f, "  ]\n");
    } else {
        fprintf(f, "\n");
    }
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
        int wifi_count = 0;

        for (uint32_t j = 0; j < config->wan_count; j++) {
            const wan_config_t *w2 = &config->wans[j];
            if (strcmp(w1->name, w2->name) == 0) {
                if (w2->type == WAN_TYPE_DHCP) dhcp_count++;
                else if (w2->type == WAN_TYPE_STATIC) static_count++;
                else if (w2->type == WAN_TYPE_PPPOE) pppoe_count++;
                else if (w2->type == WAN_TYPE_WIFI) wifi_count++;
            }
        }

        if (wifi_count > 1) {
            if (err_msg && err_size > 0) {
                snprintf(err_msg, err_size,
                         "Physical interface '%s' has %d WiFi clients configured. A wireless card can only connect to 1 WiFi network concurrently.",
                         w1->name, wifi_count);
            }
            return false;
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
            ((dhcp_count > 0 || static_count > 0) && pppoe_count > 0) ||
            (wifi_count > 0 && (dhcp_count > 0 || static_count > 0 || pppoe_count > 0))) {
            if (err_msg && err_size > 0) {
                snprintf(err_msg, err_size,
                         "Physical interface '%s' mixes exclusive network modes with other WANs. A dedicated port is required.",
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

    /* 2. WAN Defaults: None (Clean install - admin adds physical WANs) */
    out_config->wan_count = 0;

    /* Groups Default: None (Clean install) */
    out_config->group_count = 0;

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

    /* DPI Defaults */
    out_config->dpi.enabled = true;
    out_config->dpi.p2p_throttle_enabled = false;
    out_config->dpi.p2p_throttle_rate_kbps = 512;
    out_config->dpi.voip_priority_enabled = true;
    out_config->dpi.gaming_priority_enabled = true;
    out_config->dpi.streaming_balance_enabled = true;

    /* Stealth Defaults */
    out_config->stealth.enabled = true;
    out_config->stealth.ttl_value = 64;
    out_config->stealth.cloak_traceroute = true;
    out_config->stealth.block_wan_probes = true;

    /* Address Lists Default */
    out_config->address_list_count = 0;

    /* PPPoE Server Defaults */
    pppoe_server_config_t *p_def = &out_config->pppoe_server;
    p_def->enabled = false;
    safe_str_copy(p_def->lan_mode, "dual", sizeof(p_def->lan_mode));
    safe_str_copy(p_def->interface, "eth0", sizeof(p_def->interface));
    safe_str_copy(p_def->service_name, "FluxWAN-Broadband", sizeof(p_def->service_name));
    safe_str_copy(p_def->ac_name, "FluxWAN-BRAS", sizeof(p_def->ac_name));
    safe_str_copy(p_def->local_ip, "10.100.0.1", sizeof(p_def->local_ip));
    safe_str_copy(p_def->pool_start, "10.100.0.2", sizeof(p_def->pool_start));
    safe_str_copy(p_def->pool_end, "10.100.0.254", sizeof(p_def->pool_end));
    p_def->pool_count = 250;
    safe_str_copy(p_def->dns1, "1.1.1.1", sizeof(p_def->dns1));
    safe_str_copy(p_def->dns2, "8.8.8.8", sizeof(p_def->dns2));
    p_def->mru = 1492;
    p_def->mss = 1452;

    /* RADIUS / RadSec AAA Defaults */
    p_def->radius.enabled = false;
    p_def->radius.proto = RADIUS_PROTO_RADSEC;
    safe_str_copy(p_def->radius.server, "radius.example.com", sizeof(p_def->radius.server));
    safe_str_copy(p_def->radius.secret, "radsec", sizeof(p_def->radius.secret));
    p_def->radius.auth_port = 2083;
    p_def->radius.acct_port = 2083;
    p_def->radius.coa_port = 3799;
    p_def->radius.interim_interval = 300;
    safe_str_copy(p_def->radius.nas_identifier, "FluxWAN-BRAS-01", sizeof(p_def->radius.nas_identifier));
    p_def->radius.tls_verify_cert = false;

    safe_str_copy(p_def->profiles[0].name, "Economy_10M", sizeof(p_def->profiles[0].name));
    p_def->profiles[0].rate_down_kbps = 10240;
    p_def->profiles[0].rate_up_kbps = 5120;
    safe_str_copy(p_def->profiles[0].description, "10 Mbps Down / 5 Mbps Up", sizeof(p_def->profiles[0].description));

    safe_str_copy(p_def->profiles[1].name, "Standard_25M", sizeof(p_def->profiles[1].name));
    p_def->profiles[1].rate_down_kbps = 25600;
    p_def->profiles[1].rate_up_kbps = 10240;
    safe_str_copy(p_def->profiles[1].description, "25 Mbps Down / 10 Mbps Up", sizeof(p_def->profiles[1].description));

    safe_str_copy(p_def->profiles[2].name, "Ultra_50M", sizeof(p_def->profiles[2].name));
    p_def->profiles[2].rate_down_kbps = 51200;
    p_def->profiles[2].rate_up_kbps = 20480;
    safe_str_copy(p_def->profiles[2].description, "50 Mbps Down / 20 Mbps Up", sizeof(p_def->profiles[2].description));

    safe_str_copy(p_def->profiles[3].name, "Unlimited", sizeof(p_def->profiles[3].name));
    p_def->profiles[3].rate_down_kbps = 0;
    p_def->profiles[3].rate_up_kbps = 0;
    safe_str_copy(p_def->profiles[3].description, "Max Line Speed (No Shaping)", sizeof(p_def->profiles[3].description));
    p_def->profile_count = 4;

    safe_str_copy(p_def->users[0].username, "fluxwan", sizeof(p_def->users[0].username));
    safe_str_copy(p_def->users[0].password, "123456", sizeof(p_def->users[0].password));
    safe_str_copy(p_def->users[0].profile, "Standard_25M", sizeof(p_def->users[0].profile));
    p_def->users[0].enabled = true;
    safe_str_copy(p_def->users[0].comment, "Default Broadband User", sizeof(p_def->users[0].comment));
    p_def->user_count = 1;

    /* VPN Defaults (WireGuard & ZeroTier) */
    vpn_config_t *v_def = &out_config->vpn;
    v_def->wireguard.enabled = false;
    safe_str_copy(v_def->wireguard.interface, "wg0", sizeof(v_def->wireguard.interface));
    v_def->wireguard.listen_port = 51820;
    safe_str_copy(v_def->wireguard.address, "10.250.0.1/24", sizeof(v_def->wireguard.address));
    v_def->wireguard.allow_remote_mgmt = true;
    v_def->wireguard.peer_count = 0;

    v_def->zerotier.enabled = false;
    v_def->zerotier.allow_remote_mgmt = true;
    v_def->zerotier.network_count = 0;

    return 0;
}
