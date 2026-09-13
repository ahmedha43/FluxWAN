#include "net_apply.h"
#include <fcntl.h>
#include <net/if.h>
#include <ctype.h>
#if !defined(_WIN32) && !defined(_WIN64)
#include <netdb.h>
#endif


int net_apply_set_ip_forward(bool enable) {
#if defined(__linux__)
    int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
    if (fd < 0) {
        LOG_WARN("Could not open /proc/sys/net/ipv4/ip_forward (root privileges required)");
        return -1;
    }
    const char *val = enable ? "1\n" : "0\n";
    ssize_t written = write(fd, val, strlen(val));
    close(fd);
    if (written > 0) {
        LOG_INFO("Kernel IPv4 packet forwarding %s", enable ? "ENABLED" : "DISABLED");
        return 0;
    }
    return -1;
#else
    LOG_INFO("[Simulation] Kernel IPv4 forwarding set to %d", enable);
    return 0;
#endif
}

int net_apply_wan_nat(const char *wan_ifname, bool enable) {
    if (!wan_ifname) return -1;
#if defined(__linux__)
    char cmd[512];
    if (enable) {
        snprintf(cmd, sizeof(cmd), "iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %s -j MASQUERADE 2>/dev/null", wan_ifname, wan_ifname);
    } else {
        snprintf(cmd, sizeof(cmd), "iptables -t nat -D POSTROUTING -o %s -j MASQUERADE 2>/dev/null", wan_ifname);
    }
    safe_system(cmd);
#endif
    LOG_INFO("[Firewall/NAT] %s Masquerade on WAN interface %s", enable ? "Enabling" : "Disabling", wan_ifname);
    return 0;
}

static void apply_mss_clamping(const wan_config_t *wan) {
    if (!wan) return;
    uint16_t mss = wan->mss_clamping > 0 ? wan->mss_clamping : (wan->type == WAN_TYPE_PPPOE ? 1452 : 1460);
#if defined(__linux__)
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -o %s -j TCPMSS --set-mss %u 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o %s -j TCPMSS --set-mss %u 2>/dev/null", wan->name, mss, wan->name, mss);
    safe_system(cmd);
#endif
    LOG_INFO("[QoS / MTU] Configuring TCP MSS Clamping to %u bytes on %s", mss, wan->name);
}

int net_apply_configuration(const fluxwan_config_t *config, netlink_ctx_t *nl) {
    if (!config) return -1;

    LOG_INFO("Applying Full Network Topology & Kernel Routing to Linux System...");

    /* 1. Enable Linux IPv4 Forwarding and Multi-WAN ARP Isolation */
    net_apply_set_ip_forward(true);
#if defined(__linux__)
    /* Multi-WAN ARP Isolation & RP Filter for overlapping subnets/identical gateways (e.g. Starlink 192.168.1.1) */
    safe_system("sysctl -w net.ipv4.conf.all.arp_ignore=1 >/dev/null 2>&1");
    safe_system("sysctl -w net.ipv4.conf.all.arp_announce=2 >/dev/null 2>&1");
    safe_system("sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1");
    safe_system("sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1");
#endif

    /* 2. Configure Dedicated LAN Interface */
    char lan_ip[32], lan_mask[32];
    ip_to_str(config->lan.ip_addr, lan_ip, sizeof(lan_ip));
    ip_to_str(config->lan.netmask, lan_mask, sizeof(lan_mask));
    LOG_INFO("[Kernel Netlink] Setting LAN interface %s -> IP: %s Netmask: %s (State: UP)",
             config->lan.name, lan_ip, lan_mask);

    int l_ifidx = if_nametoindex(config->lan.name);
    if (l_ifidx <= 0) l_ifidx = config->lan.ifindex;
    if (nl && l_ifidx > 0) {
        netlink_set_interface_state(nl, l_ifidx, true);
        netlink_set_interface_ip(nl, l_ifidx, config->lan.ip_addr, config->lan.netmask);
    }
#if defined(__linux__)
    char ip_cmd[512];
    snprintf(ip_cmd, sizeof(ip_cmd), "ip addr add %s/24 dev %s 2>/dev/null || true; ip link set %s up 2>/dev/null", lan_ip, config->lan.name, config->lan.name);
    safe_system(ip_cmd);

    /* Apply Secondary LAN Subnet Gateways and Kernel Rules for Policy Routes */
    net_apply_policy_routes(config);

    /* Ensure all locally connected LAN traffic bypasses fwmark tables to allow reply packets back to LAN */
    char lan_bypass[256];
    snprintf(lan_bypass, sizeof(lan_bypass), "ip rule add to %s/24 table main prio 100 2>/dev/null", lan_ip);
    safe_system(lan_bypass);
#endif

    /* 3. Configure Multi-WAN Interfaces & Policy Tables */
    for (uint32_t i = 0; i < config->wan_count; i++) {
        const wan_config_t *w = &config->wans[i];
        char wan_ip[32], wan_gw[32];
        ip_to_str(w->ip_addr, wan_ip, sizeof(wan_ip));
        ip_to_str(w->gateway, wan_gw, sizeof(wan_gw));

        int w_ifidx = if_nametoindex(w->name);
        if (w_ifidx <= 0) w_ifidx = w->ifindex;

        /* Set WAN interface administratively UP or DOWN based on enabled state */
        if (w->enabled) {
#if defined(__linux__)
            char wan_up[128];
            snprintf(wan_up, sizeof(wan_up), "ip link set %s up 2>/dev/null || true", w->name);
            safe_system(wan_up);

            char tbl_f[64];
            snprintf(tbl_f, sizeof(tbl_f), "/run/fluxwan_table_%s", w->name);
            FILE *tf = fopen(tbl_f, "w");
            if (tf) { fprintf(tf, "%u\n", w->table_id); fclose(tf); }
#endif

            if (nl) {
                if (w_ifidx > 0) netlink_set_interface_state(nl, w_ifidx, true);
                if (w->type == WAN_TYPE_STATIC && w->ip_addr != 0 && w_ifidx > 0) {
                    netlink_set_interface_ip(nl, w_ifidx, w->ip_addr, w->netmask);
                }

                /* Create Policy Route Table & Rule */
                uint32_t fwmark = 0x100 + i + 1;
                netlink_add_ip_rule(nl, fwmark, w->table_id, 1000 + i);
                if (w->gateway != 0) {
                    netlink_add_default_route(nl, w->table_id, w->gateway, w_ifidx);
                }
            }

#if defined(__linux__)
            if (w->gateway != 0) {
                char route_cmd[512];
                snprintf(route_cmd, sizeof(route_cmd),
                         "ip route replace default via %s dev %s table %u proto static 2>/dev/null || true; "
                         "ip rule del oif %s table %u 2>/dev/null || true; "
                         "ip rule add oif %s table %u pref 100 2>/dev/null || true; "
                         "ip route replace default via %s dev %s metric %u 2>/dev/null || true",
                         wan_gw, w->name, w->table_id,
                         w->name, w->table_id,
                         w->name, w->table_id,
                         wan_gw, w->name, 100 + i + 1);
                safe_system(route_cmd);

                char rp_cmd[256];
                snprintf(rp_cmd, sizeof(rp_cmd),
                         "sysctl -w net.ipv4.conf.%s.rp_filter=0 >/dev/null 2>&1 || true; "
                         "sysctl -w net.ipv4.conf.%s.arp_ignore=1 >/dev/null 2>&1 || true; "
                         "sysctl -w net.ipv4.conf.%s.arp_announce=2 >/dev/null 2>&1 || true",
                         w->name, w->name, w->name);
                safe_system(rp_cmd);
            }
#endif

            /* Enable NAT Masquerade for this WAN */
            net_apply_wan_nat(w->name, true);
            if (w->type == WAN_TYPE_PPPOE) {
                char ppp_if[16];
                snprintf(ppp_if, sizeof(ppp_if), "ppp%u", i);
                net_apply_wan_nat(ppp_if, true);
            }

            /* Apply MSS Clamping for PPPoE / Low MTU links */
            apply_mss_clamping(w);

        } else {
            /* WAN is DISABLED: Completely halt routing, kill DHCP, drop NAT, and bring link down */
#if defined(__linux__)
            char wan_down[512];
            snprintf(wan_down, sizeof(wan_down),
                     "ip link set %s down 2>/dev/null || true; "
                     "ip route del default dev %s 2>/dev/null || true; "
                     "ip route flush table %u 2>/dev/null || true; "
                     "ip rule del oif %s 2>/dev/null || true; "
                     "ip rule del table %u 2>/dev/null || true; "
                     "if [ -f /run/udhcpc_%s.pid ]; then kill $(cat /run/udhcpc_%s.pid 2>/dev/null) 2>/dev/null || true; rm -f /run/udhcpc_%s.pid /run/fluxwan_wan_%s.lease; fi",
                     w->name, w->name, w->table_id, w->name, w->table_id,
                     w->name, w->name, w->name, w->name);
            safe_system(wan_down);
#endif
            if (nl && w_ifidx > 0) {
                netlink_set_interface_state(nl, w_ifidx, false);
            }
            net_apply_wan_nat(w->name, false);
            if (w->type == WAN_TYPE_PPPOE) {
                char ppp_if[16];
                snprintf(ppp_if, sizeof(ppp_if), "ppp%u", i);
                net_apply_wan_nat(ppp_if, false);
            }
        }
    }

#if defined(__linux__)
    /* 4. Configure Linux Kernel Mangle Rules with Conntrack Sticky Marks */
    safe_system("iptables -t mangle -F PREROUTING 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -j CONNMARK --restore-mark --mask 0x0000ffff 2>/dev/null || true");

    /* Bypass Multi-WAN load balancing for local, broadcast and directly-connected subnets */
    safe_system("iptables -t mangle -A PREROUTING -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -d 10.10.0.0/16 -j RETURN 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -d 192.168.0.0/16 -j RETURN 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -d 172.16.0.0/12 -j RETURN 2>/dev/null || true");

    /* Address Lists Steering (evaluated before default load balancing) */
    safe_system("iptables -t mangle -N FLUXWAN_ADDRLIST 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -j FLUXWAN_ADDRLIST 2>/dev/null || true");
    safe_system("iptables -t mangle -A OUTPUT -j FLUXWAN_ADDRLIST 2>/dev/null || true");

    /* Calculate total active dynamic weight (strictly exclude disabled WANs) */
    uint32_t total_active_weight = 0;
    for (uint32_t i = 0; i < config->wan_count; i++) {
        if (config->wans[i].enabled && config->wans[i].state != WAN_STATE_DOWN && config->wans[i].dynamic_weight > 0) {
            total_active_weight += config->wans[i].dynamic_weight;
        }
    }

    if (total_active_weight > 0) {
        uint32_t remaining_weight = total_active_weight;
        for (uint32_t i = 0; i < config->wan_count; i++) {
            const wan_config_t *w = &config->wans[i];
            if (!w->enabled || w->state == WAN_STATE_DOWN || w->dynamic_weight == 0) continue;

            uint32_t fwmark = 0x100 + i + 1;
            char cmd[512];
            if (i == config->wan_count - 1 || remaining_weight == w->dynamic_weight) {
                /* Last active WAN catches remaining flows */
                snprintf(cmd, sizeof(cmd),
                         "iptables -t mangle -A PREROUTING -i %s -m mark --mark 0 -j MARK --set-mark 0x%x 2>/dev/null",
                         config->lan.name, fwmark);
            } else {
                double prob = (double)w->dynamic_weight / (double)remaining_weight;
                snprintf(cmd, sizeof(cmd),
                         "iptables -t mangle -A PREROUTING -i %s -m mark --mark 0 -m statistic --mode random --probability %.4f -j MARK --set-mark 0x%x 2>/dev/null",
                         config->lan.name, prob, fwmark);
                remaining_weight -= w->dynamic_weight;
            }
            safe_system(cmd);
        }
    }
    safe_system("iptables -t mangle -A PREROUTING -j CONNMARK --save-mark --mask 0x0000ffff 2>/dev/null || true");
#endif

    /* 5. Apply QoS, Rate Limits, Application Steering, DPI, and DNS Redirection */
    net_apply_qos(config);
    net_apply_rate_limits(config);
    net_apply_address_lists(config);
    net_apply_app_steering(config);
    net_apply_dpi(config);
    net_apply_dns_features(config);

    LOG_INFO("Network configuration successfully applied to Kernel!");
    return 0;
}

int net_apply_policy_routes(const fluxwan_config_t *config) {
    if (!config) return -1;
#if defined(__linux__)
    for (uint32_t p = 0; p < config->lan.policy_route_count; p++) {
        const policy_route_t *pr = &config->lan.policy_routes[p];
        if (pr->enabled && pr->gateway_ip_str[0]) {
            char gw_cmd[512];
            snprintf(gw_cmd, sizeof(gw_cmd), "ip addr add %s/%u dev %s 2>/dev/null || true",
                     pr->gateway_ip_str, pr->prefix_len > 0 ? pr->prefix_len : 24, config->lan.name);
            safe_system(gw_cmd);
            LOG_INFO("[Kernel Netlink] Added Policy Gateway Alias %s/%u on %s (Target Group: %s)",
                     pr->gateway_ip_str, pr->prefix_len > 0 ? pr->prefix_len : 24, config->lan.name, pr->target_group);

            /* If target group has members, add kernel policy routing rule for this subnet */
            for (uint32_t g = 0; g < config->group_count; g++) {
                if (config->groups[g].id == pr->target_group_id && config->groups[g].wan_count > 0) {
                    uint32_t first_wan_idx = config->groups[g].wan_member_indices[0];
                    if (first_wan_idx < config->wan_count) {
                        uint32_t tbl = config->wans[first_wan_idx].table_id;
                        char rule_cmd[512];
                        snprintf(rule_cmd, sizeof(rule_cmd),
                                 "ip rule del from %s lookup %u 2>/dev/null || true; ip rule add from %s lookup %u priority %u 2>/dev/null || true",
                                 pr->subnet_str, tbl, pr->subnet_str, tbl, 500 + p);
                        safe_system(rule_cmd);
                    }
                    break;
                }
            }
        }
    }
#endif
    return 0;
}

int net_apply_qos(const fluxwan_config_t *config) {
    if (!config) return -1;
#if defined(__linux__)
    const qos_config_t *qos = &config->lan.qos;
    const char *lan = config->lan.name[0] ? config->lan.name : "eth0";

    if (!qos->enabled) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null || true", lan);
        safe_system(cmd);
        for (uint32_t i = 0; i < config->wan_count; i++) {
            snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null || true", config->wans[i].name);
            safe_system(cmd);
        }
        return 0;
    }

    char qdisc_cmd[512];
    if (strcmp(qos->algorithm, "cake") == 0) {
        if (qos->bandwidth_down_mbps > 0) {
            snprintf(qdisc_cmd, sizeof(qdisc_cmd),
                     "tc qdisc replace dev %s root cake bandwidth %llubit %s nonat dual-dsthost 2>/dev/null || true",
                     lan, (unsigned long long)qos->bandwidth_down_mbps * 1000000ULL,
                     qos->diffserv4 ? "diffserv4" : "besteffort");
        } else {
            snprintf(qdisc_cmd, sizeof(qdisc_cmd),
                     "tc qdisc replace dev %s root cake %s nonat dual-dsthost 2>/dev/null || true",
                     lan, qos->diffserv4 ? "diffserv4" : "besteffort");
        }
        safe_system(qdisc_cmd);

        for (uint32_t i = 0; i < config->wan_count; i++) {
            const wan_config_t *w = &config->wans[i];
            if (!w->enabled || w->state == WAN_STATE_DOWN) continue;
            uint32_t up_bw = w->bandwidth_up_mbps > 0 ? w->bandwidth_up_mbps : (qos->bandwidth_up_mbps / (config->wan_count > 0 ? config->wan_count : 1));
            if (up_bw > 0) {
                snprintf(qdisc_cmd, sizeof(qdisc_cmd),
                         "tc qdisc replace dev %s root cake bandwidth %llubit %s nat dual-srchost 2>/dev/null || true",
                         w->name, (unsigned long long)up_bw * 1000000ULL,
                         qos->diffserv4 ? "diffserv4" : "besteffort");
            } else {
                snprintf(qdisc_cmd, sizeof(qdisc_cmd),
                         "tc qdisc replace dev %s root cake %s nat dual-srchost 2>/dev/null || true",
                         w->name, qos->diffserv4 ? "diffserv4" : "besteffort");
            }
            safe_system(qdisc_cmd);
        }
    } else {
        snprintf(qdisc_cmd, sizeof(qdisc_cmd),
                 "tc qdisc replace dev %s root fq_codel limit 1024 target 5ms interval 100ms 2>/dev/null || true",
                 lan);
        safe_system(qdisc_cmd);
        for (uint32_t i = 0; i < config->wan_count; i++) {
            const wan_config_t *w = &config->wans[i];
            if (!w->enabled || w->state == WAN_STATE_DOWN) continue;
            snprintf(qdisc_cmd, sizeof(qdisc_cmd),
                     "tc qdisc replace dev %s root fq_codel limit 1024 target 5ms interval 100ms 2>/dev/null || true",
                     w->name);
            safe_system(qdisc_cmd);
        }
    }
    LOG_INFO("[QoS Engine] SQM (%s) bufferbloat mitigations active on LAN %s", qos->algorithm, lan);
#endif
    return 0;
}

int net_apply_rate_limits(const fluxwan_config_t *config) {
    if (!config) return -1;
#if defined(__linux__)
    safe_system("iptables -F FLUXWAN_RATELIMIT 2>/dev/null || true");
    safe_system("iptables -N FLUXWAN_RATELIMIT 2>/dev/null || true");
    safe_system("iptables -D FORWARD -j FLUXWAN_RATELIMIT 2>/dev/null || true");
    safe_system("iptables -I FORWARD 1 -j FLUXWAN_RATELIMIT 2>/dev/null || true");

    for (uint32_t i = 0; i < config->lan.rate_limit_count; i++) {
        const rate_limit_t *rl = &config->lan.rate_limits[i];
        if (!rl->enabled || !rl->ip_str[0]) continue;

        char cmd[512];
        if (rl->max_down_mbps > 0) {
            uint32_t kbps = rl->max_down_mbps * 1024;
            snprintf(cmd, sizeof(cmd),
                     "iptables -A FLUXWAN_RATELIMIT -d %s -m hashlimit --hashlimit-above %ukb/s --hashlimit-mode dstip --hashlimit-name rl_d_%u -j DROP 2>/dev/null || true",
                     rl->ip_str, kbps, i);
            safe_system(cmd);
        }
        if (rl->max_up_mbps > 0) {
            uint32_t kbps = rl->max_up_mbps * 1024;
            snprintf(cmd, sizeof(cmd),
                     "iptables -A FLUXWAN_RATELIMIT -s %s -m hashlimit --hashlimit-above %ukb/s --hashlimit-mode srcip --hashlimit-name rl_u_%u -j DROP 2>/dev/null || true",
                     rl->ip_str, kbps, i);
            safe_system(cmd);
        }
        LOG_INFO("[Rate Limiter] Applied %u/%u Mbps limit for %s (%s)",
                 rl->max_down_mbps, rl->max_up_mbps, rl->ip_str, rl->description);
    }
#endif
    return 0;
}

int net_apply_app_steering(const fluxwan_config_t *config) {
    if (!config) return -1;
#if defined(__linux__)
    safe_system("iptables -t mangle -F FLUXWAN_STEER 2>/dev/null || true");
    safe_system("iptables -t mangle -N FLUXWAN_STEER 2>/dev/null || true");
    safe_system("iptables -t mangle -D PREROUTING -j FLUXWAN_STEER 2>/dev/null || true");
    safe_system("iptables -t mangle -I PREROUTING 2 -j FLUXWAN_STEER 2>/dev/null || true");

    const app_steering_t *as = &config->app_steering;
    const char *lan = config->lan.name[0] ? config->lan.name : "eth0";

    /* Find lowest RTT WAN for Gaming */
    if (as->gaming_steering_enabled && config->wan_count > 0) {
        uint32_t best_wan_idx = 0;
        uint32_t min_rtt = 999999;
        for (uint32_t i = 0; i < config->wan_count; i++) {
            const wan_config_t *w = &config->wans[i];
            if (as->primary_gaming_wan_id > 0 && w->id == as->primary_gaming_wan_id) {
                best_wan_idx = i;
                break;
            }
            if (w->enabled && w->state == WAN_STATE_HEALTHY && w->metrics.rtt_ms < min_rtt) {
                min_rtt = w->metrics.rtt_ms;
                best_wan_idx = i;
            }
        }
        uint32_t fwmark = 0x100 + best_wan_idx + 1;
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "iptables -t mangle -A FLUXWAN_STEER -i %s -p udp -m multiport --dports 3074,3478,3479,3480,27015,27020,27031,27036 -j MARK --set-mark 0x%x 2>/dev/null || true",
                 lan, fwmark);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "iptables -t mangle -A FLUXWAN_STEER -i %s -p udp --dport 27000:27050 -j MARK --set-mark 0x%x 2>/dev/null || true",
                 lan, fwmark);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "iptables -t mangle -A FLUXWAN_STEER -i %s -p udp --dport 5000:5500 -j MARK --set-mark 0x%x 2>/dev/null || true",
                 lan, fwmark);
        safe_system(cmd);
        LOG_INFO("[App Steering] Steered Gaming traffic -> WAN %u (%s, mark 0x%x)",
                 config->wans[best_wan_idx].id, config->wans[best_wan_idx].name, fwmark);
    }

    /* Find lowest Jitter WAN for VoIP & RTC */
    if (as->voip_steering_enabled && config->wan_count > 0) {
        uint32_t best_voip_idx = 0;
        uint32_t min_jitter = 999999;
        for (uint32_t i = 0; i < config->wan_count; i++) {
            const wan_config_t *w = &config->wans[i];
            if (as->primary_voip_wan_id > 0 && w->id == as->primary_voip_wan_id) {
                best_voip_idx = i;
                break;
            }
            if (w->enabled && w->state == WAN_STATE_HEALTHY && w->metrics.jitter_ms < min_jitter) {
                min_jitter = w->metrics.jitter_ms;
                best_voip_idx = i;
            }
        }
        uint32_t fwmark = 0x100 + best_voip_idx + 1;
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "iptables -t mangle -A FLUXWAN_STEER -i %s -p udp -m multiport --dports 5060,5061 -j MARK --set-mark 0x%x 2>/dev/null || true",
                 lan, fwmark);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "iptables -t mangle -A FLUXWAN_STEER -i %s -p udp --dport 10000:20000 -j MARK --set-mark 0x%x 2>/dev/null || true",
                 lan, fwmark);
        safe_system(cmd);
        LOG_INFO("[App Steering] Steered VoIP & RTC traffic -> WAN %u (%s, mark 0x%x)",
                 config->wans[best_voip_idx].id, config->wans[best_voip_idx].name, fwmark);
    }
#endif
    return 0;
}

int net_apply_dns_features(const fluxwan_config_t *config) {
    if (!config) return -1;
#if defined(__linux__)
    safe_system("iptables -t nat -F FLUXWAN_DNS 2>/dev/null || true");
    safe_system("iptables -t nat -N FLUXWAN_DNS 2>/dev/null || true");
    safe_system("iptables -t nat -D PREROUTING -j FLUXWAN_DNS 2>/dev/null || true");
    safe_system("iptables -t nat -I PREROUTING 1 -j FLUXWAN_DNS 2>/dev/null || true");

    const dns_features_t *dns = &config->lan.dns;
    const char *lan = config->lan.name[0] ? config->lan.name : "eth0";

    const char *target_dns = "1.1.1.1";
    if (dns->adblock_enabled) {
        target_dns = "94.140.14.14"; /* AdGuard DNS */
    } else if (dns->fast_dns_enabled && dns->primary_dns[0]) {
        target_dns = dns->primary_dns;
    }

    if (dns->adblock_enabled || dns->fast_dns_enabled) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -A FLUXWAN_DNS -i %s -p udp --dport 53 -j DNAT --to-destination %s:53 2>/dev/null || true",
                 lan, target_dns);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "iptables -t nat -A FLUXWAN_DNS -i %s -p tcp --dport 53 -j DNAT --to-destination %s:53 2>/dev/null || true",
                 lan, target_dns);
        safe_system(cmd);
        LOG_INFO("[DNS Engine] Intercepting port 53 -> %s (%s)",
                 target_dns, dns->adblock_enabled ? "Ad-Blocking Active" : "Fast DNS Active");
    }
#endif
    return 0;
}

int net_apply_dpi(const fluxwan_config_t *config) {
    if (!config) return -1;
#if defined(__linux__)
    safe_system("iptables -t mangle -F FLUXWAN_DPI 2>/dev/null || true");
    safe_system("iptables -t mangle -F FLUXWAN_DPI_QOS 2>/dev/null || true");
    safe_system("iptables -t mangle -F FLUXWAN_DPI_ACCT 2>/dev/null || true");
    safe_system("iptables -t mangle -D PREROUTING -j FLUXWAN_DPI 2>/dev/null || true");
    safe_system("iptables -t mangle -D PREROUTING -j FLUXWAN_DPI_QOS 2>/dev/null || true");
    safe_system("iptables -t mangle -D PREROUTING -j FLUXWAN_DPI_ACCT 2>/dev/null || true");

    if (!config->dpi.enabled) {
        LOG_INFO("[DPI Engine] L7 Deep Packet Inspection is DISABLED");
        return 0;
    }

    safe_system("iptables -t mangle -N FLUXWAN_DPI 2>/dev/null || true");
    safe_system("iptables -t mangle -N FLUXWAN_DPI_QOS 2>/dev/null || true");
    safe_system("iptables -t mangle -N FLUXWAN_DPI_ACCT 2>/dev/null || true");

    /* Insert chains into PREROUTING:
     * 1. FLUXWAN_DPI: Classifies connections via SNI & Signatures, writes mark 0x00XX0000 into connmark
     * 2. FLUXWAN_DPI_QOS: Applies DSCP priorities (VoIP EF, Gaming CS5, Torrent CS1) and throttling
     * 3. FLUXWAN_DPI_ACCT: Tracks byte and packet metrics per application category
     */
    safe_system("iptables -t mangle -I PREROUTING 1 -j FLUXWAN_DPI 2>/dev/null || true");
    safe_system("iptables -t mangle -I PREROUTING 2 -j FLUXWAN_DPI_QOS 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -j FLUXWAN_DPI_ACCT 2>/dev/null || true");

    /* FLUXWAN_DPI Chain: If flow already classified (mark != 0 in mask 0x00ff0000), return early */
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m connmark ! --mark 0/0x00ff0000 -j RETURN 2>/dev/null || true");

    /* YouTube / Google Video (0x00100000) */
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"googlevideo.com\" --algo bm -j CONNMARK --set-xmark 0x00100000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"youtube.com\" --algo bm -j CONNMARK --set-xmark 0x00100000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"ytimg.com\" --algo bm -j CONNMARK --set-xmark 0x00100000/0x00ff0000 2>/dev/null || true");

    /* TikTok / ByteDance (0x00200000) */
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"byteoversea.com\" --algo bm -j CONNMARK --set-xmark 0x00200000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"tiktokv.com\" --algo bm -j CONNMARK --set-xmark 0x00200000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"musical.ly\" --algo bm -j CONNMARK --set-xmark 0x00200000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"ibytedtos.com\" --algo bm -j CONNMARK --set-xmark 0x00200000/0x00ff0000 2>/dev/null || true");

    /* Netflix Video (0x00300000) */
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"netflix.com\" --algo bm -j CONNMARK --set-xmark 0x00300000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"nflxvideo.net\" --algo bm -j CONNMARK --set-xmark 0x00300000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"nflxext.com\" --algo bm -j CONNMARK --set-xmark 0x00300000/0x00ff0000 2>/dev/null || true");

    /* Zoom Conferencing (0x00400000) */
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"zoom.us\" --algo bm -j CONNMARK --set-xmark 0x00400000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -p udp -m multiport --dports 8801,8802 -j CONNMARK --set-xmark 0x00400000/0x00ff0000 2>/dev/null || true");

    /* Microsoft Teams & Skype (0x00500000) */
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"teams.microsoft.com\" --algo bm -j CONNMARK --set-xmark 0x00500000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"skype.com\" --algo bm -j CONNMARK --set-xmark 0x00500000/0x00ff0000 2>/dev/null || true");

    /* Steam & Online Gaming (0x00600000) */
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"steampowered.com\" --algo bm -j CONNMARK --set-xmark 0x00600000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --string \"steamcontent.com\" --algo bm -j CONNMARK --set-xmark 0x00600000/0x00ff0000 2>/dev/null || true");

    /* BitTorrent P2P Handshake & Ports (0x00700000) */
    safe_system("iptables -t mangle -A FLUXWAN_DPI -m string --hex-string \"|13426974546f7272656e742070726f746f636f6c|\" --algo bm -j CONNMARK --set-xmark 0x00700000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -p tcp -m multiport --dports 6881:6889,51413 -j CONNMARK --set-xmark 0x00700000/0x00ff0000 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI -p udp -m multiport --dports 6881:6889,51413 -j CONNMARK --set-xmark 0x00700000/0x00ff0000 2>/dev/null || true");

    /* FLUXWAN_DPI_QOS Chain: Set DSCP class & apply P2P throttle */
    if (config->dpi.voip_priority_enabled) {
        safe_system("iptables -t mangle -A FLUXWAN_DPI_QOS -m connmark --mark 0x00400000/0x00ff0000 -j DSCP --set-dscp-class EF 2>/dev/null || true");
        safe_system("iptables -t mangle -A FLUXWAN_DPI_QOS -m connmark --mark 0x00500000/0x00ff0000 -j DSCP --set-dscp-class EF 2>/dev/null || true");
    }
    if (config->dpi.gaming_priority_enabled) {
        safe_system("iptables -t mangle -A FLUXWAN_DPI_QOS -m connmark --mark 0x00600000/0x00ff0000 -j DSCP --set-dscp-class CS5 2>/dev/null || true");
    }

    /* BitTorrent Scavenger DSCP CS1 & Dynamic Throttling */
    safe_system("iptables -t mangle -A FLUXWAN_DPI_QOS -m connmark --mark 0x00700000/0x00ff0000 -j DSCP --set-dscp-class CS1 2>/dev/null || true");
    if (config->dpi.p2p_throttle_enabled) {
        uint32_t kbps = config->dpi.p2p_throttle_rate_kbps > 0 ? config->dpi.p2p_throttle_rate_kbps : 512;
        char th_cmd[512];
        snprintf(th_cmd, sizeof(th_cmd),
                 "iptables -t mangle -A FLUXWAN_DPI_QOS -m connmark --mark 0x00700000/0x00ff0000 -m hashlimit --hashlimit-above %ukb/s --hashlimit-mode dstip --hashlimit-name p2p_throttle -j DROP 2>/dev/null || true",
                 kbps);
        safe_system(th_cmd);
        LOG_INFO("[DPI Engine] P2P BitTorrent throttling ACTIVE at %u Kbps", kbps);
    }

    /* FLUXWAN_DPI_ACCT Chain: Accounting counters */
    safe_system("iptables -t mangle -A FLUXWAN_DPI_ACCT -m connmark --mark 0x00100000/0x00ff0000 -m comment --comment 'YouTube' 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI_ACCT -m connmark --mark 0x00200000/0x00ff0000 -m comment --comment 'TikTok' 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI_ACCT -m connmark --mark 0x00300000/0x00ff0000 -m comment --comment 'Netflix' 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI_ACCT -m connmark --mark 0x00400000/0x00ff0000 -m comment --comment 'Zoom' 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI_ACCT -m connmark --mark 0x00500000/0x00ff0000 -m comment --comment 'Teams' 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI_ACCT -m connmark --mark 0x00600000/0x00ff0000 -m comment --comment 'Steam' 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI_ACCT -m connmark --mark 0x00700000/0x00ff0000 -m comment --comment 'BitTorrent' 2>/dev/null || true");
    safe_system("iptables -t mangle -A FLUXWAN_DPI_ACCT -m comment --comment 'Other' 2>/dev/null || true");

    LOG_INFO("[DPI Engine] L7 Deep Packet Inspection & App Classification rules ACTIVE (VoIP:%d, Gaming:%d, P2P_Throttle:%d)",
             config->dpi.voip_priority_enabled, config->dpi.gaming_priority_enabled, config->dpi.p2p_throttle_enabled);
#endif
    return 0;
}

static void sanitize_set_name(const char *in_name, char *out_name, size_t out_len) {
    if (!out_name || out_len < 4) return;
    snprintf(out_name, out_len, "fw_");
    size_t p = 3;
    for (size_t i = 0; in_name && in_name[i] && p < out_len - 1 && p < 28; i++) {
        char c = in_name[i];
        if (isalnum((unsigned char)c) || c == '_' || c == '-') {
            out_name[p++] = (char)tolower((unsigned char)c);
        } else {
            out_name[p++] = '_';
        }
    }
    out_name[p] = '\0';
}

int net_apply_address_lists(const fluxwan_config_t *config) {
    if (!config) return -1;
#if defined(__linux__)

    /* Initialize FLUXWAN_ADDRLIST chain in mangle table */
    safe_system("iptables -t mangle -N FLUXWAN_ADDRLIST 2>/dev/null || true");
    safe_system("iptables -t mangle -F FLUXWAN_ADDRLIST 2>/dev/null || true");
    safe_system("iptables -t mangle -C PREROUTING -j FLUXWAN_ADDRLIST 2>/dev/null || iptables -t mangle -I PREROUTING 6 -j FLUXWAN_ADDRLIST 2>/dev/null || true");
    safe_system("iptables -t mangle -C OUTPUT -j FLUXWAN_ADDRLIST 2>/dev/null || iptables -t mangle -A OUTPUT -j FLUXWAN_ADDRLIST 2>/dev/null || true");

    /* Skip re-marking if packet already has a restored conntrack routing mark */
    safe_system("iptables -t mangle -A FLUXWAN_ADDRLIST -m mark ! --mark 0 -j RETURN 2>/dev/null || true");

    for (uint32_t a = 0; a < config->address_list_count; a++) {
        const address_list_t *al = &config->address_lists[a];
        if (!al->enabled || al->entry_count == 0) continue;

        char set_name[64], tmp_set[80];
        sanitize_set_name(al->name, set_name, sizeof(set_name));
        snprintf(tmp_set, sizeof(tmp_set), "t_%s", set_name);
        if (strlen(tmp_set) > 31) tmp_set[31] = '\0';

        /* 1. Create temporary ipset */
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "ipset create %s hash:net maxelem 65536 -exist 2>/dev/null || true", set_name);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd), "ipset create %s hash:net maxelem 65536 -exist 2>/dev/null || true", tmp_set);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd), "ipset flush %s 2>/dev/null || true", tmp_set);
        safe_system(cmd);

        /* 2. Populate temporary ipset with IPs and resolved domain addresses */
        uint32_t added_count = 0;
        for (uint32_t e = 0; e < al->entry_count; e++) {
            const address_list_entry_t *entry = &al->entries[e];
            if (!entry->value[0]) continue;

            if (entry->type == ADDR_ENTRY_IP) {
                snprintf(cmd, sizeof(cmd), "ipset add %s %s -exist 2>/dev/null || true", tmp_set, entry->value);
                safe_system(cmd);
                added_count++;
            } else {
                /* Domain resolution via getaddrinfo */
                struct addrinfo hints, *res = NULL, *p = NULL;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET; /* IPv4 */
                hints.ai_socktype = SOCK_STREAM;
                if (getaddrinfo(entry->value, NULL, &hints, &res) == 0 && res) {
                    for (p = res; p != NULL; p = p->ai_next) {
                        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
                        snprintf(cmd, sizeof(cmd), "ipset add %s %s -exist 2>/dev/null || true", tmp_set, ip_str);
                        safe_system(cmd);
                        added_count++;
                    }
                    freeaddrinfo(res);
                }
            }
        }

        /* 3. Atomic swap and cleanup */
        snprintf(cmd, sizeof(cmd), "ipset swap %s %s 2>/dev/null || true", set_name, tmp_set);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null || true", tmp_set);
        safe_system(cmd);

        /* 4. Determine steering mark or group load balancing */
        bool is_wan = (strcmp(al->target_type, "wan") == 0);
        if (is_wan) {
            /* Single WAN target */
            int target_wan_idx = -1;
            for (uint32_t w = 0; w < config->wan_count; w++) {
                if (config->wans[w].id == al->target_id ||
                    (al->target_name[0] && (strcmp(config->wans[w].label, al->target_name) == 0 ||
                                            strcmp(config->wans[w].name, al->target_name) == 0))) {
                    target_wan_idx = (int)w;
                    break;
                }
            }
            if (target_wan_idx >= 0) {
                uint32_t fwmark = 0x100 + target_wan_idx + 1;
                snprintf(cmd, sizeof(cmd),
                         "iptables -t mangle -A FLUXWAN_ADDRLIST -m set --match-set %s dst -j MARK --set-mark 0x%x 2>/dev/null || true",
                         set_name, fwmark);
                safe_system(cmd);
                snprintf(cmd, sizeof(cmd),
                         "iptables -t mangle -A FLUXWAN_ADDRLIST -m set --match-set %s dst -j CONNMARK --save-mark --mask 0x0000ffff 2>/dev/null || true",
                         set_name);
                safe_system(cmd);
                LOG_INFO("[Address List] List '%s' (%u entries) -> Steered to WAN %u (%s, mark 0x%x)",
                         al->name, added_count, config->wans[target_wan_idx].id, config->wans[target_wan_idx].label, fwmark);
            }
        } else {
            /* WAN Group target */
            int target_grp_idx = -1;
            for (uint32_t g = 0; g < config->group_count; g++) {
                if (config->groups[g].id == al->target_id ||
                    (al->target_name[0] && strcmp(config->groups[g].name, al->target_name) == 0)) {
                    target_grp_idx = (int)g;
                    break;
                }
            }

            if (target_grp_idx >= 0) {
                const wan_group_t *grp = &config->groups[target_grp_idx];
                uint32_t total_group_weight = 0;
                uint32_t active_member_indices[MAX_GROUP_MEMBERS];
                uint32_t active_member_count = 0;

                for (uint32_t m = 0; m < grp->wan_count; m++) {
                    uint32_t w_idx = grp->wan_member_indices[m];
                    if (w_idx < config->wan_count) {
                        const wan_config_t *w = &config->wans[w_idx];
                        if (w->enabled && w->state != WAN_STATE_DOWN && w->dynamic_weight > 0) {
                            active_member_indices[active_member_count++] = w_idx;
                            total_group_weight += w->dynamic_weight;
                        }
                    }
                }

                if (active_member_count == 1) {
                    /* Only 1 WAN active in group: direct mark */
                    uint32_t w_idx = active_member_indices[0];
                    uint32_t fwmark = 0x100 + w_idx + 1;
                    snprintf(cmd, sizeof(cmd),
                             "iptables -t mangle -A FLUXWAN_ADDRLIST -m set --match-set %s dst -j MARK --set-mark 0x%x 2>/dev/null || true",
                             set_name, fwmark);
                    safe_system(cmd);
                    snprintf(cmd, sizeof(cmd),
                             "iptables -t mangle -A FLUXWAN_ADDRLIST -m set --match-set %s dst -j CONNMARK --save-mark --mask 0x0000ffff 2>/dev/null || true",
                             set_name);
                    safe_system(cmd);
                    LOG_INFO("[Address List] List '%s' (%u entries) -> Steered to Group '%s' (WAN %s, mark 0x%x)",
                             al->name, added_count, grp->name, config->wans[w_idx].label, fwmark);
                } else if (active_member_count > 1 && total_group_weight > 0) {
                    /* Multiple WANs active in group: subchain with weighted distribution */
                    char subchain[80];
                    snprintf(subchain, sizeof(subchain), "FW_L_%s", set_name);
                    if (strlen(subchain) > 28) subchain[28] = '\0';

                    snprintf(cmd, sizeof(cmd), "iptables -t mangle -F %s 2>/dev/null || true", subchain);
                    safe_system(cmd);
                    snprintf(cmd, sizeof(cmd), "iptables -t mangle -N %s 2>/dev/null || true", subchain);
                    safe_system(cmd);

                    snprintf(cmd, sizeof(cmd),
                             "iptables -t mangle -A FLUXWAN_ADDRLIST -m set --match-set %s dst -j %s 2>/dev/null || true",
                             set_name, subchain);
                    safe_system(cmd);

                    uint32_t rem_weight = total_group_weight;
                    for (uint32_t mi = 0; mi < active_member_count; mi++) {
                        uint32_t w_idx = active_member_indices[mi];
                        const wan_config_t *w = &config->wans[w_idx];
                        uint32_t fwmark = 0x100 + w_idx + 1;

                        if (mi == active_member_count - 1 || rem_weight == w->dynamic_weight) {
                            snprintf(cmd, sizeof(cmd),
                                     "iptables -t mangle -A %s -m mark --mark 0 -j MARK --set-mark 0x%x 2>/dev/null || true",
                                     subchain, fwmark);
                        } else {
                            double prob = (double)w->dynamic_weight / (double)rem_weight;
                            snprintf(cmd, sizeof(cmd),
                                     "iptables -t mangle -A %s -m mark --mark 0 -m statistic --mode random --probability %.4f -j MARK --set-mark 0x%x 2>/dev/null || true",
                                     subchain, prob, fwmark);
                            rem_weight -= w->dynamic_weight;
                        }
                        safe_system(cmd);
                    }

                    snprintf(cmd, sizeof(cmd),
                             "iptables -t mangle -A %s -j CONNMARK --save-mark --mask 0x0000ffff 2>/dev/null || true",
                             subchain);
                    safe_system(cmd);

                    LOG_INFO("[Address List] List '%s' (%u entries) -> Balanced across Group '%s' (%u active WANs)",
                             al->name, added_count, grp->name, active_member_count);
                }
            }
        }
    }
#else
    LOG_INFO("[Simulation] Address Lists steering rules applied (%u lists configured)", config->address_list_count);
#endif
    return 0;
}

