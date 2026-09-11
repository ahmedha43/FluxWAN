#include "net_apply.h"
#include <fcntl.h>
#include <net/if.h>


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
#if defined(__linux__)
        char wan_up[128];
        if (w->enabled) {
            snprintf(wan_up, sizeof(wan_up), "ip link set %s up 2>/dev/null || true", w->name);
        } else {
            snprintf(wan_up, sizeof(wan_up), "ip link set %s down 2>/dev/null || true", w->name);
        }
        safe_system(wan_up);

        char tbl_f[64];
        snprintf(tbl_f, sizeof(tbl_f), "/run/fluxwan_table_%s", w->name);
        FILE *tf = fopen(tbl_f, "w");
        if (tf) { fprintf(tf, "%u\n", w->table_id); fclose(tf); }

        if (!w->enabled || w->type != WAN_TYPE_DHCP) {
            char stop_dhcp[256];
            snprintf(stop_dhcp, sizeof(stop_dhcp),
                     "if [ -f /run/udhcpc_%s.pid ]; then kill $(cat /run/udhcpc_%s.pid 2>/dev/null) 2>/dev/null || true; rm -f /run/udhcpc_%s.pid /run/fluxwan_wan_%s.lease; fi",
                     w->name, w->name, w->name, w->name);
            safe_system(stop_dhcp);
        }
#endif

        if (nl) {
            if (w_ifidx > 0) netlink_set_interface_state(nl, w_ifidx, w->enabled);
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
    }

#if defined(__linux__)
    /* 4. Configure Linux Kernel Mangle Rules with Conntrack Sticky Marks */
    safe_system("iptables -t mangle -F PREROUTING 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -j CONNMARK --restore-mark 2>/dev/null || true");

    /* Bypass Multi-WAN load balancing for local, broadcast and directly-connected subnets */
    safe_system("iptables -t mangle -A PREROUTING -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -d 10.10.0.0/16 -j RETURN 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -d 192.168.0.0/16 -j RETURN 2>/dev/null || true");
    safe_system("iptables -t mangle -A PREROUTING -d 172.16.0.0/12 -j RETURN 2>/dev/null || true");

    /* Calculate total active dynamic weight */
    uint32_t total_active_weight = 0;
    for (uint32_t i = 0; i < config->wan_count; i++) {
        if (config->wans[i].state != WAN_STATE_DOWN && config->wans[i].dynamic_weight > 0) {
            total_active_weight += config->wans[i].dynamic_weight;
        }
    }

    if (total_active_weight > 0) {
        uint32_t remaining_weight = total_active_weight;
        for (uint32_t i = 0; i < config->wan_count; i++) {
            const wan_config_t *w = &config->wans[i];
            if (w->state == WAN_STATE_DOWN || w->dynamic_weight == 0) continue;

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
    safe_system("iptables -t mangle -A PREROUTING -j CONNMARK --save-mark 2>/dev/null || true");
#endif

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

