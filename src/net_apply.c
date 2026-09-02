#include "net_apply.h"
#include <fcntl.h>
#include <net/if.h>

#if defined(__linux__)
static inline int safe_system(const char *cmd) {
    if (!cmd || cmd[0] == '\0') return -1;
    int rc = system(cmd);
    (void)rc; /* Acknowledged exit code */
    return rc;
}
#else
static inline int safe_system(const char *cmd) {
    (void)cmd;
    return 0;
}
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
    safe_system("sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1");
    safe_system("sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1");
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
    snprintf(ip_cmd, sizeof(ip_cmd), "ip addr replace %s/24 dev %s 2>/dev/null || ip addr add %s/24 dev %s 2>/dev/null; ip link set %s up 2>/dev/null", lan_ip, config->lan.name, lan_ip, config->lan.name, config->lan.name);
    safe_system(ip_cmd);
#endif

    /* 3. Configure Multi-WAN Interfaces & Policy Tables */
    for (uint32_t i = 0; i < config->wan_count; i++) {
        const wan_config_t *w = &config->wans[i];
        char wan_ip[32], wan_gw[32];
        ip_to_str(w->ip_addr, wan_ip, sizeof(wan_ip));
        ip_to_str(w->gateway, wan_gw, sizeof(wan_gw));

        LOG_INFO("[Kernel Netlink] Setting WAN %u (%s) -> Type: %d, IP: %s, GW: %s, Table: %u",
                 w->id, w->name, w->type, wan_ip, wan_gw, w->table_id);

        if (nl) {
            netlink_set_interface_state(nl, w->ifindex, true);
            if (w->type == WAN_TYPE_STATIC && w->ip_addr != 0) {
                netlink_set_interface_ip(nl, w->ifindex, w->ip_addr, w->netmask);
            }

            /* Create Policy Route Table & Rule */
            uint32_t fwmark = 0x100 + i + 1;
            netlink_add_ip_rule(nl, fwmark, w->table_id, 1000 + i);
            if (w->gateway != 0) {
                netlink_add_default_route(nl, w->table_id, w->gateway, w->ifindex);
            }
        }

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
