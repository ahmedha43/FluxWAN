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

#include "fluxwan.h"
#include "config.h"
#include "netlink_manager.h"
#include "bpf_loader.h"
#include "prober.h"
#include "wan_manager.h"
#include "sticky.h"
#include "web_server.h"
#include "net_discovery.h"
#include "net_apply.h"
#include "dhcp_server.h"
#include "dns64_daemon.h"
#include "pppoe_server.h"
#include "vpn_manager.h"
#include "license_manager.h"
#include "proxy_manager.h"

#include <signal.h>
#if defined(_WIN32) || defined(_WIN64)
#define poll WSAPoll
#else
#include <poll.h>
#endif

static volatile bool g_running = true;

static void handle_signal(int sig) {
    (void)sig;
    g_running = false;
}

#if defined(__linux__)
static void self_healing_watchdog_tick(fluxwan_config_t *config, wan_manager_ctx_t *wan_mgr) {
    if (!config) return;
    (void)wan_mgr;

    /* 1. Ensure Kernel Packet Forwarding is ALWAYS Enabled */
    safe_write_proc("/proc/sys/net/ipv4/ip_forward", "1");

    /* 2. Self-Healing Firewall & NAT Masquerade */
    for (uint32_t i = 0; i < config->wan_count; i++) {
        wan_config_t *w = &config->wans[i];
        if (w->enabled && w->state != WAN_STATE_DOWN) {
            /* Verify Loose Mode Reverse Path Filter */
            char rp_path[128];
            snprintf(rp_path, sizeof(rp_path), "/proc/sys/net/ipv4/conf/%s/rp_filter", w->name);
            safe_write_proc(rp_path, "2");

            /* Verify Outbound NAT Masquerade */
            char check_nat[256];
            snprintf(check_nat, sizeof(check_nat),
                     "iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || "
                     "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true",
                     w->name, w->name);
            safe_system(check_nat);

            if (w->proxy.enabled && w->proxy.tun_dev[0]) {
                char check_tun_nat[256];
                snprintf(check_tun_nat, sizeof(check_tun_nat),
                         "iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || "
                         "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true",
                         w->proxy.tun_dev, w->proxy.tun_dev);
                safe_system(check_tun_nat);
            }
        }
    }

    /* 3. Self-Cleaning Storage & Ramdisk Watchdog:
     * Truncate oversized log files (> 2MB) in /var/log and remove stale tmp files */
    safe_system("for f in /var/log/fluxwan*.log /tmp/*.log; do "
                "  [ -f \"$f\" ] && [ $(wc -c < \"$f\" 2>/dev/null || echo 0) -gt 2097152 ] && : > \"$f\"; "
                "done 2>/dev/null || true");
    safe_system("rm -f /tmp/fluxwan_test_cfg.json /tmp/fluxwan_version.json 2>/dev/null || true");

    /* 4. DNS Fallback Health Check */
    if (access("/etc/resolv.conf", R_OK) != 0 || access("/etc/resolv.conf", W_OK) == 0) {
        FILE *rf = fopen("/etc/resolv.conf", "r");
        bool has_ns = false;
        if (rf) {
            char line[128];
            while (fgets(line, sizeof(line), rf)) {
                if (strncmp(line, "nameserver", 10) == 0) {
                    has_ns = true;
                    break;
                }
            }
            fclose(rf);
        }
        if (!has_ns) {
            FILE *wf = fopen("/etc/resolv.conf", "w");
            if (wf) {
                fputs("nameserver 1.1.1.1\nnameserver 8.8.8.8\n", wf);
                fclose(wf);
                LOG_WARN("[Watchdog] Restored missing fallback DNS resolvers in /etc/resolv.conf");
            }
        }
    }
}
#else
static void self_healing_watchdog_tick(fluxwan_config_t *config, wan_manager_ctx_t *wan_mgr) {
    (void)config; (void)wan_mgr;
}
#endif

int main(int argc, char *argv[]) {
    const char *config_path = "config/fluxwan.json";
    if (argc > 1) {
        config_path = argv[1];
    }

    printf("===============================================================\n");
    printf("   FluxWAN - Bare-Metal Linux Multi-WAN Carrier Router v%s     \n", FLUXWAN_VERSION);
    printf("   Developed by %s                     \n", FLUXWAN_AUTHOR);
    printf("   License: %s | %s\n", FLUXWAN_LICENSE, FLUXWAN_COPYRIGHT);
    printf("===============================================================\n");
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Register Signal Handlers */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#if !defined(_WIN32) && !defined(_WIN64)
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN); /* Automatically reap all terminated child processes */
#endif

#if defined(_WIN32) || defined(_WIN64)
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    safe_system("depmod -a 2>/dev/null || true; "
                "modprobe af_packet 2>/dev/null || modprobe packet 2>/dev/null || "
                "insmod $(find /lib/modules -name 'af_packet.ko*' 2>/dev/null | head -n 1) 2>/dev/null || true");
    safe_system("modprobe nf_nat 2>/dev/null || true");
#endif

    /* 1. Load Configuration */
    static fluxwan_config_t config;
    if (config_load(config_path, &config) < 0) {
        LOG_ERROR("Fatal: Failed to load configuration from %s", config_path);
        return EXIT_FAILURE;
    }
    config_print(&config);

    /* Initialize Cryptographic Licensing Engine */
    license_manager_init(&config.license);
    LOG_INFO("Licensing Engine: Status=[%s], Type=[%s], Client=[%s], Days Remaining=[%u], Grace=[%us]",
             config.license.status_str, config.license.type_str,
             config.license.client_name, config.license.days_remaining,
             config.license.grace_seconds_remaining);

    /* 2. Hardware Interface Discovery */
    iface_discovery_result_t disc;
    net_discovery_scan(&config, &disc);

    /* 3. Initialize Netlink Policy Routing Manager */
    netlink_ctx_t *nl = netlink_init();

    /* 4. Apply Network & Kernel Routing Topology */
    net_apply_configuration(&config, nl);

    /* 5. Initialize eBPF / XDP Loader */
    bpf_loader_ctx_t *bpf = bpf_loader_init("bpf/xdp_router.bpf.o");

    /* 6. Initialize WAN Manager & Dynamic Rebalancer */
    wan_manager_ctx_t *wan_mgr = wan_manager_init(&config, nl, bpf);

    /* 7. Initialize Sticky Session Engine */
    sticky_table_t *sticky = NULL;
    if (config.sticky.enabled) {
        sticky = sticky_table_init(16384, config.sticky.timeout_seconds);
    }

    /* 8. Initialize Embedded RFC 2131 DHCP Server for LAN */
    dhcp_server_ctx_t *dhcp = dhcp_server_init(&config);

    /* 9. Initialize Dynamic Health Prober */
    prober_ctx_t *prober = prober_init(&config, wan_manager_on_health_update, wan_mgr);

    /* 10. Initialize Embedded DNS64 / NAT46 Starlink Bypass Engine */
    dns64_ctx_t *dns64 = NULL;
    if (config.nat46.enabled) {
        dns64 = dns64_init(&config, -1, -1, -1);
    }

    /* 11. Initialize Broadband PPPoE Server (BRAS) */
    pppoe_server_ctx_t *pppoe_srv = pppoe_server_init(&config);
    if (config.pppoe_server.enabled) {
        pppoe_server_start(pppoe_srv);
    }

    /* 12. Initialize VPN Subsystem (WireGuard & ZeroTier) */
    vpn_manager_init(&config.vpn);
    vpn_manager_apply(&config.vpn);

    /* 13. Initialize Outbound Proxy Subsystem (Xray / Zero-Rating Engine) */
    proxy_manager_ctx_t *proxy_mgr = proxy_manager_init(&config);
    if (proxy_mgr) {
        proxy_manager_apply(proxy_mgr);
    }

    /* 14. Initialize Embedded Web Server & REST Engine */
    web_server_ctx_t *web = web_server_init(&config, nl, dhcp);
    web_server_set_wan_manager(web, wan_mgr);
    web_server_set_pppoe_server(web, pppoe_srv);
    web_server_set_proxy_manager(web, proxy_mgr);
    web_server_start_thread(web);

    LOG_INFO("FluxWAN Core Daemon fully initialized and running on Bare-Metal reactor loop...");

    uint64_t last_probe_ms = 0;
    uint64_t last_sticky_ms = 0;
    uint64_t last_watchdog_ms = 0;

    /* Main Non-Blocking Event Reactor Loop */
    while (g_running) {
        struct pollfd fds[3];
        int nfds = 0;

        socket_t dhcp_fd = dhcp_server_get_fd(dhcp);
        if (IS_VALID_SOCK(dhcp_fd)) {
            fds[nfds].fd = (int)dhcp_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        socket_t nl_fd = (socket_t)netlink_get_fd(nl);
        if (IS_VALID_SOCK(nl_fd)) {
            fds[nfds].fd = (int)nl_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        socket_t prober_fd = (socket_t)prober_get_fd(prober);
        if (IS_VALID_SOCK(prober_fd)) {
            fds[nfds].fd = (int)prober_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        int poll_res = poll(fds, nfds, 100); /* 100ms timeout for timer ticks */

        if (poll_res > 0) {
            for (int i = 0; i < nfds; i++) {
                if (fds[i].revents & POLLIN) {
                    if (IS_VALID_SOCK(dhcp_fd) && (socket_t)fds[i].fd == dhcp_fd) {
                        dhcp_server_process(dhcp);
                    } else if (IS_VALID_SOCK(nl_fd) && (socket_t)fds[i].fd == nl_fd) {
                        netlink_process_events(nl, &config);
                    } else if (IS_VALID_SOCK(prober_fd) && (socket_t)fds[i].fd == prober_fd) {
                        prober_process_responses(prober);
                    }
                }
            }
        }

        /* Drain any pending ICMP prober responses across all WAN sockets */
        prober_process_responses(prober);

        /* Periodic Timer: Dynamic Prober Trigger */
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_ms = (uint64_t)ts.tv_sec * 1000ULL + (ts.tv_nsec / 1000000ULL);

        if (now_ms - last_probe_ms >= config.prober.interval_ms) {
            prober_send_probes(prober);
            last_probe_ms = now_ms;
        }

        /* Periodic Timer: Sticky Table Cleanup */
        if (sticky && (now_ms - last_sticky_ms >= 10000)) {
            sticky_cleanup_expired(sticky);
            last_sticky_ms = now_ms;
        }

        /* Periodic Timer: WAN Manager Tick (DHCP Lease & PPPoE Auto-Reconnect) */
        wan_manager_periodic_tick(wan_mgr, now_ms);

        /* Periodic Timer: Broadband PPPoE Server Subscriber Tick (Expiry & Session Enforcement) */
        if (pppoe_srv) {
            pppoe_server_periodic_tick(pppoe_srv, now_ms);
        }

        /* Periodic Timer: Licensing Engine Tick (Clock Rollback & Grace Period Tracking) */
        license_manager_tick(&config.license, now_ms);

        /* Periodic Timer: Outbound Proxy Manager Tick (Supervision & Auto-Restart) */
        if (proxy_mgr) {
            proxy_manager_tick(proxy_mgr);
        }

        /* Periodic Timer: 24/7 Self-Healing Watchdog (Firewall, NAT, Storage & DNS Recovery) */
        if (now_ms - last_watchdog_ms >= 30000) {
            self_healing_watchdog_tick(&config, wan_mgr);
            last_watchdog_ms = now_ms;
        }
    }

    LOG_INFO("Shutting down FluxWAN Router Engine...");

    /* Graceful Cleanup */
    if (proxy_mgr) proxy_manager_close(proxy_mgr);
    if (dns64) dns64_destroy(dns64);
    if (pppoe_srv) pppoe_server_close(pppoe_srv);
    web_server_close(web);
    prober_close(prober);
    if (dhcp) dhcp_server_close(dhcp);
    if (sticky) sticky_table_destroy(sticky);
    wan_manager_close(wan_mgr);
    bpf_loader_close(bpf);
    netlink_close(nl);

    LOG_INFO("Shutdown complete. Goodbye!");
    return EXIT_SUCCESS;
}
