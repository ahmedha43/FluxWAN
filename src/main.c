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

int main(int argc, char *argv[]) {
    const char *config_path = "config/fluxwan.json";
    if (argc > 1) {
        config_path = argv[1];
    }

    printf("===============================================================\n");
    printf("   FluxWAN - Bare-Metal x86 Linux Multi-WAN Router v%s   \n", FLUXWAN_VERSION);
    printf("===============================================================\n");
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Register Signal Handlers */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#if !defined(_WIN32) && !defined(_WIN64)
    signal(SIGPIPE, SIG_IGN);
#endif

#if defined(_WIN32) || defined(_WIN64)
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    /* 1. Load Configuration */
    fluxwan_config_t config;
    if (config_load(config_path, &config) < 0) {
        LOG_ERROR("Fatal: Failed to load configuration from %s", config_path);
        return EXIT_FAILURE;
    }
    config_print(&config);

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

    /* 11. Initialize Embedded Web Server & REST Engine */
    web_server_ctx_t *web = web_server_init(&config, nl, dhcp);

    LOG_INFO("FluxWAN Core Daemon fully initialized and running on Bare-Metal reactor loop...");

    uint64_t last_probe_ms = 0;
    uint64_t last_sticky_ms = 0;

    /* Main Non-Blocking Event Reactor Loop */
    while (g_running) {
        struct pollfd fds[4];
        int nfds = 0;

        socket_t web_fd = web_server_get_fd(web);
        if (IS_VALID_SOCK(web_fd)) {
            fds[nfds].fd = (int)web_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

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
                    if ((socket_t)fds[i].fd == web_fd) {
                        socket_t client_fd = web_server_accept_client(web);
                        if (IS_VALID_SOCK(client_fd)) {
                            web_server_process_client(web, client_fd);
                        }
                    } else if (IS_VALID_SOCK(dhcp_fd) && (socket_t)fds[i].fd == dhcp_fd) {
                        dhcp_server_process(dhcp);
                    } else if (IS_VALID_SOCK(nl_fd) && (socket_t)fds[i].fd == nl_fd) {
                        netlink_process_events(nl, &config);
                    } else if (IS_VALID_SOCK(prober_fd) && (socket_t)fds[i].fd == prober_fd) {
                        prober_process_responses(prober);
                    }
                }
            }
        }

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
    }

    LOG_INFO("Shutting down FluxWAN Router Engine...");

    /* Graceful Cleanup */
    if (dns64) dns64_destroy(dns64);
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
