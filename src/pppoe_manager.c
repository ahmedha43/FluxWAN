/*
 * FluxWAN Real PPPoE Session Manager
 * ====================================
 * Manages real Linux PPPoE clients via pppd + rp-pppoe kernel/userspace plugin.
 */

#include "pppoe_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32) && !defined(_WIN64)
#include <sys/wait.h>
#include <arpa/inet.h>
#include <net/if.h>
#endif

#define PPPOE_INITIAL_BACKOFF_S 15
#define PPPOE_MAX_BACKOFF_S     120

static inline void safe_str_copy(char *dst, const char *src, size_t max_len) {
    if (!dst || max_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t slen = strlen(src);
    if (slen >= max_len) slen = max_len - 1;
    memcpy(dst, src, slen);
    dst[slen] = '\0';
}

#if defined(__linux__)
static inline int safe_system(const char *cmd) {
    if (!cmd || cmd[0] == '\0') return -1;
    int rc = system(cmd);
    (void)rc;
    return rc;
}
#endif

static uint64_t get_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (ts.tv_nsec / 1000000ULL);
}

const char *pppoe_state_str(pppoe_state_t s) {
    switch (s) {
        case PPPOE_STATE_IDLE:         return "IDLE";
        case PPPOE_STATE_DIALING:      return "DIALING";
        case PPPOE_STATE_AUTH:         return "AUTHENTICATING";
        case PPPOE_STATE_CONNECTED:    return "CONNECTED";
        case PPPOE_STATE_DISCONNECTED: return "DISCONNECTED";
        case PPPOE_STATE_RECONNECTING: return "RECONNECTING";
        case PPPOE_STATE_STOPPING:     return "STOPPING";
        default:                       return "UNKNOWN";
    }
}

pppoe_manager_ctx_t *pppoe_manager_init(void) {
    pppoe_manager_ctx_t *pctx = (pppoe_manager_ctx_t *)calloc(1, sizeof(pppoe_manager_ctx_t));
    if (!pctx) {
        LOG_ERROR("Failed to allocate pppoe_manager_ctx_t");
        return NULL;
    }
    for (int i = 0; i < MAX_WANS; i++) {
        pctx->sessions[i].wan_index = i;
        pctx->sessions[i].state = PPPOE_STATE_IDLE;
        pctx->sessions[i].pppd_pid = -1;
        pctx->sessions[i].backoff_s = PPPOE_INITIAL_BACKOFF_S;
        snprintf(pctx->sessions[i].opts_path, sizeof(pctx->sessions[i].opts_path), "/tmp/fluxwan_ppp%d.opts", i);
        snprintf(pctx->sessions[i].pid_file, sizeof(pctx->sessions[i].pid_file), "/tmp/fluxwan_ppp%d.pid", i);
    }
    LOG_INFO("PPPoE Session Manager initialized (support for multi-session per physical port).");
    return pctx;
}

pppoe_session_t *pppoe_get_session(pppoe_manager_ctx_t *pctx, int wan_index) {
    if (!pctx || wan_index < 0 || wan_index >= MAX_WANS) return NULL;
    return &pctx->sessions[wan_index];
}

/* Helper to parse IP and gateway from Linux /proc/net/route or ip addr */
static bool get_ppp_interface_ip(const char *ifname, uint32_t *out_ip, uint32_t *out_gw, char *out_ip_str, char *out_gw_str) {
#if defined(__linux__)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip -4 -o addr show %s 2>/dev/null | awk '{print $4}' | cut -d/ -f1", ifname);
    FILE *fp = popen(cmd, "r");
    if (!fp) return false;

    char ip_buf[64] = {0};
    if (fgets(ip_buf, sizeof(ip_buf), fp)) {
        char *nl = strchr(ip_buf, '\n');
        if (nl) *nl = '\0';
    }
    pclose(fp);

    if (strlen(ip_buf) == 0) return false;

    /* Get remote peer / gateway */
    char gw_buf[64] = {0};
    snprintf(cmd, sizeof(cmd), "ip -4 -o addr show %s 2>/dev/null | awk '{print $6}' | cut -d/ -f1", ifname);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(gw_buf, sizeof(gw_buf), fp)) {
            char *nl = strchr(gw_buf, '\n');
            if (nl) *nl = '\0';
        }
        pclose(fp);
    }

    if (strlen(gw_buf) == 0) {
        /* Fallback peer gateway detection */
        safe_str_copy(gw_buf, ip_buf, sizeof(gw_buf));
        char *last_dot = strrchr(gw_buf, '.');
        if (last_dot) {
            *(last_dot + 1) = '1';
            *(last_dot + 2) = '\0';
        }
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_buf, &addr) == 1) {
        *out_ip = ntohl(addr.s_addr);
        if (out_ip_str) safe_str_copy(out_ip_str, ip_buf, 20);
    } else {
        return false;
    }

    if (inet_pton(AF_INET, gw_buf, &addr) == 1) {
        *out_gw = ntohl(addr.s_addr);
        if (out_gw_str) safe_str_copy(out_gw_str, gw_buf, 20);
    } else {
        *out_gw = *out_ip;
        if (out_gw_str) safe_str_copy(out_gw_str, ip_buf, 20);
    }

    return true;
#else
    (void)ifname;
    *out_ip = (10 << 24) | (100 << 16) | 1;
    *out_gw = (10 << 24) | (100 << 16) | 254;
    if (out_ip_str) strcpy(out_ip_str, "10.100.0.1");
    if (out_gw_str) strcpy(out_gw_str, "10.100.0.254");
    return true;
#endif
}

static void generate_unique_virtual_mac(int wan_index, const char *parent_ifname, char *out_mac_str) {
    /* 
     * Locally Administered Unicast MAC (Bit 1 of byte 0 is 1, Bit 0 is 0 -> 0x02)
     * Combines hash of parent interface name + wan_index to guarantee a 100% unique MAC per session
     */
    uint32_t h = 0x811c9dc5;
    for (const char *p = parent_ifname; p && *p; p++) {
        h = (h ^ (uint8_t)*p) * 0x01000193;
    }
    uint8_t b1 = 0x02; /* Locally Administered Unicast */
    uint8_t b2 = (uint8_t)((h >> 16) & 0xFE);
    uint8_t b3 = (uint8_t)((h >> 8) & 0xFF);
    uint8_t b4 = (uint8_t)(h & 0xFF);
    uint8_t b5 = (uint8_t)(((wan_index + 1) * 0x2B) & 0xFF);
    uint8_t b6 = (uint8_t)(((wan_index + 1) * 0x3F) & 0xFF);

    snprintf(out_mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x", b1, b2, b3, b4, b5, b6);
}

int pppoe_session_start(pppoe_manager_ctx_t *pctx, int wan_index, const wan_config_t *wan) {
    if (!pctx || !wan || wan_index < 0 || wan_index >= MAX_WANS) return -1;
    pppoe_session_t *sess = &pctx->sessions[wan_index];

    if (sess->state == PPPOE_STATE_CONNECTED || sess->state == PPPOE_STATE_DIALING) {
        LOG_WARN("[PPPoE WAN%d] Session already active (State: %s)", wan_index + 1, pppoe_state_str(sess->state));
        return 0;
    }

    /* Stop previous instance if any */
    pppoe_session_stop(pctx, wan_index);

    /* Generate unique PPP interface unit name: ppp<wan_index> */
    snprintf(sess->ppp_ifname, sizeof(sess->ppp_ifname), "ppp%d", wan_index);

#if defined(__linux__)
    /* 1. Generate Virtual MAC and create dedicated MACVLAN sub-interface */
    snprintf(sess->macvlan_ifname, sizeof(sess->macvlan_ifname), "mv_wan%d", wan_index);
    generate_unique_virtual_mac(wan_index, wan->name, sess->virtual_mac);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link delete %s 2>/dev/null || true", sess->macvlan_ifname);
    safe_system(cmd);

    snprintf(cmd, sizeof(cmd), "ip link add link %s name %s address %s type macvlan mode private 2>/dev/null",
             wan->name, sess->macvlan_ifname, sess->virtual_mac);
    safe_system(cmd);

    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", sess->macvlan_ifname);
    safe_system(cmd);

    LOG_INFO("[PPPoE WAN%d] Preparing PPPoE Dialing on Virtual MACVLAN: %s (Parent: %s | Unique MAC: %s | User: %s)...",
             wan_index + 1, sess->macvlan_ifname, wan->name, sess->virtual_mac, wan->ppp_username);

    /* 2. Ensure secrets & global plugin options exist */
    mkdir("/etc/ppp", 0755);
    FILE *opt_fp = fopen("/etc/ppp/options", "a+");
    if (opt_fp) {
        fprintf(opt_fp, "plugin /usr/lib/pppd/2.5.0/pppoe.so\n");
        fclose(opt_fp);
    }
    FILE *sec_fp = fopen("/etc/ppp/pap-secrets", "a+");
    if (sec_fp) {
        fprintf(sec_fp, "\"%s\" * \"%s\" *\n", wan->ppp_username, wan->ppp_password);
        fclose(sec_fp);
        chmod("/etc/ppp/pap-secrets", 0600);
    }
    sec_fp = fopen("/etc/ppp/chap-secrets", "a+");
    if (sec_fp) {
        fprintf(sec_fp, "\"%s\" * \"%s\" *\n", wan->ppp_username, wan->ppp_password);
        fclose(sec_fp);
        chmod("/etc/ppp/chap-secrets", 0600);
    }

    /* 3. Write custom pppd options file targeting the dedicated MACVLAN interface */
    FILE *opts_fp = fopen(sess->opts_path, "w");
    if (!opts_fp) {
        LOG_ERROR("[PPPoE WAN%d] Failed to write options file %s", wan_index + 1, sess->opts_path);
        return -1;
    }

    fprintf(opts_fp, "plugin /usr/lib/pppd/2.5.0/pppoe.so\n");
    fprintf(opts_fp, "nic-%s\n", sess->macvlan_ifname);
    fprintf(opts_fp, "user \"%s\"\n", wan->ppp_username);
    fprintf(opts_fp, "password \"%s\"\n", wan->ppp_password);
    fprintf(opts_fp, "unit %d\n", wan_index);
    fprintf(opts_fp, "noauth\n");
    fprintf(opts_fp, "nodefaultroute\n");
    fprintf(opts_fp, "usepeerdns\n");
    fprintf(opts_fp, "persist\n");
    fprintf(opts_fp, "maxfail 0\n");
    fprintf(opts_fp, "holdoff 5\n");
    fprintf(opts_fp, "mtu 1492\n");
    fprintf(opts_fp, "mru 1492\n");
    fprintf(opts_fp, "lcp-echo-interval 10\n");
    fprintf(opts_fp, "lcp-echo-failure 3\n");
    fprintf(opts_fp, "linkname fluxwan_ppp%d\n", wan_index);
    fprintf(opts_fp, "nodetach\n");
    fclose(opts_fp);

    /* 4. Launch pppd process */
    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERROR("[PPPoE WAN%d] fork() failed: %s", wan_index + 1, strerror(errno));
        return -1;
    } else if (pid == 0) {
        int dev_null = open("/dev/null", O_RDWR);
        if (dev_null >= 0) {
            dup2(dev_null, STDIN_FILENO);
            close(dev_null);
        }
        execlp("pppd", "pppd", "file", sess->opts_path, (char *)NULL);
        execl("/usr/sbin/pppd", "pppd", "file", sess->opts_path, (char *)NULL);
        execl("/sbin/pppd", "pppd", "file", sess->opts_path, (char *)NULL);
        _exit(127);
    }

    sess->pppd_pid = pid;
    sess->state = PPPOE_STATE_DIALING;
    sess->dial_start_ms = get_now_ms();
    sess->next_retry_ms = 0;

    FILE *pid_fp = fopen(sess->pid_file, "w");
    if (pid_fp) {
        fprintf(pid_fp, "%d\n", (int)pid);
        fclose(pid_fp);
    }

    LOG_INFO("[PPPoE WAN%d] Started pppd (PID: %d) on %s (MAC: %s) -> %s",
             wan_index + 1, (int)pid, sess->macvlan_ifname, sess->virtual_mac, sess->ppp_ifname);
#else
    sess->state = PPPOE_STATE_CONNECTED;
    sess->assigned_ip = (10 << 24) | (100 << 16) | (wan_index + 1);
    sess->remote_ip = (10 << 24) | (100 << 16) | 254;
    snprintf(sess->assigned_ip_str, sizeof(sess->assigned_ip_str), "10.100.%d.2", wan_index + 1);
    snprintf(sess->remote_ip_str, sizeof(sess->remote_ip_str), "10.100.%d.1", wan_index + 1);
    LOG_INFO("[PPPoE Simulation WAN%d] Connected -> IP: %s GW: %s",
             wan_index + 1, sess->assigned_ip_str, sess->remote_ip_str);
#endif

    return 0;
}

int pppoe_session_stop(pppoe_manager_ctx_t *pctx, int wan_index) {
    if (!pctx || wan_index < 0 || wan_index >= MAX_WANS) return -1;
    pppoe_session_t *sess = &pctx->sessions[wan_index];

    if (sess->pppd_pid > 0) {
        LOG_INFO("[PPPoE WAN%d] Terminating pppd process (PID: %d)...", wan_index + 1, (int)sess->pppd_pid);
#if defined(__linux__)
        kill(sess->pppd_pid, SIGTERM);
        usleep(50000); /* 50ms */
        kill(sess->pppd_pid, SIGKILL);
        waitpid(sess->pppd_pid, NULL, WNOHANG);
#endif
        sess->pppd_pid = -1;
    }

#if defined(__linux__)
    if (sess->macvlan_ifname[0] != '\0') {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip link delete %s 2>/dev/null || true", sess->macvlan_ifname);
        system(cmd);
    }
#endif

    unlink(sess->opts_path);
    unlink(sess->pid_file);

    sess->state = PPPOE_STATE_IDLE;
    sess->assigned_ip = 0;
    sess->remote_ip = 0;
    sess->assigned_ip_str[0] = '\0';
    sess->remote_ip_str[0] = '\0';

    return 0;
}

void pppoe_manager_start_all(pppoe_manager_ctx_t *pctx, fluxwan_config_t *config) {
    if (!pctx || !config) return;
    for (uint32_t i = 0; i < config->wan_count; i++) {
        if (config->wans[i].type == WAN_TYPE_PPPOE && config->wans[i].enabled) {
            pppoe_session_start(pctx, (int)i, &config->wans[i]);
        }
    }
}

void pppoe_manager_tick(pppoe_manager_ctx_t *pctx,
                        fluxwan_config_t *config,
                        pppoe_on_connected_fn    on_connected,
                        pppoe_on_disconnected_fn on_disconnected,
                        void *userdata) {
    if (!pctx || !config) return;
    uint64_t now_ms = get_now_ms();

    for (uint32_t i = 0; i < config->wan_count; i++) {
        wan_config_t *w = &config->wans[i];
        if (w->type != WAN_TYPE_PPPOE) continue;

        pppoe_session_t *sess = &pctx->sessions[i];

        /* If WAN was disabled administratively, ensure pppd is stopped */
        if (!w->enabled) {
            if (sess->state != PPPOE_STATE_IDLE && sess->state != PPPOE_STATE_STOPPING) {
                pppoe_session_stop(pctx, (int)i);
            }
            continue;
        }

        /* Check if process is still running */
#if defined(__linux__)
        if (sess->pppd_pid > 0) {
            int status = 0;
            pid_t res = waitpid(sess->pppd_pid, &status, WNOHANG);
            if (res > 0 || (res < 0 && errno == ECHILD)) {
                /* pppd exited */
                LOG_WARN("[PPPoE WAN%d] pppd process (PID %d) terminated unexpectedly.",
                         i + 1, (int)sess->pppd_pid);
                sess->pppd_pid = -1;
                sess->state = PPPOE_STATE_DISCONNECTED;
                sess->reconnect_attempts++;

                /* Calculate exponential backoff */
                uint32_t delay_s = sess->backoff_s;
                sess->backoff_s = (sess->backoff_s * 2 > PPPOE_MAX_BACKOFF_S) ? PPPOE_MAX_BACKOFF_S : (sess->backoff_s * 2);
                sess->next_retry_ms = now_ms + ((uint64_t)delay_s * 1000ULL);

                LOG_INFO("[PPPoE WAN%d] Auto-reconnect scheduled in %u seconds (Attempt #%d)...",
                         i + 1, delay_s, sess->reconnect_attempts);

                if (on_disconnected) {
                    on_disconnected((int)i, sess->ppp_ifname, sess->reconnect_attempts, userdata);
                }
            }
        }
#endif

        /* State Machine Transitions */
        switch (sess->state) {
            case PPPOE_STATE_IDLE:
                pppoe_session_start(pctx, (int)i, w);
                break;

            case PPPOE_STATE_DIALING:
            case PPPOE_STATE_AUTH: {
                /* Check if PPP interface acquired IP address */
                uint32_t ip = 0, gw = 0;
                char ip_str[32] = {0}, gw_str[32] = {0};
                if (get_ppp_interface_ip(sess->ppp_ifname, &ip, &gw, ip_str, gw_str)) {
                    sess->assigned_ip = ip;
                    sess->remote_ip = gw;
                    safe_str_copy(sess->assigned_ip_str, ip_str, sizeof(sess->assigned_ip_str));
                    safe_str_copy(sess->remote_ip_str, gw_str, sizeof(sess->remote_ip_str));
                    sess->state = PPPOE_STATE_CONNECTED;
                    sess->connected_since_ms = now_ms;
                    sess->backoff_s = PPPOE_INITIAL_BACKOFF_S;
                    sess->reconnect_attempts = 0;

                    LOG_INFO("[PPPoE WAN%d] 🎉 SESSION ESTABLISHED on %s -> Local IP: %s, Gateway: %s",
                             i + 1, sess->ppp_ifname, ip_str, gw_str);

                    /* Update WAN configuration with acquired IP and gateway */
                    w->ip_addr = htonl(ip);
                    w->gateway = htonl(gw);
                    w->netmask = htonl(0xFFFFFFFF); /* /32 Point-to-point */
                    safe_str_copy(w->probe_target, gw_str, sizeof(w->probe_target));
                    w->probe_target_ip = htonl(gw);

                    if (on_connected) {
                        on_connected((int)i, sess->ppp_ifname, ip, gw, userdata);
                    }
                } else if (now_ms - sess->dial_start_ms > 45000) {
                    /* Timeout: 45s without IP assignment -> restart dial */
                    LOG_WARN("[PPPoE WAN%d] Dialing timeout (45s) on %s. Retrying...", i + 1, sess->ppp_ifname);
                    pppoe_session_stop(pctx, (int)i);
                    sess->state = PPPOE_STATE_RECONNECTING;
                    sess->next_retry_ms = now_ms + 5000;
                }
                break;
            }

            case PPPOE_STATE_CONNECTED: {
                /* Periodically verify carrier link */
                if (now_ms - sess->last_check_ms >= 5000) {
                    sess->last_check_ms = now_ms;
                    uint32_t ip = 0, gw = 0;
                    if (!get_ppp_interface_ip(sess->ppp_ifname, &ip, &gw, NULL, NULL)) {
                        LOG_WARN("[PPPoE WAN%d] PPP interface %s lost carrier IP address.", i + 1, sess->ppp_ifname);
                        sess->state = PPPOE_STATE_DISCONNECTED;
                        sess->next_retry_ms = now_ms + 5000;
                        if (on_disconnected) {
                            on_disconnected((int)i, sess->ppp_ifname, sess->reconnect_attempts, userdata);
                        }
                    }
                }
                break;
            }

            case PPPOE_STATE_DISCONNECTED:
            case PPPOE_STATE_RECONNECTING:
                if (now_ms >= sess->next_retry_ms && w->enabled) {
                    LOG_INFO("[PPPoE WAN%d] Executing Auto-Reconnect on %s...", i + 1, w->name);
                    pppoe_session_start(pctx, (int)i, w);
                }
                break;

            case PPPOE_STATE_STOPPING:
                pppoe_session_stop(pctx, (int)i);
                break;
        }
    }
}

void pppoe_manager_destroy(pppoe_manager_ctx_t *pctx) {
    if (!pctx) return;
    for (int i = 0; i < MAX_WANS; i++) {
        pppoe_session_stop(pctx, i);
    }
    free(pctx);
    LOG_INFO("PPPoE Session Manager cleanly shut down.");
}
