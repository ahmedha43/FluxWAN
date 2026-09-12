#include "prober.h"
#include <math.h>
#if !defined(_WIN32) && !defined(_WIN64)
#include <fcntl.h>
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#if defined(__linux__)
#include <netinet/ip_icmp.h>
#else
/* ICMP Header definitions for non-Linux compilation check */
struct icmphdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
    } un;
};
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#endif

typedef struct {
    uint16_t seq;
    uint64_t send_time_us;
    bool received;
} probe_slot_t;

typedef struct {
    uint32_t wan_idx;
    uint32_t target_ip;
    uint16_t current_seq;
    uint64_t rtt_history[PROBE_WINDOW_SIZE];
    bool loss_history[PROBE_WINDOW_SIZE];
    uint32_t history_idx;
    probe_slot_t pending_probes[16];
} wan_probe_state_t;

struct prober_ctx {
    int raw_fd;                  /* Global listening raw ICMP socket */
    int wan_send_fds[MAX_WANS];  /* Interface-bound dedicated sockets */
    fluxwan_config_t *config;
    wan_health_callback_t callback;
    void *user_data;
    wan_probe_state_t wan_states[MAX_WANS];
    uint16_t pid;
};

static uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    uint32_t sum = 0;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static uint64_t get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (ts.tv_nsec / 1000ULL);
}

prober_ctx_t *prober_init(fluxwan_config_t *config, wan_health_callback_t cb, void *user_data) {
    if (!config) return NULL;
    prober_ctx_t *ctx = calloc(1, sizeof(prober_ctx_t));
    if (!ctx) return NULL;

    ctx->config = config;
    ctx->callback = cb;
    ctx->user_data = user_data;
    ctx->pid = (uint16_t)(getpid() & 0xFFFF);

    for (uint32_t i = 0; i < MAX_WANS; i++) {
        ctx->wan_send_fds[i] = -1;
    }

    ctx->raw_fd = (int)socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ctx->raw_fd < 0) {
        LOG_WARN("RAW ICMP Socket creation failed (Root required for real ICMP). Running Prober in active simulation mode.");
        ctx->raw_fd = -1;
    } else {
#if !defined(_WIN32) && !defined(_WIN64)
        fcntl(ctx->raw_fd, F_SETFD, FD_CLOEXEC);
        int flags = fcntl(ctx->raw_fd, F_GETFL, 0);
        if (flags >= 0) fcntl(ctx->raw_fd, F_SETFL, flags | O_NONBLOCK);
#endif
        LOG_INFO("RAW ICMP Global Prober Engine initialized (fd: %d)", ctx->raw_fd);
    }

    for (uint32_t i = 0; i < config->wan_count; i++) {
        ctx->wan_states[i].wan_idx = i;
        ctx->wan_states[i].target_ip = config->wans[i].probe_target_ip;
        ctx->wan_states[i].current_seq = 1;
    }

    return ctx;
}

void prober_close(prober_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->raw_fd >= 0) close(ctx->raw_fd);
    for (uint32_t i = 0; i < MAX_WANS; i++) {
        if (ctx->wan_send_fds[i] >= 0) {
            close(ctx->wan_send_fds[i]);
            ctx->wan_send_fds[i] = -1;
        }
    }
    free(ctx);
}

int prober_get_fd(const prober_ctx_t *ctx) {
    return ctx ? ctx->raw_fd : -1;
}

int prober_send_probes(prober_ctx_t *ctx) {
    if (!ctx) return -1;
    uint64_t now_us = get_time_us();

    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        wan_config_t *w = &ctx->config->wans[i];
        wan_probe_state_t *ps = &ctx->wan_states[i];
        if (!w->enabled) continue;

        uint16_t seq = ps->current_seq++;
        uint32_t slot = seq % 16;

        /* Check if previous probe in this slot timed out */
        if (ps->pending_probes[slot].send_time_us > 0 && !ps->pending_probes[slot].received) {
            uint64_t elapsed_ms = (now_us - ps->pending_probes[slot].send_time_us) / 1000ULL;
            if (elapsed_ms >= (uint64_t)ctx->config->prober.timeout_ms) {
                ps->loss_history[ps->history_idx % PROBE_WINDOW_SIZE] = true;
                ps->history_idx++;
            }
        }

        ps->pending_probes[slot].seq = seq;
        ps->pending_probes[slot].send_time_us = now_us;
        ps->pending_probes[slot].received = false;

        /* Ensure dedicated socket bound to this interface exists */
        if (ctx->wan_send_fds[i] < 0 && w->name[0]) {
            ctx->wan_send_fds[i] = (int)socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (ctx->wan_send_fds[i] >= 0) {
#if !defined(_WIN32) && !defined(_WIN64)
                fcntl(ctx->wan_send_fds[i], F_SETFD, FD_CLOEXEC);
                int flags = fcntl(ctx->wan_send_fds[i], F_GETFL, 0);
                if (flags >= 0) fcntl(ctx->wan_send_fds[i], F_SETFL, flags | O_NONBLOCK);
#if defined(SO_BINDTODEVICE)
                setsockopt(ctx->wan_send_fds[i], SOL_SOCKET, SO_BINDTODEVICE,
                           w->name, (socklen_t)strlen(w->name));
#endif
#endif
            }
        }

        int send_fd = (ctx->wan_send_fds[i] >= 0) ? ctx->wan_send_fds[i] : ctx->raw_fd;

        if (send_fd >= 0 && w->probe_target_ip != 0) {
            char packet[64];
            memset(packet, 0, sizeof(packet));

            struct icmphdr *icmp = (struct icmphdr *)packet;
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.id = htons((uint16_t)(ctx->pid + i));
            icmp->un.echo.sequence = htons(seq);

            /* Embed 64-bit microsecond send timestamp in payload */
            uint64_t *ts_payload = (uint64_t *)(packet + sizeof(struct icmphdr));
            *ts_payload = now_us;

            icmp->checksum = checksum(packet, sizeof(packet));

            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = w->probe_target_ip;

            sendto(send_fd, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
        }

        /* Calculate moving average RTT, Jitter, and Loss from real packet history */
        uint64_t total_rtt = 0;
        uint32_t count = 0, losses = 0;
        for (uint32_t k = 0; k < PROBE_WINDOW_SIZE; k++) {
            if (ps->rtt_history[k] > 0) {
                total_rtt += ps->rtt_history[k];
                count++;
            }
            if (ps->loss_history[k]) losses++;
        }

        if (count > 0) {
            uint32_t avg_rtt = (uint32_t)(total_rtt / count);
            w->metrics.jitter_ms = (avg_rtt >= w->metrics.rtt_ms) ?
                                   (avg_rtt - w->metrics.rtt_ms) : (w->metrics.rtt_ms - avg_rtt);
            w->metrics.rtt_ms = avg_rtt;
        }
        w->metrics.packet_loss_pct = (losses * 100.0f) / PROBE_WINDOW_SIZE;
        w->metrics.last_probe_time = now_us / 1000ULL;

        /* Evaluate Link Health */
        wan_state_t new_state = WAN_STATE_HEALTHY;
        if (w->metrics.packet_loss_pct > ctx->config->prober.max_acceptable_loss_pct) {
            new_state = WAN_STATE_DOWN;
        } else if (w->metrics.rtt_ms > ctx->config->prober.max_acceptable_rtt_ms) {
            new_state = WAN_STATE_DEGRADED;
        }

        if (w->state != new_state) {
            w->state = new_state;
            if (ctx->callback) {
                ctx->callback(i, new_state, &w->metrics, ctx->user_data);
            }
        }
    }
    return 0;
}

static void prober_handle_packet(prober_ctx_t *ctx, const uint8_t *buf, ssize_t len) {
    if (len < 28) return;

    int ip_hl = (buf[0] & 0x0F) * 4;
    if (len < ip_hl + 8) return;

    struct icmphdr *icmp = (struct icmphdr *)(buf + ip_hl);
    if (icmp->type != ICMP_ECHOREPLY) return;

    uint16_t id = ntohs(icmp->un.echo.id);
    uint16_t seq = ntohs(icmp->un.echo.sequence);

    if (id < ctx->pid || id >= ctx->pid + ctx->config->wan_count) return;

    uint32_t wan_idx = id - ctx->pid;
    wan_config_t *w = &ctx->config->wans[wan_idx];
    wan_probe_state_t *ps = &ctx->wan_states[wan_idx];

    uint64_t now_us = get_time_us();
    uint64_t send_time_us = 0;

    /* Extract embedded timestamp from ICMP payload */
    if (len >= ip_hl + (int)sizeof(struct icmphdr) + (int)sizeof(uint64_t)) {
        uint64_t *ts_ptr = (uint64_t *)(buf + ip_hl + sizeof(struct icmphdr));
        send_time_us = *ts_ptr;
    } else {
        send_time_us = ps->pending_probes[seq % 16].send_time_us;
    }

    uint32_t measured_rtt_ms = 1;
    if (send_time_us > 0 && now_us >= send_time_us) {
        uint64_t diff_us = now_us - send_time_us;
        measured_rtt_ms = (uint32_t)(diff_us / 1000ULL);
        if (measured_rtt_ms == 0) measured_rtt_ms = 1; /* Sub-millisecond local latency */
    }

    /* Record real RTT in moving history */
    ps->rtt_history[ps->history_idx % PROBE_WINDOW_SIZE] = measured_rtt_ms;
    ps->loss_history[ps->history_idx % PROBE_WINDOW_SIZE] = false;
    ps->history_idx++;

    w->metrics.rtt_ms = measured_rtt_ms;
    w->metrics.last_probe_time = now_us / 1000ULL;
    ps->pending_probes[seq % 16].received = true;
}

int prober_process_responses(prober_ctx_t *ctx) {
    if (!ctx) return 0;
    uint8_t buf[512];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t len;

    /* Drain global listening socket */
    if (ctx->raw_fd >= 0) {
        while ((len = recvfrom(ctx->raw_fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen)) > 0) {
            prober_handle_packet(ctx, buf, len);
        }
    }

    /* Drain each interface-bound socket */
    for (uint32_t i = 0; i < ctx->config->wan_count; i++) {
        if (ctx->wan_send_fds[i] >= 0) {
            while ((len = recvfrom(ctx->wan_send_fds[i], buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen)) > 0) {
                prober_handle_packet(ctx, buf, len);
            }
        }
    }
    return 0;
}
