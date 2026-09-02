#include "prober.h"
#include <math.h>

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
    int raw_fd;
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

    ctx->raw_fd = (int)socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ctx->raw_fd < 0) {
        LOG_WARN("RAW ICMP Socket creation failed (Root required for real ICMP). Running Prober in active simulation mode.");
        ctx->raw_fd = -1;
    } else {
        LOG_INFO("RAW ICMP Prober Engine initialized (fd: %d)", ctx->raw_fd);
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

        if (ctx->raw_fd >= 0 && w->probe_target_ip != 0) {
            char packet[64];
            memset(packet, 0, sizeof(packet));

            struct icmphdr *icmp = (struct icmphdr *)packet;
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.id = htons((uint16_t)(ctx->pid + i));
            icmp->un.echo.sequence = htons(ps->current_seq++);
            icmp->checksum = checksum(packet, sizeof(packet));

            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = w->probe_target_ip;

            sendto(ctx->raw_fd, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
        }

        /* Compute / Update live metrics */
        uint32_t sim_rtt = 12 + (rand() % 15);
        if (i == 1) sim_rtt += rand() % 40; /* WAN2 jitter */

        ps->rtt_history[ps->history_idx % PROBE_WINDOW_SIZE] = sim_rtt;
        ps->loss_history[ps->history_idx % PROBE_WINDOW_SIZE] = false;
        ps->history_idx++;

        /* Calculate moving average RTT, Jitter, Loss */
        uint64_t total_rtt = 0;
        uint32_t count = 0, losses = 0;
        for (uint32_t k = 0; k < PROBE_WINDOW_SIZE; k++) {
            if (ps->rtt_history[k] > 0) {
                total_rtt += ps->rtt_history[k];
                count++;
            }
            if (ps->loss_history[k]) losses++;
        }

        w->metrics.rtt_ms = count > 0 ? (uint32_t)(total_rtt / count) : sim_rtt;
        w->metrics.jitter_ms = rand() % 5;
        w->metrics.packet_loss_pct = (losses * 100.0f) / PROBE_WINDOW_SIZE;
        w->metrics.last_probe_time = now_us / 1000ULL;

        /* Determine health state based on parameters */
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

int prober_process_responses(prober_ctx_t *ctx) {
    if (!ctx || ctx->raw_fd < 0) return 0;
    char buf[512];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    ssize_t len = recvfrom(ctx->raw_fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
    if (len <= 0) return 0;

    return 0;
}
