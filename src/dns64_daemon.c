#include "dns64_daemon.h"
#include <pthread.h>
#include <fcntl.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <sys/select.h>
#include <bpf/bpf.h>
#endif

#define SYNTH_START_IP_HOST 0xC6120001 /* 198.18.0.1 */
#define SYNTH_END_IP_HOST   0xC613FFFE /* 198.19.255.254 */

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns64_ctx {
    socket_t server_fd;
    socket_t upstream_fd;
    struct sockaddr_in upstream_addr;
    fluxwan_config_t *config;
    int v4_map_fd;
    int v6_map_fd;
    int cfg_map_fd;
    uint32_t current_synth_ip_host;
    dns64_stats_t stats;
    pthread_t thread;
    bool running;
};

static uint32_t allocate_synthetic_ip(dns64_ctx_t *ctx) {
    uint32_t ip = ctx->current_synth_ip_host++;
    if (ctx->current_synth_ip_host > SYNTH_END_IP_HOST) {
        ctx->current_synth_ip_host = SYNTH_START_IP_HOST;
    }
    return htonl(ip);
}

int dns64_register_mapping(dns64_ctx_t *ctx, uint32_t fake_v4, struct in6_addr real_v6) {
    if (!ctx) return -1;

#if !defined(_WIN32) && !defined(_WIN64)
    if (ctx->v4_map_fd >= 0) {
        /* nat46_forward_val */
        struct {
            struct in6_addr target_v6;
            uint32_t client_v4;
            uint32_t last_seen_sec;
        } fwd;
        memset(&fwd, 0, sizeof(fwd));
        fwd.target_v6 = real_v6;
        bpf_map_update_elem(ctx->v4_map_fd, &fake_v4, &fwd, BPF_ANY);
    }
    if (ctx->v6_map_fd >= 0) {
        /* nat46_reverse_val */
        struct {
            uint32_t synthetic_v4;
            uint32_t client_v4;
            uint32_t last_seen_sec;
        } rev;
        memset(&rev, 0, sizeof(rev));
        rev.synthetic_v4 = fake_v4;
        bpf_map_update_elem(ctx->v6_map_fd, &real_v6, &rev, BPF_ANY);
    }
#endif
    ctx->stats.active_synthetic_mappings++;
    return 0;
}

static void *dns64_worker(void *arg) {
    dns64_ctx_t *ctx = (dns64_ctx_t *)arg;
    unsigned char buf[2048];
    struct sockaddr_in client_addr;

    LOG_INFO("DNS64 Daemon listening on 0.0.0.0:53 (Synthetic Pool: 198.18.0.0/15)...");

    while (ctx->running) {
        socklen_t addr_len = sizeof(client_addr);
        ssize_t n = recvfrom(ctx->server_fd, (char *)buf, sizeof(buf), 0,
                             (struct sockaddr *)&client_addr, &addr_len);
        if (n < (ssize_t)sizeof(struct dns_header)) {
            continue;
        }

        ctx->stats.total_queries++;
        struct dns_header *hdr = (struct dns_header *)buf;

        /* Parse Query Type */
        unsigned char *qptr = buf + sizeof(struct dns_header);
        while (qptr < buf + n && *qptr != 0) {
            qptr += (*qptr + 1);
        }
        if (qptr < buf + n && *qptr == 0) qptr++; /* Skip null terminator */

        if (qptr + 4 <= buf + n) {
            uint16_t qtype = (qptr[0] << 8) | qptr[1];
            
            /* If Type A Query (IPv4 Request) */
            if (qtype == 0x0001) {
                /* Allocate Synthetic IPv4 */
                uint32_t synth_v4 = allocate_synthetic_ip(ctx);

                /* Default Target IPv6 (e.g. Google/CDN IPv6 Anycast or Upstream resolved) */
                struct in6_addr target_v6;
                inet_pton(AF_INET6, "2001:4860:4860::8888", &target_v6);

                dns64_register_mapping(ctx, synth_v4, target_v6);

                /* Construct Synthesized DNS A Reply */
                hdr->flags = htons(0x8180); /* Standard Query Response, No error */
                hdr->ancount = htons(1);

                unsigned char *ans = buf + n;
                ans[0] = 0xc0; /* Name Pointer */
                ans[1] = 0x0c; /* Offset to QNAME */
                ans[2] = 0x00; ans[3] = 0x01; /* Type A */
                ans[4] = 0x00; ans[5] = 0x01; /* Class IN */
                ans[6] = 0x00; ans[7] = 0x00; ans[8] = 0x00; ans[9] = 0x3c; /* TTL: 60s */
                ans[10] = 0x00; ans[11] = 0x04; /* Data length: 4 bytes */
                memcpy(ans + 12, &synth_v4, 4);

                sendto(ctx->server_fd, (const char *)buf, n + 16, 0,
                       (struct sockaddr *)&client_addr, addr_len);

                ctx->stats.synthesized_a_records++;
                continue;
            }
        }

        /* Passthrough other queries to Upstream DNS */
        sendto(ctx->upstream_fd, (const char *)buf, n, 0,
               (struct sockaddr *)&ctx->upstream_addr, sizeof(ctx->upstream_addr));

        unsigned char up_buf[2048];
        ssize_t up_len = recv(ctx->upstream_fd, (char *)up_buf, sizeof(up_buf), 0);
        if (up_len > 0) {
            sendto(ctx->server_fd, (const char *)up_buf, up_len, 0,
                   (struct sockaddr *)&client_addr, addr_len);
            ctx->stats.passthrough_queries++;
        }
    }

    return NULL;
}

dns64_ctx_t *dns64_init(fluxwan_config_t *config, int v4_map_fd, int v6_map_fd, int cfg_map_fd) {
    if (!config) return NULL;

    dns64_ctx_t *ctx = calloc(1, sizeof(dns64_ctx_t));
    if (!ctx) return NULL;

    ctx->config = config;
    ctx->v4_map_fd = v4_map_fd;
    ctx->v6_map_fd = v6_map_fd;
    ctx->cfg_map_fd = cfg_map_fd;
    ctx->current_synth_ip_host = SYNTH_START_IP_HOST;
    ctx->running = true;

    ctx->server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (!IS_VALID_SOCK(ctx->server_fd)) {
        LOG_WARN("Could not open DNS64 UDP socket (port 53 may require root)");
        free(ctx);
        return NULL;
    }

    int opt = 1;
    setsockopt(ctx->server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(53);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(ctx->server_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG_WARN("DNS64 could not bind to port 53: %s (will run in simulated mode)", strerror(errno));
    }

    ctx->upstream_fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ctx->upstream_addr, 0, sizeof(ctx->upstream_addr));
    ctx->upstream_addr.sin_family = AF_INET;
    ctx->upstream_addr.sin_port = htons(53);
    ctx->upstream_addr.sin_addr.s_addr = inet_addr("1.1.1.1");

    pthread_create(&ctx->thread, NULL, dns64_worker, ctx);
    return ctx;
}

void dns64_destroy(dns64_ctx_t *ctx) {
    if (!ctx) return;
    ctx->running = false;
    if (IS_VALID_SOCK(ctx->server_fd)) {
        CLOSE_SOCK(ctx->server_fd);
    }
    if (IS_VALID_SOCK(ctx->upstream_fd)) {
        CLOSE_SOCK(ctx->upstream_fd);
    }
    pthread_join(ctx->thread, NULL);
    free(ctx);
}

void dns64_get_stats(dns64_ctx_t *ctx, dns64_stats_t *out_stats) {
    if (!ctx || !out_stats) return;
    *out_stats = ctx->stats;
    out_stats->current_pool_ip = htonl(ctx->current_synth_ip_host);
}