#include "dns64_daemon.h"
#include <pthread.h>
#include <fcntl.h>

#if defined(__linux__)
#include <sys/select.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

static inline int sys_bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.value = (uint64_t)(uintptr_t)value;
    attr.flags = flags;
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
#define bpf_map_update_elem sys_bpf_map_update_elem
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

typedef struct {
    struct sockaddr_in client_addr;
    time_t timestamp;
} pending_dns_entry_t;

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
    pending_dns_entry_t *pending_queries;
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

    LOG_INFO("FluxWAN Embedded DNS Forwarder & Engine listening on 0.0.0.0:53...");

    while (ctx->running) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(ctx->server_fd, &rset);
        FD_SET(ctx->upstream_fd, &rset);

        int max_fd = (int)(ctx->server_fd > ctx->upstream_fd ? ctx->server_fd : ctx->upstream_fd) + 1;
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(max_fd, &rset, NULL, NULL, &tv);
        if (sel <= 0) {
            continue;
        }

        /* 1. Client query received on server_fd */
        if (FD_ISSET(ctx->server_fd, &rset)) {
            socklen_t addr_len = sizeof(client_addr);
            ssize_t n = recvfrom(ctx->server_fd, (char *)buf, sizeof(buf), 0,
                                 (struct sockaddr *)&client_addr, &addr_len);
            if (n >= (ssize_t)sizeof(struct dns_header)) {
                ctx->stats.total_queries++;
                struct dns_header *hdr = (struct dns_header *)buf;
                uint16_t qid = ntohs(hdr->id);

                /* If NAT46 is explicitly enabled and Type A Query (IPv4 Request) */
                if (ctx->config && ctx->config->nat46.enabled) {
                    unsigned char *qptr = buf + sizeof(struct dns_header);
                    while (qptr < buf + n && *qptr != 0) {
                        qptr += (*qptr + 1);
                    }
                    if (qptr < buf + n && *qptr == 0) qptr++;

                    if (qptr + 4 <= buf + n) {
                        uint16_t qtype = (qptr[0] << 8) | qptr[1];
                        if (qtype == 0x0001) {
                            uint32_t synth_v4 = allocate_synthetic_ip(ctx);
                            struct in6_addr target_v6;
                            inet_pton(AF_INET6, "2001:4860:4860::8888", &target_v6);

                            dns64_register_mapping(ctx, synth_v4, target_v6);

                            hdr->flags = htons(0x8180);
                            hdr->ancount = htons(1);

                            unsigned char *ans = buf + n;
                            ans[0] = 0xc0; ans[1] = 0x0c;
                            ans[2] = 0x00; ans[3] = 0x01;
                            ans[4] = 0x00; ans[5] = 0x01;
                            ans[6] = 0x00; ans[7] = 0x00; ans[8] = 0x00; ans[9] = 0x3c;
                            ans[10] = 0x00; ans[11] = 0x04;
                            memcpy(ans + 12, &synth_v4, 4);

                            sendto(ctx->server_fd, (const char *)buf, n + 16, 0,
                                   (struct sockaddr *)&client_addr, addr_len);

                            ctx->stats.synthesized_a_records++;
                            continue;
                        }
                    }
                }

                /* Record client mapping by DNS Query ID */
                if (ctx->pending_queries) {
                    ctx->pending_queries[qid].client_addr = client_addr;
                    ctx->pending_queries[qid].timestamp = time(NULL);
                }

                /* Forward query to Upstream DNS (1.1.1.1 / Primary DNS) */
                sendto(ctx->upstream_fd, (const char *)buf, n, 0,
                       (struct sockaddr *)&ctx->upstream_addr, sizeof(ctx->upstream_addr));
            }
        }

        /* 2. Response from Upstream DNS on upstream_fd */
        if (FD_ISSET(ctx->upstream_fd, &rset)) {
            struct sockaddr_in up_addr;
            socklen_t up_len = sizeof(up_addr);
            ssize_t n = recvfrom(ctx->upstream_fd, (char *)buf, sizeof(buf), 0,
                                 (struct sockaddr *)&up_addr, &up_len);
            if (n >= (ssize_t)sizeof(struct dns_header)) {
                struct dns_header *hdr = (struct dns_header *)buf;
                uint16_t qid = ntohs(hdr->id);

                if (ctx->pending_queries && ctx->pending_queries[qid].client_addr.sin_family == AF_INET) {
                    sendto(ctx->server_fd, (const char *)buf, n, 0,
                           (struct sockaddr *)&ctx->pending_queries[qid].client_addr,
                           sizeof(ctx->pending_queries[qid].client_addr));
                    ctx->pending_queries[qid].client_addr.sin_family = 0; /* Clear entry */
                    ctx->stats.passthrough_queries++;
                }
            }
        }
    }

    return NULL;
}

dns64_ctx_t *dns64_init(fluxwan_config_t *config, int v4_map_fd, int v6_map_fd, int cfg_map_fd) {
    if (!config) return NULL;

    dns64_ctx_t *ctx = calloc(1, sizeof(dns64_ctx_t));
    if (!ctx) return NULL;

    ctx->pending_queries = calloc(65536, sizeof(pending_dns_entry_t));
    if (!ctx->pending_queries) {
        free(ctx);
        return NULL;
    }

    ctx->config = config;
    ctx->v4_map_fd = v4_map_fd;
    ctx->v6_map_fd = v6_map_fd;
    ctx->cfg_map_fd = cfg_map_fd;
    ctx->current_synth_ip_host = SYNTH_START_IP_HOST;
    ctx->running = true;

    ctx->server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (!IS_VALID_SOCK(ctx->server_fd)) {
        LOG_WARN("Could not open DNS UDP socket (port 53 may require root)");
        free(ctx->pending_queries);
        free(ctx);
        return NULL;
    }
#if defined(__linux__)
    fcntl(ctx->server_fd, F_SETFD, FD_CLOEXEC);
#endif

    int opt = 1;
    setsockopt(ctx->server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(53);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(ctx->server_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG_WARN("DNS could not bind to port 53: %s (will run in simulated mode)", strerror(errno));
    }

    ctx->upstream_fd = socket(AF_INET, SOCK_DGRAM, 0);
#if defined(__linux__)
    if (IS_VALID_SOCK(ctx->upstream_fd)) {
        fcntl(ctx->upstream_fd, F_SETFD, FD_CLOEXEC);
    }
#endif
    memset(&ctx->upstream_addr, 0, sizeof(ctx->upstream_addr));
    ctx->upstream_addr.sin_family = AF_INET;
    ctx->upstream_addr.sin_port = htons(53);
    const char *target_dns = "1.1.1.1";
    if (config->lan.dns.adblock_enabled) {
        target_dns = "94.140.14.14";
    } else if (config->lan.dns.primary_dns[0]) {
        target_dns = config->lan.dns.primary_dns;
    }
    ctx->upstream_addr.sin_addr.s_addr = inet_addr(target_dns);

    pthread_create(&ctx->thread, NULL, dns64_worker, ctx);
    return ctx;
}

void dns64_destroy(dns64_ctx_t *ctx) {
    if (!ctx) return;
    ctx->running = false;
#if !defined(_WIN32) && !defined(_WIN64)
    if (IS_VALID_SOCK(ctx->server_fd)) {
        shutdown(ctx->server_fd, SHUT_RDWR);
    }
    if (IS_VALID_SOCK(ctx->upstream_fd)) {
        shutdown(ctx->upstream_fd, SHUT_RDWR);
    }
#endif
    if (IS_VALID_SOCK(ctx->server_fd)) {
        CLOSE_SOCK(ctx->server_fd);
    }
    if (IS_VALID_SOCK(ctx->upstream_fd)) {
        CLOSE_SOCK(ctx->upstream_fd);
    }
    pthread_join(ctx->thread, NULL);
    if (ctx->pending_queries) {
        free(ctx->pending_queries);
    }
    free(ctx);
}

void dns64_get_stats(dns64_ctx_t *ctx, dns64_stats_t *out_stats) {
    if (!ctx || !out_stats) return;
    *out_stats = ctx->stats;
    out_stats->current_pool_ip = htonl(ctx->current_synth_ip_host);
}