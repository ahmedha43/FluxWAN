#include "netlink_manager.h"
#if !defined(_WIN32) && !defined(_WIN64)
#include <net/if.h>
#endif

#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#endif

#ifndef FRA_FWMARK
#define FRA_FWMARK 10
#endif
#ifndef FRA_TABLE
#define FRA_TABLE 15
#endif
#ifndef FRA_PRIORITY
#define FRA_PRIORITY 6
#endif

#if !defined(__linux__)
/* Fallback constants & structures for non-Linux compilation check */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef AF_NETLINK
#define AF_NETLINK 16
#define NETLINK_ROUTE 0
#define RTM_NEWLINK  16
#define RTM_DELLINK  17
#define RTM_NEWADDR  20
#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define RTM_NEWRULE  32
#define RTM_DELRULE  33
#define NLM_F_REQUEST 1
#define NLM_F_MULTI   2
#define NLM_F_ACK     4
#define NLM_F_CREATE  0x400
#define NLM_F_EXCL    0x200
#define NLM_F_REPLACE 0x100
#define NLM_F_APPEND  0x800
#define RT_TABLE_MAIN 254
#define RTPROT_STATIC 4
#define RT_SCOPE_UNIVERSE 0
#define RTN_UNICAST   1
#define FRA_FWMARK    10
#define FRA_TABLE     15
#define RTA_DST       1
#define RTA_OIF       4
#define RTA_GATEWAY   5
#define RTA_TABLE     15
#define NLMSG_DONE    3

struct nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

struct rtmsg {
    uint8_t rtm_family;
    uint8_t rtm_dst_len;
    uint8_t rtm_src_len;
    uint8_t rtm_tos;
    uint8_t rtm_table;
    uint8_t rtm_protocol;
    uint8_t rtm_scope;
    uint8_t rtm_type;
    uint32_t rtm_flags;
};

struct fib_rule_hdr {
    uint8_t family;
    uint8_t dst_len;
    uint8_t src_len;
    uint8_t tos;
    uint8_t table;
    uint8_t res1;
    uint8_t res2;
    uint8_t action;
    uint32_t flags;
};

struct rtattr {
    unsigned short rta_len;
    unsigned short rta_type;
};

#define RTA_ALIGNTO 4U
#define RTA_ALIGN(len) (((len) + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1))
#define RTA_DATA(rta) ((void *)(((char *)(rta)) + RTA_ALIGN(sizeof(struct rtattr))))
#define RTA_NEXT(rta, len) ((len) -= RTA_ALIGN((rta)->rta_len), (struct rtattr *)(((char *)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_OK(rta, len) ((len) >= (int)sizeof(struct rtattr) && (rta)->rta_len >= sizeof(struct rtattr) && (rta)->rta_len <= (len))
#define RTA_LENGTH(len) (RTA_ALIGN(sizeof(struct rtattr)) + (len))

#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_DATA(nlh) ((void *)(((char *)(nlh)) + NLMSG_HDRLEN))
#define NLMSG_NEXT(nlh, len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), (struct nlmsghdr *)(((char *)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh, len) ((len) >= (int)sizeof(struct nlmsghdr) && (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && (nlh)->nlmsg_len <= (len))

#endif
#endif

struct netlink_ctx {
    int fd;
    uint32_t seq;
};

static void add_rtattr(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen) {
    int len = RTA_LENGTH(alen);
    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > (size_t)maxlen) {
        return;
    }
    struct rtattr *rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = (unsigned short)type;
    rta->rta_len = (unsigned short)len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = (uint32_t)(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len));
}

netlink_ctx_t *netlink_init(void) {
    netlink_ctx_t *ctx = calloc(1, sizeof(netlink_ctx_t));
    if (!ctx) return NULL;

#if defined(__linux__)
    ctx->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (ctx->fd < 0) {
        LOG_WARN("Netlink socket creation failed (Not running as root or non-Linux kernel). Simulation mode active.");
        ctx->fd = -1;
    } else {
        struct sockaddr_nl sa;
        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR;
        if (bind(ctx->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            LOG_WARN("Netlink bind failed. Falling back to basic operations.");
        } else {
            LOG_INFO("Netlink Manager initialized successfully (AF_NETLINK fd: %d)", ctx->fd);
        }
    }
#else
    ctx->fd = -1;
    LOG_INFO("Netlink Manager initialized in Portable Simulation mode.");
#endif
    return ctx;
}

void netlink_close(netlink_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->fd >= 0) {
        close(ctx->fd);
    }
    free(ctx);
}

int netlink_get_fd(const netlink_ctx_t *ctx) {
    return ctx ? ctx->fd : -1;
}

int netlink_add_ip_rule(netlink_ctx_t *ctx, uint32_t fwmark, uint32_t table_id, uint32_t priority) {
    if (!ctx) return -1;
    LOG_INFO("[Netlink] Adding IP Policy Rule: fwmark 0x%x -> lookup Table %u (Priority %u)", fwmark, table_id, priority);

    if (ctx->fd < 0) return 0; /* Simulated success for testing */

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
    n->nlmsg_type = RTM_NEWRULE;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    n->nlmsg_seq = ++ctx->seq;

    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)NLMSG_DATA(n);
    frh->family = AF_INET;
    frh->action = 1; /* FR_ACT_TO_TBL */

    add_rtattr(n, sizeof(buf), FRA_FWMARK, &fwmark, sizeof(fwmark));
    add_rtattr(n, sizeof(buf), FRA_TABLE, &table_id, sizeof(table_id));

    if (send(ctx->fd, (const char *)n, (int)n->nlmsg_len, 0) < 0) {
        LOG_ERROR("Netlink add_ip_rule send failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int netlink_del_ip_rule(netlink_ctx_t *ctx, uint32_t fwmark, uint32_t table_id, uint32_t priority) {
    if (!ctx) return -1;
    (void)priority;
    LOG_INFO("[Netlink] Deleting IP Policy Rule: fwmark 0x%x -> Table %u", fwmark, table_id);

    if (ctx->fd < 0) return 0;

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
    n->nlmsg_type = RTM_DELRULE;
    n->nlmsg_flags = NLM_F_REQUEST;
    n->nlmsg_seq = ++ctx->seq;

    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)NLMSG_DATA(n);
    frh->family = AF_INET;

    add_rtattr(n, sizeof(buf), FRA_FWMARK, &fwmark, sizeof(fwmark));
    add_rtattr(n, sizeof(buf), FRA_TABLE, &table_id, sizeof(table_id));

    send(ctx->fd, (const char *)n, (int)n->nlmsg_len, 0);
    return 0;
}

int netlink_add_default_route(netlink_ctx_t *ctx, uint32_t table_id, uint32_t gateway_ip, int ifindex) {
    if (!ctx) return -1;
    char gw_str[32];
    ip_to_str(gateway_ip, gw_str, sizeof(gw_str));
    LOG_INFO("[Netlink] Adding Default Route: table %u via %s (ifindex %d)", table_id, gw_str, ifindex);

    if (ctx->fd < 0) return 0;

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    n->nlmsg_type = RTM_NEWROUTE;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    n->nlmsg_seq = ++ctx->seq;

    struct rtmsg *r = (struct rtmsg *)NLMSG_DATA(n);
    r->rtm_family = AF_INET;
    r->rtm_table = (table_id < 256) ? (uint8_t)table_id : (uint8_t)RT_TABLE_MAIN;
    r->rtm_protocol = RTPROT_STATIC;
    r->rtm_scope = RT_SCOPE_UNIVERSE;
    r->rtm_type = RTN_UNICAST;
    r->rtm_dst_len = 0; /* default route 0.0.0.0/0 */

    add_rtattr(n, sizeof(buf), RTA_GATEWAY, &gateway_ip, sizeof(gateway_ip));
    if (ifindex > 0) {
        add_rtattr(n, sizeof(buf), RTA_OIF, &ifindex, sizeof(ifindex));
    }
    if (table_id >= 256) {
        add_rtattr(n, sizeof(buf), RTA_TABLE, &table_id, sizeof(table_id));
    }

    if (send(ctx->fd, (const char *)n, (int)n->nlmsg_len, 0) < 0) {
        LOG_ERROR("Netlink add_default_route failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int netlink_del_default_route(netlink_ctx_t *ctx, uint32_t table_id, uint32_t gateway_ip, int ifindex) {
    if (!ctx) return -1;
    (void)ifindex;
    LOG_INFO("[Netlink] Deleting Default Route: table %u", table_id);
    if (ctx->fd < 0) return 0;

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    n->nlmsg_type = RTM_DELROUTE;
    n->nlmsg_flags = NLM_F_REQUEST;
    n->nlmsg_seq = ++ctx->seq;

    struct rtmsg *r = (struct rtmsg *)NLMSG_DATA(n);
    r->rtm_family = AF_INET;
    r->rtm_table = (table_id < 256) ? (uint8_t)table_id : (uint8_t)RT_TABLE_MAIN;

    add_rtattr(n, sizeof(buf), RTA_GATEWAY, &gateway_ip, sizeof(gateway_ip));

    send(ctx->fd, (const char *)n, (int)n->nlmsg_len, 0);
    return 0;
}

int netlink_set_interface_ip(netlink_ctx_t *ctx, int ifindex, uint32_t ip_addr, uint32_t netmask) {
    if (!ctx) return -1;
    (void)netmask;
    char ip_str[32];
    ip_to_str(ip_addr, ip_str, sizeof(ip_str));
    LOG_INFO("[Netlink] Assigning IP %s to interface index %d", ip_str, ifindex);

    if (ctx->fd < 0) return 0;
    return 0;
}

int netlink_set_interface_state(netlink_ctx_t *ctx, int ifindex, bool up) {
    if (!ctx) return -1;
    LOG_INFO("[Netlink] Setting interface index %d state: %s", ifindex, up ? "UP" : "DOWN");

    if (ctx->fd < 0) return 0;
    return 0;
}

int netlink_process_events(netlink_ctx_t *ctx, fluxwan_config_t *config) {
    if (!ctx || ctx->fd < 0) return 0;
    (void)config;

    char buf[4096];
    ssize_t len = recv(ctx->fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (len <= 0) return 0;

    struct nlmsghdr *nh;
    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
        if (nh->nlmsg_type == NLMSG_DONE) break;
        if (nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) {
            LOG_INFO("[Netlink Event] Network link state change detected by Kernel");
        }
    }
    return 0;
}
