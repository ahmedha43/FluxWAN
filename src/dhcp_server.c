#include "dhcp_server.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTREPLY   2

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7
#define DHCP_INFORM   8

#define DHCP_OPT_PAD         0
#define DHCP_OPT_SUBNET_MASK 1
#define DHCP_OPT_ROUTER      3
#define DHCP_OPT_DNS         6
#define DHCP_OPT_HOSTNAME    12
#define DHCP_OPT_REQ_IP      50
#define DHCP_OPT_LEASE_TIME  51
#define DHCP_OPT_MSG_TYPE    53
#define DHCP_OPT_SERVER_ID   54
#define DHCP_OPT_PARAM_REQ   55
#define DHCP_OPT_END         255

#define DHCP_MAGIC_COOKIE 0x63825363

#pragma pack(push, 1)
struct dhcp_packet {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    char     sname[64];
    char     file[128];
    uint32_t magic;
    uint8_t  options[308];
};
#pragma pack(pop)

struct dhcp_server_ctx {
    socket_t sock_fd;
    fluxwan_config_t config;
    dhcp_lease_t leases[MAX_DHCP_LEASES];
    uint32_t lease_count;
};

static const uint8_t *get_dhcp_option(const uint8_t *opts, size_t max_len, uint8_t opt_type, uint8_t *out_len) {
    size_t i = 0;
    while (i < max_len) {
        uint8_t type = opts[i++];
        if (type == DHCP_OPT_PAD) continue;
        if (type == DHCP_OPT_END) break;
        if (i >= max_len) break;
        uint8_t len = opts[i++];
        if (i + len > max_len) break;
        if (type == opt_type) {
            if (out_len) *out_len = len;
            return &opts[i];
        }
        i += len;
    }
    return NULL;
}

static size_t append_option(uint8_t *opts, size_t offset, size_t max_len, uint8_t type, uint8_t len, const void *data) {
    if (offset + 2 + len >= max_len) return offset;
    opts[offset++] = type;
    opts[offset++] = len;
    if (len > 0 && data) {
        memcpy(&opts[offset], data, len);
        offset += len;
    }
    return offset;
}

static dhcp_lease_t *find_lease_by_mac(dhcp_server_ctx_t *ctx, const uint8_t *mac) {
    for (uint32_t i = 0; i < ctx->lease_count; i++) {
        if (memcmp(ctx->leases[i].mac_addr, mac, 6) == 0) {
            return &ctx->leases[i];
        }
    }
    return NULL;
}

static dhcp_lease_t *find_lease_by_ip(dhcp_server_ctx_t *ctx, uint32_t ip) {
    for (uint32_t i = 0; i < ctx->lease_count; i++) {
        if (ctx->leases[i].ip_addr == ip) {
            return &ctx->leases[i];
        }
    }
    return NULL;
}

static uint32_t allocate_next_ip(dhcp_server_ctx_t *ctx, const uint8_t *mac) {
    /* Check if this MAC already has a lease */
    dhcp_lease_t *existing = find_lease_by_mac(ctx, mac);
    if (existing && existing->is_active) {
        return existing->ip_addr;
    }

    uint32_t start_h = ntohl(ctx->config.lan.dhcp_start);
    uint32_t end_h   = ntohl(ctx->config.lan.dhcp_end);

    if (start_h == 0 || end_h == 0 || end_h < start_h) {
        start_h = ntohl(str_to_ip("192.168.1.100"));
        end_h   = ntohl(str_to_ip("192.168.1.200"));
    }

    for (uint32_t ip_h = start_h; ip_h <= end_h; ip_h++) {
        uint32_t ip_n = htonl(ip_h);
        dhcp_lease_t *l = find_lease_by_ip(ctx, ip_n);
        if (!l || !l->is_active) {
            return ip_n;
        }
    }
    return 0; /* Pool exhausted */
}

static void update_lease_record(dhcp_server_ctx_t *ctx, const uint8_t *mac, uint32_t ip, const char *hostname) {
    dhcp_lease_t *l = find_lease_by_mac(ctx, mac);
    if (!l) {
        if (ctx->lease_count < MAX_DHCP_LEASES) {
            l = &ctx->leases[ctx->lease_count++];
        } else {
            l = &ctx->leases[0]; /* Overwrite oldest if full */
        }
    }

    memcpy(l->mac_addr, mac, 6);
    snprintf(l->mac_str, sizeof(l->mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    l->ip_addr = ip;
    if (hostname && hostname[0]) {
        strncpy(l->hostname, hostname, sizeof(l->hostname) - 1);
        l->hostname[sizeof(l->hostname) - 1] = '\0';
    } else if (!l->hostname[0]) {
        strncpy(l->hostname, "LAN-Client", sizeof(l->hostname) - 1);
    }
    l->lease_start_sec = (uint64_t)time(NULL);
    l->lease_expire_sec = l->lease_start_sec + ctx->config.lan.dhcp_lease_time;
    l->is_active = true;
}

dhcp_server_ctx_t *dhcp_server_init(const fluxwan_config_t *config) {
    if (!config || !config->lan.dhcp_enabled) return NULL;
    dhcp_server_ctx_t *ctx = calloc(1, sizeof(dhcp_server_ctx_t));
    if (!ctx) return NULL;

    ctx->config = *config;

    ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (!IS_VALID_SOCK(ctx->sock_fd)) {
        LOG_WARN("Could not create DHCP UDP socket (Running without root or port 67 busy). Passive mode active.");
        ctx->sock_fd = INVALID_SOCKET;
    } else {
        int opt = 1;
        setsockopt(ctx->sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
        setsockopt(ctx->sock_fd, SOL_SOCKET, SO_BROADCAST, (const char *)&opt, sizeof(opt));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(DHCP_SERVER_PORT);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(ctx->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            LOG_WARN("Could not bind DHCP socket to port 67 (Root privileges required). Active in passive mode.");
            CLOSE_SOCK(ctx->sock_fd);
            ctx->sock_fd = INVALID_SOCKET;
        } else {
            LOG_INFO("RFC 2131 DHCP Server initialized on LAN (%s:%u)", config->lan.name, DHCP_SERVER_PORT);
        }
    }

    /* Seed default active LAN device for demonstration */
    uint8_t def_mac[6] = {0xd8, 0x3a, 0xdd, 0x12, 0x34, 0x56};
    uint32_t def_ip = config->lan.dhcp_start != 0 ? config->lan.dhcp_start : str_to_ip("192.168.1.105");
    update_lease_record(ctx, def_mac, def_ip, "Workstation-Office");

    return ctx;
}

void dhcp_server_close(dhcp_server_ctx_t *ctx) {
    if (!ctx) return;
    if (IS_VALID_SOCK(ctx->sock_fd)) CLOSE_SOCK(ctx->sock_fd);
    free(ctx);
}

socket_t dhcp_server_get_fd(const dhcp_server_ctx_t *ctx) {
    return ctx ? ctx->sock_fd : INVALID_SOCKET;
}

int dhcp_server_process(dhcp_server_ctx_t *ctx) {
    if (!ctx || !IS_VALID_SOCK(ctx->sock_fd)) return 0;

    struct dhcp_packet req;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    ssize_t n = recvfrom(ctx->sock_fd, (char *)&req, sizeof(req), 0, (struct sockaddr *)&client_addr, &addrlen);
    if (n < (ssize_t)sizeof(struct dhcp_packet) - 308) return 0;

    if (ntohl(req.magic) != DHCP_MAGIC_COOKIE || req.op != DHCP_BOOTREQUEST) return 0;

    uint8_t msg_type_len = 0;
    const uint8_t *msg_type_ptr = get_dhcp_option(req.options, sizeof(req.options), DHCP_OPT_MSG_TYPE, &msg_type_len);
    if (!msg_type_ptr) return 0;

    uint8_t msg_type = *msg_type_ptr;
    char hostname[64] = "";
    uint8_t hlen = 0;
    const uint8_t *hptr = get_dhcp_option(req.options, sizeof(req.options), DHCP_OPT_HOSTNAME, &hlen);
    if (hptr && hlen > 0) {
        size_t copy_len = hlen < sizeof(hostname) - 1 ? hlen : sizeof(hostname) - 1;
        memcpy(hostname, hptr, copy_len);
        hostname[copy_len] = '\0';
    }

    LOG_INFO("[DHCP] MsgType %u from MAC %02x:%02x:%02x:%02x:%02x:%02x (Hostname: '%s')",
             msg_type, req.chaddr[0], req.chaddr[1], req.chaddr[2], req.chaddr[3], req.chaddr[4], req.chaddr[5], hostname);

    if (msg_type == DHCP_DISCOVER) {
        uint32_t offer_ip = allocate_next_ip(ctx, req.chaddr);
        if (offer_ip == 0) {
            LOG_WARN("[DHCP] IP address pool exhausted!");
            return 0;
        }

        struct dhcp_packet reply;
        memset(&reply, 0, sizeof(reply));
        reply.op = DHCP_BOOTREPLY;
        reply.htype = req.htype;
        reply.hlen = req.hlen;
        reply.xid = req.xid;
        reply.flags = req.flags;
        reply.yiaddr = offer_ip;
        reply.siaddr = ctx->config.lan.ip_addr;
        memcpy(reply.chaddr, req.chaddr, 16);
        reply.magic = htonl(DHCP_MAGIC_COOKIE);

        size_t opt_offset = 0;
        uint8_t offer_type = DHCP_OFFER;
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_MSG_TYPE, 1, &offer_type);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_SUBNET_MASK, 4, &ctx->config.lan.netmask);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_ROUTER, 4, &ctx->config.lan.ip_addr);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_DNS, 4, &ctx->config.lan.ip_addr);

        uint32_t lease_sec = htonl(ctx->config.lan.dhcp_lease_time);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_LEASE_TIME, 4, &lease_sec);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_SERVER_ID, 4, &ctx->config.lan.ip_addr);
        reply.options[opt_offset++] = DHCP_OPT_END;

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(DHCP_CLIENT_PORT);
        dest.sin_addr.s_addr = htonl(INADDR_BROADCAST);

        sendto(ctx->sock_fd, (const char *)&reply, (int)sizeof(reply), 0, (struct sockaddr *)&dest, sizeof(dest));
        char ip_str[32];
        ip_to_str(offer_ip, ip_str, sizeof(ip_str));
        LOG_INFO("[DHCP] Sent DHCPOFFER -> %s for MAC %02x:%02x:%02x:%02x:%02x:%02x",
                 ip_str, req.chaddr[0], req.chaddr[1], req.chaddr[2], req.chaddr[3], req.chaddr[4], req.chaddr[5]);

    } else if (msg_type == DHCP_REQUEST) {
        uint32_t assigned_ip = 0;
        uint8_t req_ip_len = 0;
        const uint8_t *req_ip_ptr = get_dhcp_option(req.options, sizeof(req.options), DHCP_OPT_REQ_IP, &req_ip_len);
        if (req_ip_ptr && req_ip_len == 4) {
            memcpy(&assigned_ip, req_ip_ptr, 4);
        } else if (req.ciaddr != 0) {
            assigned_ip = req.ciaddr;
        } else {
            assigned_ip = allocate_next_ip(ctx, req.chaddr);
        }

        update_lease_record(ctx, req.chaddr, assigned_ip, hostname);

        struct dhcp_packet reply;
        memset(&reply, 0, sizeof(reply));
        reply.op = DHCP_BOOTREPLY;
        reply.htype = req.htype;
        reply.hlen = req.hlen;
        reply.xid = req.xid;
        reply.flags = req.flags;
        reply.yiaddr = assigned_ip;
        reply.siaddr = ctx->config.lan.ip_addr;
        memcpy(reply.chaddr, req.chaddr, 16);
        reply.magic = htonl(DHCP_MAGIC_COOKIE);

        size_t opt_offset = 0;
        uint8_t ack_type = DHCP_ACK;
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_MSG_TYPE, 1, &ack_type);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_SUBNET_MASK, 4, &ctx->config.lan.netmask);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_ROUTER, 4, &ctx->config.lan.ip_addr);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_DNS, 4, &ctx->config.lan.ip_addr);

        uint32_t lease_sec = htonl(ctx->config.lan.dhcp_lease_time);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_LEASE_TIME, 4, &lease_sec);
        opt_offset = append_option(reply.options, opt_offset, sizeof(reply.options), DHCP_OPT_SERVER_ID, 4, &ctx->config.lan.ip_addr);
        reply.options[opt_offset++] = DHCP_OPT_END;

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(DHCP_CLIENT_PORT);
        dest.sin_addr.s_addr = htonl(INADDR_BROADCAST);

        sendto(ctx->sock_fd, (const char *)&reply, (int)sizeof(reply), 0, (struct sockaddr *)&dest, sizeof(dest));
        char ip_str[32];
        ip_to_str(assigned_ip, ip_str, sizeof(ip_str));
        LOG_INFO("[DHCP] Sent DHCPACK -> %s (MAC: %02x:%02x:%02x:%02x:%02x:%02x)",
                 ip_str, req.chaddr[0], req.chaddr[1], req.chaddr[2], req.chaddr[3], req.chaddr[4], req.chaddr[5]);

    } else if (msg_type == DHCP_RELEASE) {
        dhcp_lease_t *l = find_lease_by_mac(ctx, req.chaddr);
        if (l) {
            l->is_active = false;
            LOG_INFO("[DHCP] Lease released for MAC %02x:%02x:%02x:%02x:%02x:%02x",
                     req.chaddr[0], req.chaddr[1], req.chaddr[2], req.chaddr[3], req.chaddr[4], req.chaddr[5]);
        }
    }

    return 0;
}

uint32_t dhcp_server_get_leases(const dhcp_server_ctx_t *ctx, dhcp_lease_t *out_leases, uint32_t max_count) {
    if (!ctx || !out_leases || max_count == 0) return 0;
    uint32_t copied = 0;
    for (uint32_t i = 0; i < ctx->lease_count && copied < max_count; i++) {
        if (ctx->leases[i].is_active) {
            out_leases[copied++] = ctx->leases[i];
        }
    }
    return copied;
}
