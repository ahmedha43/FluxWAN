#ifndef FLUXWAN_H
#define FLUXWAN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#define getpid _getpid
typedef intptr_t ssize_t;
typedef SOCKET socket_t;
#define IS_VALID_SOCK(s) ((s) != INVALID_SOCKET)
#define CLOSE_SOCK(s) closesocket(s)
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
static inline int clock_gettime(int clk_id, struct timespec *tp) {
    (void)clk_id;
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    tp->tv_sec = (time_t)(count.QuadPart / freq.QuadPart);
    tp->tv_nsec = (long)(((count.QuadPart % freq.QuadPart) * 1000000000ULL) / freq.QuadPart);
    return 0;
}
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
typedef int socket_t;
#define IS_VALID_SOCK(s) ((s) >= 0)
#define CLOSE_SOCK(s) close(s)
#define INVALID_SOCKET (-1)
#endif

#define FLUXWAN_VERSION "1.0.0"
#define MAX_WANS 8
#define MAX_IFNAME_LEN 32
#define MAX_LABEL_LEN 64
#define MAX_PATH_LEN 256
#define PROBE_WINDOW_SIZE 32

/* Maglev Consistent Hashing & BPF Map Dimensions */
#define MAGLEV_RING_SIZE 65537
#define MAX_EBPF_WANS 8
#define MAX_STICKY_ENTRIES 16384

/* 5-Tuple Flow Key Structure */
struct flow_5tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  tcp_flags;
    uint16_t pad;
};

/* BPF WAN Entry Structure */
struct bpf_wan_entry {
    uint32_t wan_id;
    uint32_t ifindex;
    uint32_t ip_addr;
    uint32_t gateway;
    uint32_t weight;
    uint32_t is_active;
    uint32_t table_id;
    uint32_t fwmark;
};

/* BPF WAN Telemetry Counters */
struct bpf_wan_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t dropped_packets;
};

/* BPF Session Table Value */
struct bpf_session_val {
    uint32_t wan_idx;
    uint32_t wan_id;
    uint64_t last_seen_sec;
};

/* Log Macros */
#define LOG_INFO(fmt, ...)  fprintf(stdout, "[INFO]  " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  fprintf(stdout, "[WARN]  " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

/* WAN Provisioning Type */
typedef enum {
    WAN_TYPE_STATIC = 0,
    WAN_TYPE_DHCP,
    WAN_TYPE_PPPOE
} wan_type_t;

/* WAN Health Status */
typedef enum {
    WAN_STATE_DOWN = 0,
    WAN_STATE_DEGRADED,
    WAN_STATE_HEALTHY
} wan_state_t;

/* WAN Metrics & Telemetry */
typedef struct {
    uint32_t rtt_ms;
    uint32_t jitter_ms;
    float packet_loss_pct;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t last_probe_time;
} wan_metrics_t;

/* WAN Interface Definition */
typedef struct {
    uint32_t id;
    char name[MAX_IFNAME_LEN];
    char label[MAX_LABEL_LEN];
    wan_type_t type;
    
    /* IPv4 & IPv6 Configuration */
    uint32_t ip_addr;       /* Network byte order */
    uint32_t netmask;       /* Network byte order */
    uint32_t gateway;       /* Network byte order */
    uint32_t dns[2];        /* Network byte order */
    char ip6_addr[48];      /* e.g. "2a02:cb40:1000::1/64" */
    
    /* PPPoE specific */
    char ppp_username[64];
    char ppp_password[64];
    uint16_t mss_clamping;
    
    /* Routing & Weighting */
    uint32_t table_id;      /* Policy routing table ID (e.g. 101) */
    uint32_t config_weight; /* User configured base weight (1-100) */
    uint32_t dynamic_weight;/* Health-scaled dynamic weight */
    wan_state_t state;
    bool enabled;           /* Administrative status: true=Enabled, false=Disabled */
    
    /* Probing */
    char probe_target[64];
    uint32_t probe_target_ip;
    wan_metrics_t metrics;
    
    /* Internal OS state */
    int ifindex;
    
    /* Session Live Telemetry & Details */
    uint64_t session_start_sec;   /* Uptime tracking */
    uint32_t lease_time_total;    /* Total DHCP lease duration (seconds) */
    uint32_t lease_time_remaining;/* Remaining DHCP lease (seconds) */
    char ac_name[64];             /* PPPoE Access Concentrator Name */
    char session_status[32];      /* e.g. "CONNECTED", "BOUND", "ONLINE" */
    uint16_t link_mtu;            /* e.g. 1500, 1492 */
    char dns_servers[64];         /* e.g. "1.1.1.1, 8.8.8.8" */
} wan_config_t;

#define MAX_WAN_GROUPS 8
#define MAX_POLICY_ROUTES 16
#define MAX_GROUP_MEMBERS 8

/* Policy Route Definition (Multi-Subnet LAN to WAN Group Binding) */
typedef struct {
    char subnet_str[32];           /* e.g. "10.10.20.0/24" */
    uint32_t subnet_ip;            /* Network byte order: e.g. 10.10.20.0 */
    uint32_t netmask;              /* Network byte order: e.g. 255.255.255.0 */
    uint32_t prefix_len;          /* e.g. 24 */
    char gateway_ip_str[32];       /* e.g. "10.10.20.1" */
    uint32_t gateway_ip;          /* Network byte order */
    char target_group[32];         /* e.g. "Starlink_Fleet", "Iraq_Local" */
    uint32_t target_group_id;      /* 0=Default/All, 1, 2... */
    char description[64];
    bool enabled;
} policy_route_t;

/* WAN Group Definition (Independent Maglev Ring & Health Domain) */
typedef struct {
    uint32_t id;                                /* Group ID (0=Default/All_WANs, 1, 2...) */
    char name[32];                              /* Group Name: e.g. "Starlink_Fleet", "Iraq_Local" */
    char description[64];
    char wan_names[MAX_GROUP_MEMBERS][MAX_LABEL_LEN]; /* Names of WAN interfaces assigned */
    uint32_t wan_member_indices[MAX_GROUP_MEMBERS];   /* Indices in wans[] array */
    uint32_t wan_count;                         /* Total WANs configured in this group */
    uint32_t active_wan_count;                  /* Currently active WANs in this group */
    uint32_t maglev_ring[MAGLEV_RING_SIZE];     /* Dedicated Maglev Consistent Hash ring */
    bool enabled;
} wan_group_t;

/* LAN Interface Definition */
typedef struct {
    char name[MAX_IFNAME_LEN];
    uint32_t ip_addr;
    uint32_t netmask;
    bool dhcp_enabled;
    uint32_t dhcp_start;
    uint32_t dhcp_end;
    uint32_t dhcp_lease_time;
    int ifindex;
    policy_route_t policy_routes[MAX_POLICY_ROUTES];
    uint32_t policy_route_count;
} lan_config_t;

/* Prober Configuration */
typedef struct {
    uint32_t interval_ms;
    uint32_t timeout_ms;
    uint32_t loss_window;
    uint32_t max_acceptable_rtt_ms;
    float max_acceptable_loss_pct;
} prober_config_t;

/* Sticky Session Configuration */
typedef struct {
    bool enabled;
    uint32_t timeout_seconds;
} sticky_config_t;

/* Embedded Web Server Configuration */
typedef struct {
    char bind_ip[64];
    uint16_t port;
} web_config_t;

/* Administrator Authentication Configuration */
typedef struct {
    bool enabled;
    char username[64];
    char password[64];
    char session_token[64];
} auth_config_t;

/* System Event Log Entry */
#define MAX_SYSTEM_LOGS 32
typedef struct {
    uint64_t timestamp_sec;
    char time_str[32];
    char level[16];
    char message[256];
} system_log_entry_t;

/* DNS64 & Stateless NAT46 Configuration */
typedef struct {
    bool enabled;
    char synthetic_prefix[32];
    char upstream_dns[64];
    char starlink_wan_name[MAX_IFNAME_LEN];
} nat46_config_t;

/* Global App Configuration Structure */
typedef struct {
    lan_config_t lan;
    wan_config_t wans[MAX_WANS];
    uint32_t wan_count;
    wan_group_t groups[MAX_WAN_GROUPS];
    uint32_t group_count;
    prober_config_t prober;
    sticky_config_t sticky;
    web_config_t web;
    auth_config_t auth;
    nat46_config_t nat46;
} fluxwan_config_t;

/* Helper function prototypes */
static inline void ip_to_str(uint32_t ip, char *buf, size_t len) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, len);
}

static inline uint32_t str_to_ip(const char *str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) <= 0) return 0;
    return addr.s_addr;
}

#endif /* FLUXWAN_H */
