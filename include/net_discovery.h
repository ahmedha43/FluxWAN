#ifndef NET_DISCOVERY_H
#define NET_DISCOVERY_H

#include "fluxwan.h"

#define MAX_PHYSICAL_INTERFACES 16

typedef enum {
    ROLE_UNASSIGNED = 0,
    ROLE_LAN,
    ROLE_WAN
} iface_role_t;

typedef struct {
    char name[MAX_IFNAME_LEN];
    char mac_addr[18];        /* e.g. "00:1a:2b:3c:4d:5e" */
    char driver[32];          /* e.g. "igb", "r8169", "e1000e" */
    uint32_t speed_mbps;      /* e.g. 1000, 2500, 10000 */
    bool is_up;
    bool has_carrier;         /* Cable connected */
    bool is_physical;         /* True if physical hardware PCI/USB NIC */
    
    iface_role_t role;
    uint32_t wan_id;          /* If role == ROLE_WAN (1, 2, 3...) */
    
    /* Real Live Byte & Packet Counters from Kernel / Sysfs */
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_errors;
    uint64_t tx_errors;
    
    /* Current Assigned IP */
    uint32_t current_ip;
    uint32_t current_netmask;
    char ip6_addr[48];        /* e.g. "2a02:cb40:1000::1/64" */
} physical_interface_t;

typedef struct {
    physical_interface_t interfaces[MAX_PHYSICAL_INTERFACES];
    uint32_t count;
} iface_discovery_result_t;

/**
 * Scan all hardware network interfaces present on the system.
 * Reads /sys/class/net on Linux or native OS adapter APIs.
 */
int net_discovery_scan(const fluxwan_config_t *config, iface_discovery_result_t *out_result);

/**
 * Get real-time stats for a specific interface by name.
 */
int net_discovery_get_stats(const char *ifname, uint64_t *rx_bytes, uint64_t *tx_bytes, uint64_t *rx_pkts, uint64_t *tx_pkts);

#endif /* NET_DISCOVERY_H */
