#ifndef __NAT46_MAPS_H
#define __NAT46_MAPS_H

#include <linux/types.h>
#include <linux/bpf.h>

/* Synthetic IPv4 Pool: 198.18.0.0/15 (0xC6120000 - 0xC613FFFF) */
#define SYNTH_IPV4_NET   0xC6120000
#define SYNTH_IPV4_MASK  0xFFFE0000
#define SYNTH_START_IP   0xC6120001
#define SYNTH_END_IP     0xC613FFFE

/* Forward Mapping: Synthetic IPv4 -> Real Destination IPv6 */
struct nat46_forward_val {
    struct in6_addr target_v6;
    __u32 client_v4;       /* Client source IPv4 */
    __u32 last_seen_sec;
};

/* Reverse Mapping: Real Destination IPv6 -> Synthetic IPv4 & Client IPv4 */
struct nat46_reverse_val {
    __u32 synthetic_v4;
    __u32 client_v4;
    __u32 last_seen_sec;
};

/* Global NAT46 & Starlink Configuration Map Struct */
struct nat46_config {
    struct in6_addr router_v6_src; /* Starlink Delegated IPv6 Address of Router */
    __u32 starlink_ifindex;        /* Starlink WAN interface ifindex */
    __u32 lan_ifindex;             /* Local LAN interface ifindex */
    unsigned char starlink_gw_mac[6]; /* Next-hop MAC of Starlink Router/Dish */
    unsigned char lan_gw_mac[6];      /* Next-hop MAC of LAN Gateway / Client */
    __u32 enabled;                 /* 1 = NAT46 Bypass Enabled, 0 = Disabled */
    __u32 total_translated_egress;
    __u32 total_translated_ingress;
};

#endif /* __NAT46_MAPS_H */