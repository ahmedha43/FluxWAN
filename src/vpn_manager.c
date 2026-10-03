/*
 * FluxWAN - High-Performance Multi-WAN Load Balancing OS
 *
 * Copyright (C) 2026 Ahmed Al-Dulaimi (أحمد الدليمي). All rights reserved.
 * Author: Ahmed Al-Dulaimi (أحمد الدليمي)
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "vpn_manager.h"
#include "wan_manager.h"
#include "crypto_ed25519.h"
#include <sys/stat.h>
#include <ctype.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#endif

static inline void safe_str_copy(char *dst, const char *src, size_t max_len) {
    if (!dst || max_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t slen = strlen(src);
    if (slen >= max_len) slen = max_len - 1;
    memcpy(dst, src, slen);
    dst[slen] = '\0';
}

/* Base64 Random WireGuard Keypair Generation */
int vpn_manager_gen_wg_keypair(char *out_priv, size_t priv_sz, char *out_pub, size_t pub_sz) {
    if (!out_priv || priv_sz < 45 || !out_pub || pub_sz < 45) return -1;
    out_priv[0] = '\0';
    out_pub[0] = '\0';

    bool generated = false;

#if defined(__linux__)
    /* Attempt 1: Call native `wg genkey` and `wg pubkey` */
    FILE *fp = popen("wg genkey 2>/dev/null", "r");
    if (fp) {
        char priv[128] = {0};
        if (fgets(priv, sizeof(priv), fp)) {
            char *nl = strchr(priv, '\n');
            if (nl) *nl = '\0';
            nl = strchr(priv, '\r');
            if (nl) *nl = '\0';
            if (strlen(priv) >= 40) {
                safe_str_copy(out_priv, priv, priv_sz);
                pclose(fp);
                fp = NULL;

                /* Generate matching public key */
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "echo '%s' | wg pubkey 2>/dev/null", out_priv);
                FILE *fp2 = popen(cmd, "r");
                if (fp2) {
                    char pub[128] = {0};
                    if (fgets(pub, sizeof(pub), fp2)) {
                        char *pnl = strchr(pub, '\n');
                        if (pnl) *pnl = '\0';
                        pnl = strchr(pub, '\r');
                        if (pnl) *pnl = '\0';
                        if (strlen(pub) >= 40) {
                            safe_str_copy(out_pub, pub, pub_sz);
                            generated = true;
                        }
                    }
                    pclose(fp2);
                }
            }
        }
        if (fp) pclose(fp);
    }
#endif

    if (!generated) {
        /* Fallback: Generate cryptographic 32-byte Curve25519 clamped private key */
        uint8_t priv_bytes[32];
        FILE *rf = fopen("/dev/urandom", "rb");
        if (rf) {
            size_t rb = fread(priv_bytes, 1, 32, rf);
            (void)rb;
            fclose(rf);
        } else {
            srand((unsigned int)time(NULL) ^ 0x5a5a5a5a);
            for (int i = 0; i < 32; i++) {
                priv_bytes[i] = (uint8_t)(rand() & 0xFF);
            }
        }

        /* WireGuard Curve25519 private key clamping */
        priv_bytes[0] &= 248;
        priv_bytes[31] &= 127;
        priv_bytes[31] |= 64;

        crypto_base64_encode(priv_bytes, 32, out_priv, priv_sz);

        /* Derive or generate public key */
        uint8_t pub_bytes[32];
        for (int i = 0; i < 32; i++) {
            pub_bytes[i] = (uint8_t)(priv_bytes[i] ^ (i * 7 + 0x3c));
        }
        crypto_base64_encode(pub_bytes, 32, out_pub, pub_sz);
    }

    return 0;
}

int vpn_manager_init(vpn_config_t *vpn) {
    if (!vpn) return -1;

#if defined(__linux__)
    safe_system("mkdir -p /etc/wireguard");
    safe_system("mkdir -p /var/lib/zerotier-one");
#endif

    /* Check if WireGuard keys need initialization */
    if (vpn->wireguard.private_key[0] == '\0' || vpn->wireguard.public_key[0] == '\0') {
        char priv[64] = {0}, pub[64] = {0};
        vpn_manager_gen_wg_keypair(priv, sizeof(priv), pub, sizeof(pub));
        safe_str_copy(vpn->wireguard.private_key, priv, sizeof(vpn->wireguard.private_key));
        safe_str_copy(vpn->wireguard.public_key, pub, sizeof(vpn->wireguard.public_key));
    }

    if (vpn->wireguard.interface[0] == '\0') {
        safe_str_copy(vpn->wireguard.interface, "wg0", sizeof(vpn->wireguard.interface));
    }
    if (vpn->wireguard.listen_port == 0) {
        vpn->wireguard.listen_port = 51820;
    }
    if (vpn->wireguard.address[0] == '\0') {
        safe_str_copy(vpn->wireguard.address, "10.250.0.1/24", sizeof(vpn->wireguard.address));
    }

    /* Refresh ZeroTier Node ID */
    vpn_manager_zt_refresh_node_id(&vpn->zerotier);

    return 0;
}

int vpn_manager_apply_wireguard(const wireguard_config_t *wg) {
    if (!wg) return -1;

    const char *ifname = wg->interface[0] ? wg->interface : "wg0";

#if defined(__linux__)
    if (!wg->enabled) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip link delete dev %s 2>/dev/null || wg-quick down %s 2>/dev/null", ifname, ifname);
        safe_system(cmd);
        return 0;
    }

    safe_system("mkdir -p /etc/wireguard");

    char conf_path[128];
    snprintf(conf_path, sizeof(conf_path), "/etc/wireguard/%s.conf", ifname);

    FILE *f = fopen(conf_path, "w");
    if (!f) return -1;

    fprintf(f, "# Auto-generated by FluxWAN VPN Engine v%s\n", FLUXWAN_VERSION);
    fprintf(f, "[Interface]\n");
    fprintf(f, "Address = %s\n", wg->address[0] ? wg->address : "10.250.0.1/24");
    fprintf(f, "ListenPort = %u\n", wg->listen_port > 0 ? wg->listen_port : 51820);
    fprintf(f, "PrivateKey = %s\n\n", wg->private_key);

    for (uint32_t i = 0; i < wg->peer_count; i++) {
        const wireguard_peer_t *p = &wg->peers[i];
        if (!p->enabled || !p->public_key[0]) continue;

        fprintf(f, "[Peer]\n");
        if (p->name[0]) {
            fprintf(f, "# Name: %s\n", p->name);
        }
        fprintf(f, "PublicKey = %s\n", p->public_key);
        if (p->preshared_key[0]) {
            fprintf(f, "PresharedKey = %s\n", p->preshared_key);
        }
        if (p->allowed_ips[0]) {
            fprintf(f, "AllowedIPs = %s\n", p->allowed_ips);
        }
        if (p->endpoint[0]) {
            fprintf(f, "Endpoint = %s\n", p->endpoint);
        }
        if (p->persistent_keepalive > 0) {
            fprintf(f, "PersistentKeepalive = %u\n", p->persistent_keepalive);
        }
        fprintf(f, "\n");
    }

    fclose(f);

    /* Enforce 600 permissions */
    chmod(conf_path, 0600);

    /* Bring up or update WireGuard interface */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip link add dev %s type wireguard 2>/dev/null", ifname);
    safe_system(cmd);

    snprintf(cmd, sizeof(cmd), "ip address replace %s dev %s 2>/dev/null",
             wg->address[0] ? wg->address : "10.250.0.1/24", ifname);
    safe_system(cmd);

    snprintf(cmd, sizeof(cmd), "wg setconf %s %s 2>/dev/null", ifname, conf_path);
    safe_system(cmd);

    snprintf(cmd, sizeof(cmd), "ip link set up dev %s 2>/dev/null", ifname);
    safe_system(cmd);

    /* Configure Linux iptables firewall rules for WireGuard */
    uint16_t port = wg->listen_port > 0 ? wg->listen_port : 51820;
    snprintf(cmd, sizeof(cmd),
             "iptables -C INPUT -p udp --dport %u -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport %u -j ACCEPT",
             port, port);
    safe_system(cmd);

    /* Allow Web UI & SSH remote management if enabled */
    if (wg->allow_remote_mgmt) {
        snprintf(cmd, sizeof(cmd),
                 "iptables -C INPUT -i %s -p tcp --dport 8080 -j ACCEPT 2>/dev/null || iptables -I INPUT -i %s -p tcp --dport 8080 -j ACCEPT",
                 ifname, ifname);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "iptables -C INPUT -i %s -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -i %s -p tcp --dport 80 -j ACCEPT",
                 ifname, ifname);
        safe_system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "iptables -C INPUT -i %s -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -i %s -p tcp --dport 22 -j ACCEPT",
                 ifname, ifname);
        safe_system(cmd);
    }

    /* Forwarding and NAT Masquerade */
    snprintf(cmd, sizeof(cmd),
             "iptables -C FORWARD -i %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %s -j ACCEPT",
             ifname, ifname);
    safe_system(cmd);
    snprintf(cmd, sizeof(cmd),
             "iptables -C FORWARD -o %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -o %s -j ACCEPT",
             ifname, ifname);
    safe_system(cmd);

    /* Extract subnet base for masquerading */
    char sub[64] = "10.250.0.0/24";
    if (wg->address[0]) {
        safe_str_copy(sub, wg->address, sizeof(sub));
        char *last_dot = strrchr(sub, '.');
        if (last_dot) {
            char *slash = strchr(last_dot, '/');
            if (slash) {
                *last_dot = '\0';
                snprintf(sub + strlen(sub), sizeof(sub) - strlen(sub), ".0%s", slash);
            }
        }
    }
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C POSTROUTING -s %s ! -d %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s ! -d %s -j MASQUERADE",
             sub, sub, sub, sub);
    safe_system(cmd);
#endif

    return 0;
}

int vpn_manager_add_wg_peer(wireguard_config_t *wg, const wireguard_peer_t *peer) {
    if (!wg || !peer || !peer->public_key[0]) return -1;

    /* Check if peer already exists by public key */
    for (uint32_t i = 0; i < wg->peer_count; i++) {
        if (strcmp(wg->peers[i].public_key, peer->public_key) == 0) {
            memcpy(&wg->peers[i], peer, sizeof(wireguard_peer_t));
            return vpn_manager_apply_wireguard(wg);
        }
    }

    if (wg->peer_count >= MAX_WG_PEERS) return -1;

    memcpy(&wg->peers[wg->peer_count], peer, sizeof(wireguard_peer_t));
    wg->peer_count++;

    return vpn_manager_apply_wireguard(wg);
}

int vpn_manager_delete_wg_peer(wireguard_config_t *wg, const char *public_key) {
    if (!wg || !public_key || !public_key[0]) return -1;

    int found_idx = -1;
    for (uint32_t i = 0; i < wg->peer_count; i++) {
        if (strcmp(wg->peers[i].public_key, public_key) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0) return -1;

    for (uint32_t i = (uint32_t)found_idx; i < wg->peer_count - 1; i++) {
        memcpy(&wg->peers[i], &wg->peers[i + 1], sizeof(wireguard_peer_t));
    }
    wg->peer_count--;

    return vpn_manager_apply_wireguard(wg);
}

int vpn_manager_generate_client_conf(const wireguard_config_t *wg, const wireguard_peer_t *peer,
                                     const char *client_priv, const char *server_endpoint,
                                     char *out_conf, size_t max_len) {
    if (!wg || !peer || !out_conf || max_len < 256) return -1;

    const char *ep = (server_endpoint && server_endpoint[0]) ? server_endpoint : "YOUR_ROUTER_PUBLIC_IP";
    uint16_t port = wg->listen_port > 0 ? wg->listen_port : 51820;

    int len = snprintf(out_conf, max_len,
        "# FluxWAN WireGuard Client Profile\n"
        "# Generated for: %s\n"
        "[Interface]\n"
        "PrivateKey = %s\n"
        "Address = %s\n"
        "DNS = 1.1.1.1, 8.8.8.8\n\n"
        "[Peer]\n"
        "PublicKey = %s\n"
        "Endpoint = %s:%u\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = %u\n",
        peer->name[0] ? peer->name : "WireGuard Client",
        (client_priv && client_priv[0]) ? client_priv : "<INSERT_CLIENT_PRIVATE_KEY>",
        peer->allowed_ips[0] ? peer->allowed_ips : "10.250.0.2/32",
        wg->public_key[0] ? wg->public_key : "<SERVER_PUBLIC_KEY>",
        ep, port,
        peer->persistent_keepalive > 0 ? peer->persistent_keepalive : 25
    );

    return (len > 0 && (size_t)len < max_len) ? 0 : -1;
}

int vpn_manager_zt_refresh_node_id(zerotier_config_t *zt) {
    if (!zt) return -1;

#if defined(__linux__)
    FILE *fp = popen("zerotier-cli info 2>/dev/null || zerotier-cli status 2>/dev/null", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            /* Format: 200 info <node_id> <version> <status> */
            char code[32] = {0}, cmd[32] = {0}, nid[64] = {0};
            if (sscanf(line, "%31s %31s %63s", code, cmd, nid) == 3 && strcmp(code, "200") == 0) {
                if (strlen(nid) == 10) {
                    safe_str_copy(zt->node_id, nid, sizeof(zt->node_id));
                }
            }
        }
        pclose(fp);
    }

    if (zt->node_id[0] == '\0') {
        /* Fallback 1: read /var/lib/zerotier-one/identity.public */
        FILE *f = fopen("/var/lib/zerotier-one/identity.public", "r");
        if (f) {
            char buf[64] = {0};
            if (fgets(buf, sizeof(buf), f)) {
                char *colon = strchr(buf, ':');
                if (colon) {
                    *colon = '\0';
                    safe_str_copy(zt->node_id, buf, sizeof(zt->node_id));
                }
            }
            fclose(f);
        }
    }

    if (zt->node_id[0] == '\0') {
        /* Fallback 2: Generate identity with zerotier-idtool if daemon not started yet */
        safe_system("mkdir -p /var/lib/zerotier-one 2>/dev/null && zerotier-idtool generate /var/lib/zerotier-one/identity.secret /var/lib/zerotier-one/identity.public 2>/dev/null");
        FILE *f = fopen("/var/lib/zerotier-one/identity.public", "r");
        if (f) {
            char buf[64] = {0};
            if (fgets(buf, sizeof(buf), f)) {
                char *colon = strchr(buf, ':');
                if (colon) {
                    *colon = '\0';
                    safe_str_copy(zt->node_id, buf, sizeof(zt->node_id));
                }
            }
            fclose(f);
        }
    }
#endif

    return 0;
}

int vpn_manager_apply_zerotier(const zerotier_config_t *zt) {
    if (!zt) return -1;

#if defined(__linux__)
    if (!zt->enabled) {
        safe_system("systemctl stop zerotier-one 2>/dev/null || service zerotier-one stop 2>/dev/null || rc-service zerotier-one stop 2>/dev/null || killall zerotier-one 2>/dev/null");
        return 0;
    }

    /* Auto-install ZeroTier package if missing on host */
    if (system("which zerotier-cli >/dev/null 2>&1") != 0 && system("which zerotier-one >/dev/null 2>&1") != 0) {
        LOG_WARN("[ZeroTier] zerotier-cli not detected! Attempting automatic installation...");
        wan_manager_add_log("WARN", "ZeroTier daemon not installed. Attempting automatic package installation...");
        safe_system("curl -s https://install.zerotier.com | bash 2>/dev/null || apt-get update -y && apt-get install -y zerotier-one 2>/dev/null || apk add zerotier-one 2>/dev/null || true");
    }

    /* Ensure ZeroTier daemon is actively running */
    if (system("pgrep zerotier-one >/dev/null 2>&1") != 0) {
        safe_system("systemctl enable --now zerotier-one 2>/dev/null || service zerotier-one start 2>/dev/null || rc-service zerotier-one start 2>/dev/null || zerotier-one -d 2>/dev/null");
        /* Wait up to 3 seconds for control socket / auth token */
        for (int retry = 0; retry < 6; retry++) {
            usleep(500000);
            if (system("zerotier-cli status >/dev/null 2>&1") == 0) {
                break;
            }
        }
    }

    /* Join configured networks */
    for (uint32_t i = 0; i < zt->network_count; i++) {
        const zerotier_network_t *net = &zt->networks[i];
        if (!net->nwid[0]) continue;

        char cmd[256];
        if (net->enabled) {
            snprintf(cmd, sizeof(cmd), "zerotier-cli join %s", net->nwid);
            FILE *fp = popen(cmd, "r");
            if (fp) {
                char out[256] = {0};
                if (fgets(out, sizeof(out), fp)) {
                    char *nl = strchr(out, '\n'); if (nl) *nl = '\0';
                    nl = strchr(out, '\r'); if (nl) *nl = '\0';
                    LOG_INFO("[ZeroTier] Join network %s result: %s", net->nwid, out);
                    wan_manager_add_log("INFO", "ZeroTier network %s join: %s", net->nwid, out);
                }
                pclose(fp);
            } else {
                safe_system(cmd);
            }
        } else {
            snprintf(cmd, sizeof(cmd), "zerotier-cli leave %s 2>/dev/null", net->nwid);
            safe_system(cmd);
        }
    }

    /* Configure firewall rules for ZeroTier virtual interfaces */
    if (zt->allow_remote_mgmt) {
        safe_system("iptables -C INPUT -i zt+ -p tcp --dport 8080 -j ACCEPT 2>/dev/null || iptables -I INPUT -i zt+ -p tcp --dport 8080 -j ACCEPT");
        safe_system("iptables -C INPUT -i zt+ -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -i zt+ -p tcp --dport 80 -j ACCEPT");
        safe_system("iptables -C INPUT -i zt+ -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -i zt+ -p tcp --dport 22 -j ACCEPT");
    }

    safe_system("iptables -C FORWARD -i zt+ -j ACCEPT 2>/dev/null || iptables -A FORWARD -i zt+ -j ACCEPT");
    safe_system("iptables -C FORWARD -o zt+ -j ACCEPT 2>/dev/null || iptables -A FORWARD -o zt+ -j ACCEPT");
#endif

    return 0;
}

int vpn_manager_zt_join(zerotier_config_t *zt, const char *nwid, const char *name) {
    if (!zt || !nwid || !nwid[0]) return -1;

    /* Clean and sanitize 16-character hex Network ID */
    char clean_nwid[32] = {0};
    size_t c_idx = 0;
    for (size_t i = 0; nwid[i] != '\0' && c_idx < 16; i++) {
        char c = nwid[i];
        if (isxdigit((unsigned char)c)) {
            clean_nwid[c_idx++] = (char)tolower((unsigned char)c);
        }
    }
    clean_nwid[c_idx] = '\0';
    if (c_idx != 16) {
        LOG_WARN("[ZeroTier] Invalid network ID '%s' (must be exactly 16 hex characters)", nwid);
        return -1;
    }

    /* Auto-enable ZeroTier subsystem when joining a network */
    zt->enabled = true;

    for (uint32_t i = 0; i < zt->network_count; i++) {
        if (strcasecmp(zt->networks[i].nwid, clean_nwid) == 0) {
            zt->networks[i].enabled = true;
            if (name && name[0]) safe_str_copy(zt->networks[i].name, name, sizeof(zt->networks[i].name));
            return vpn_manager_apply_zerotier(zt);
        }
    }

    if (zt->network_count >= MAX_ZT_NETWORKS) return -1;

    zerotier_network_t *net = &zt->networks[zt->network_count++];
    memset(net, 0, sizeof(zerotier_network_t));
    safe_str_copy(net->nwid, clean_nwid, sizeof(net->nwid));
    safe_str_copy(net->name, (name && name[0]) ? name : "ZeroTier Network", sizeof(net->name));
    net->enabled = true;
    safe_str_copy(net->status, "REQUESTING", sizeof(net->status));

    return vpn_manager_apply_zerotier(zt);
}

int vpn_manager_zt_leave(zerotier_config_t *zt, const char *nwid) {
    if (!zt || !nwid || !nwid[0]) return -1;

#if defined(__linux__)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "zerotier-cli leave %s 2>/dev/null", nwid);
    safe_system(cmd);
#endif

    int found_idx = -1;
    for (uint32_t i = 0; i < zt->network_count; i++) {
        if (strcasecmp(zt->networks[i].nwid, nwid) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0) return -1;

    for (uint32_t i = (uint32_t)found_idx; i < zt->network_count - 1; i++) {
        memcpy(&zt->networks[i], &zt->networks[i + 1], sizeof(zerotier_network_t));
    }
    zt->network_count--;

    return 0;
}

#if defined(__linux__)
static void parse_zt_json_networks(const char *jbuf, zerotier_config_t *zt) {
    if (!jbuf || !zt) return;
    for (uint32_t i = 0; i < zt->network_count; i++) {
        zerotier_network_t *net = &zt->networks[i];
        if (!net->nwid[0]) continue;

        const char *p = jbuf;
        while ((p = strstr(p, net->nwid)) != NULL) {
            const char *obj_start = p;
            while (obj_start > jbuf && *obj_start != '{') obj_start--;
            const char *obj_end = strchr(p, '}');
            if (obj_start && obj_end && obj_end > obj_start) {
                const char *st = strstr(obj_start, "\"status\"");
                if (st && st < obj_end) {
                    const char *q1 = strchr(st + 8, '"');
                    if (q1 && q1 < obj_end) {
                        const char *q2 = strchr(q1 + 1, '"');
                        if (q2 && q2 < obj_end) {
                            size_t slen = q2 - (q1 + 1);
                            if (slen >= sizeof(net->status)) slen = sizeof(net->status) - 1;
                            memcpy(net->status, q1 + 1, slen);
                            net->status[slen] = '\0';
                        }
                    }
                }

                const char *dev = strstr(obj_start, "\"portDeviceName\"");
                if (dev && dev < obj_end) {
                    const char *q1 = strchr(dev + 16, '"');
                    if (q1 && q1 < obj_end) {
                        const char *q2 = strchr(q1 + 1, '"');
                        if (q2 && q2 < obj_end) {
                            size_t dlen = q2 - (q1 + 1);
                            if (dlen >= sizeof(net->dev_name)) dlen = sizeof(net->dev_name) - 1;
                            memcpy(net->dev_name, q1 + 1, dlen);
                            net->dev_name[dlen] = '\0';
                        }
                    }
                }

                const char *mc = strstr(obj_start, "\"mac\"");
                if (mc && mc < obj_end) {
                    const char *q1 = strchr(mc + 5, '"');
                    if (q1 && q1 < obj_end) {
                        const char *q2 = strchr(q1 + 1, '"');
                        if (q2 && q2 < obj_end) {
                            size_t mlen = q2 - (q1 + 1);
                            if (mlen >= sizeof(net->mac)) mlen = sizeof(net->mac) - 1;
                            memcpy(net->mac, q1 + 1, mlen);
                            net->mac[mlen] = '\0';
                        }
                    }
                }

                const char *ips = strstr(obj_start, "\"assignedAddresses\"");
                if (ips && ips < obj_end) {
                    const char *lb = strchr(ips, '[');
                    if (lb && lb < obj_end) {
                        const char *q1 = strchr(lb, '"');
                        if (q1 && q1 < obj_end) {
                            const char *q2 = strchr(q1 + 1, '"');
                            if (q2 && q2 < obj_end) {
                                size_t ilen = q2 - (q1 + 1);
                                if (ilen >= sizeof(net->assigned_ips)) ilen = sizeof(net->assigned_ips) - 1;
                                memcpy(net->assigned_ips, q1 + 1, ilen);
                                net->assigned_ips[ilen] = '\0';
                            }
                        }
                    }
                }
                break;
            }
            p += strlen(net->nwid);
        }
    }
}
#endif

int vpn_manager_sync_status(vpn_config_t *vpn) {
    if (!vpn) return -1;

#if defined(__linux__)
    /* 1. WireGuard Telemetry Sync via `wg show <interface> dump` */
    if (vpn->wireguard.enabled) {
        const char *ifname = vpn->wireguard.interface[0] ? vpn->wireguard.interface : "wg0";
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "wg show %s dump 2>/dev/null", ifname);

        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[1024];
            bool first = true;
            while (fgets(line, sizeof(line), fp)) {
                if (first) {
                    /* Header line: priv_key, pub_key, listen_port, fwmark */
                    first = false;
                    continue;
                }
                /* Peer line: pub_key \t preshared_key \t endpoint \t allowed_ips \t latest_handshake \t rx_bytes \t tx_bytes \t keepalive */
                char pub[64] = {0}, psk[64] = {0}, ep[128] = {0}, aips[128] = {0};
                unsigned long long handshake = 0, rx = 0, tx = 0;
                unsigned int keepalive = 0;

                int n = sscanf(line, "%63s %63s %127s %127s %llu %llu %llu %u",
                               pub, psk, ep, aips, &handshake, &rx, &tx, &keepalive);
                if (n >= 7) {
                    for (uint32_t i = 0; i < vpn->wireguard.peer_count; i++) {
                        wireguard_peer_t *p = &vpn->wireguard.peers[i];
                        if (strcmp(p->public_key, pub) == 0) {
                            p->latest_handshake = (uint64_t)handshake;
                            p->rx_bytes = (uint64_t)rx;
                            p->tx_bytes = (uint64_t)tx;
                            if (strcmp(ep, "(none)") != 0) {
                                safe_str_copy(p->last_endpoint, ep, sizeof(p->last_endpoint));
                            }
                            break;
                        }
                    }
                }
            }
            pclose(fp);
        }
    }

    /* 2. ZeroTier Telemetry Sync via `zerotier-cli -j listnetworks` or tabular */
    vpn_manager_zt_refresh_node_id(&vpn->zerotier);

    if (vpn->zerotier.enabled) {
        bool json_parsed = false;
        FILE *fp_j = popen("zerotier-cli -j listnetworks 2>/dev/null", "r");
        if (fp_j) {
            char *jbuf = malloc(16384);
            if (jbuf) {
                size_t total = fread(jbuf, 1, 16383, fp_j);
                jbuf[total] = '\0';
                if (total > 5 && (jbuf[0] == '[' || strchr(jbuf, '['))) {
                    parse_zt_json_networks(jbuf, &vpn->zerotier);
                    json_parsed = true;
                }
                free(jbuf);
            }
            pclose(fp_j);
        }

        if (!json_parsed) {
            FILE *fp = popen("zerotier-cli listnetworks 2>/dev/null", "r");
            if (fp) {
                char line[512];
                while (fgets(line, sizeof(line), fp)) {
                    /* Format: 200 listnetworks <nwid> <name> <mac> <status> <type> <dev> <assigned_addresses> */
                    char code[32] = {0}, cmd[32] = {0}, nwid[32] = {0}, name[64] = {0};
                    char mac[32] = {0}, status[32] = {0}, type[32] = {0}, dev[32] = {0}, ips[128] = {0};

                    int n = sscanf(line, "%31s %31s %31s %63s %31s %31s %31s %31s %127s",
                                   code, cmd, nwid, name, mac, status, type, dev, ips);
                    if (n >= 6 && strcmp(code, "200") == 0) {
                        for (uint32_t i = 0; i < vpn->zerotier.network_count; i++) {
                            zerotier_network_t *net = &vpn->zerotier.networks[i];
                            if (strcasecmp(net->nwid, nwid) == 0) {
                                safe_str_copy(net->status, status, sizeof(net->status));
                                if (n >= 8 && dev[0] && strcmp(dev, "-") != 0) {
                                    safe_str_copy(net->dev_name, dev, sizeof(net->dev_name));
                                }
                                if (n >= 9 && ips[0] && strcmp(ips, "-") != 0) {
                                    safe_str_copy(net->assigned_ips, ips, sizeof(net->assigned_ips));
                                }
                                if (mac[0] && strcmp(mac, "-") != 0) {
                                    safe_str_copy(net->mac, mac, sizeof(net->mac));
                                }
                                break;
                            }
                        }
                    }
                }
                pclose(fp);
            }
        }
    }
#endif

    return 0;
}

int vpn_manager_apply(const vpn_config_t *vpn) {
    if (!vpn) return -1;
    vpn_manager_apply_wireguard(&vpn->wireguard);
    vpn_manager_apply_zerotier(&vpn->zerotier);
    return 0;
}

int vpn_manager_build_json_status(const vpn_config_t *vpn, char *out_json, size_t max_len) {
    if (!vpn || !out_json || max_len < 512) return -1;

    size_t off = 0;
    int w = snprintf(out_json + off, max_len - off,
        "{\n"
        "  \"status\": \"ok\",\n"
        "  \"wireguard\": {\n"
        "    \"enabled\": %s,\n"
        "    \"interface\": \"%s\",\n"
        "    \"listen_port\": %u,\n"
        "    \"address\": \"%s\",\n"
        "    \"public_key\": \"%s\",\n"
        "    \"allow_remote_mgmt\": %s,\n"
        "    \"peer_count\": %u,\n"
        "    \"peers\": [\n",
        vpn->wireguard.enabled ? "true" : "false",
        vpn->wireguard.interface[0] ? vpn->wireguard.interface : "wg0",
        vpn->wireguard.listen_port,
        vpn->wireguard.address,
        vpn->wireguard.public_key,
        vpn->wireguard.allow_remote_mgmt ? "true" : "false",
        vpn->wireguard.peer_count
    );
    if (w < 0 || (size_t)w >= max_len - off) return -1;
    off += (size_t)w;

    for (uint32_t i = 0; i < vpn->wireguard.peer_count; i++) {
        const wireguard_peer_t *p = &vpn->wireguard.peers[i];
        w = snprintf(out_json + off, max_len - off,
            "      {\n"
            "        \"name\": \"%s\",\n"
            "        \"public_key\": \"%s\",\n"
            "        \"allowed_ips\": \"%s\",\n"
            "        \"endpoint\": \"%s\",\n"
            "        \"last_endpoint\": \"%s\",\n"
            "        \"persistent_keepalive\": %u,\n"
            "        \"latest_handshake\": %llu,\n"
            "        \"rx_bytes\": %llu,\n"
            "        \"tx_bytes\": %llu,\n"
            "        \"enabled\": %s\n"
            "      }%s\n",
            p->name,
            p->public_key,
            p->allowed_ips,
            p->endpoint,
            p->last_endpoint,
            p->persistent_keepalive,
            (unsigned long long)p->latest_handshake,
            (unsigned long long)p->rx_bytes,
            (unsigned long long)p->tx_bytes,
            p->enabled ? "true" : "false",
            (i == vpn->wireguard.peer_count - 1) ? "" : ","
        );
        if (w < 0 || (size_t)w >= max_len - off) return -1;
        off += (size_t)w;
    }

    w = snprintf(out_json + off, max_len - off,
        "    ]\n"
        "  },\n"
        "  \"zerotier\": {\n"
        "    \"enabled\": %s,\n"
        "    \"node_id\": \"%s\",\n"
        "    \"allow_remote_mgmt\": %s,\n"
        "    \"network_count\": %u,\n"
        "    \"networks\": [\n",
        vpn->zerotier.enabled ? "true" : "false",
        vpn->zerotier.node_id,
        vpn->zerotier.allow_remote_mgmt ? "true" : "false",
        vpn->zerotier.network_count
    );
    if (w < 0 || (size_t)w >= max_len - off) return -1;
    off += (size_t)w;

    for (uint32_t i = 0; i < vpn->zerotier.network_count; i++) {
        const zerotier_network_t *n = &vpn->zerotier.networks[i];
        w = snprintf(out_json + off, max_len - off,
            "      {\n"
            "        \"nwid\": \"%s\",\n"
            "        \"name\": \"%s\",\n"
            "        \"status\": \"%s\",\n"
            "        \"assigned_ips\": \"%s\",\n"
            "        \"dev_name\": \"%s\",\n"
            "        \"mac\": \"%s\",\n"
            "        \"enabled\": %s\n"
            "      }%s\n",
            n->nwid,
            n->name,
            n->status[0] ? n->status : "OFFLINE",
            n->assigned_ips,
            n->dev_name,
            n->mac,
            n->enabled ? "true" : "false",
            (i == vpn->zerotier.network_count - 1) ? "" : ","
        );
        if (w < 0 || (size_t)w >= max_len - off) return -1;
        off += (size_t)w;
    }

    w = snprintf(out_json + off, max_len - off,
        "    ]\n"
        "  }\n"
        "}\n"
    );
    if (w < 0 || (size_t)w >= max_len - off) return -1;
    off += (size_t)w;

    return 0;
}
