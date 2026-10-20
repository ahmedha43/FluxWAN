#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "fluxwan.h"
#include "proxy_manager.h"
#include "dns64_daemon.h"

static inline void safe_str_copy(char *dst, const char *src, size_t max_len) {
    if (!dst || max_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t slen = strlen(src);
    if (slen >= max_len) slen = max_len - 1;
    memcpy(dst, src, slen);
    dst[slen] = '\0';
}

int main(void) {
    printf("=================================================================\n");
    printf("   FLUXWAN: TESTING MULTI-SERVER PROXY BALANCER & FAILOVER        \n");
    printf("=================================================================\n");

    /* 1. Test Multi-Server Endpoints Parsing & Synchronization */
    {
        printf("\n[1/3] Testing Multi-Server Endpoints Parsing & Synchronization...\n");
        wan_proxy_config_t p;
        memset(&p, 0, sizeof(p));
        p.enabled = true;
        p.strategy = PROXY_STRATEGY_FAILOVER;

        /* Node 1: Amsterdam VPS 1 */
        const char *uri1 = "vless://74f71f59-7168-40ab-b556-65aec1b68dd6@31.76.76.50:80?type=ws&security=none&path=/&host=portal.oodi.iq#AMS_Node1";
        /* Node 2: Amsterdam VPS 2 */
        const char *uri2 = "vless://5fbfc396-9937-4d6c-b35a-b30e7226564d@31.76.79.60:8080?type=ws&security=none&path=/&host=portal.oodi.iq#AMS_Node2";
        /* Node 3: Amsterdam VPS 3 */
        const char *uri3 = "vless://08e4a377-abef-41a0-8aae-aa23b58b5538@31.76.79.109:80?type=ws&security=none&path=/&host=portal.oodi.iq#AMS_Node3";

        safe_str_copy(p.servers[0].raw_uri, uri1, sizeof(p.servers[0].raw_uri));
        safe_str_copy(p.servers[1].raw_uri, uri2, sizeof(p.servers[1].raw_uri));
        safe_str_copy(p.servers[2].raw_uri, uri3, sizeof(p.servers[2].raw_uri));

        proxy_manager_sync_servers(&p);

        assert(p.server_count == 3);
        assert(strcmp(p.servers[0].server, "31.76.76.50") == 0);
        assert(p.servers[0].port == 80);
        assert(strcmp(p.servers[1].server, "31.76.79.60") == 0);
        assert(p.servers[1].port == 8080);
        assert(strcmp(p.servers[2].server, "31.76.79.109") == 0);
        assert(p.servers[2].port == 80);

        /* Verify backward compatibility mirroring: top-level fields mirror servers[0] */
        assert(strcmp(p.server, "31.76.76.50") == 0);
        assert(p.port == 80);
        assert(strcmp(p.uuid, "74f71f59-7168-40ab-b556-65aec1b68dd6") == 0);
        printf("    -> Successfully parsed 3 distinct VLESS endpoints into wan_proxy_config_t.\n");
        printf("    -> Primary legacy fields properly mirrored servers[0].\n");
    }

    /* 2. Test Configuration Generation with Load Balancer & Failover Strategies */
    {
        printf("\n[2/3] Testing Multi-Server Config Generation (Round-Robin & Least-Ping)...\n");
        wan_config_t wan;
        memset(&wan, 0, sizeof(wan));
        wan.id = 1;
        safe_str_copy(wan.name, "eth1", sizeof(wan.name));
        safe_str_copy(wan.label, "WAN1_FIBER", sizeof(wan.label));
        wan.enabled = true;
        wan.proxy.enabled = true;
        wan.proxy.strategy = PROXY_STRATEGY_ROUND_ROBIN;

        safe_str_copy(wan.proxy.servers[0].raw_uri, "vless://11111111-1111-1111-1111-111111111111@31.76.76.50:80?type=ws&security=none&path=/#S1", sizeof(wan.proxy.servers[0].raw_uri));
        safe_str_copy(wan.proxy.servers[1].raw_uri, "vless://22222222-2222-2222-2222-222222222222@31.76.79.60:8080?type=ws&security=none&path=/#S2", sizeof(wan.proxy.servers[1].raw_uri));
        proxy_manager_sync_servers(&wan.proxy);

        char out_path[256];
        int rc = proxy_manager_generate_config(&wan, 0, out_path, sizeof(out_path));
        assert(rc == 0);

        /* Verify file contents */
        FILE *f = fopen(out_path, "r");
        assert(f != NULL);
        char content[8192];
        size_t n = fread(content, 1, sizeof(content) - 1, f);
        content[n] = '\0';
        fclose(f);

        assert(strstr(content, "\"proxy-out-0\"") != NULL);
        assert(strstr(content, "\"proxy-out-1\"") != NULL);
        assert(strstr(content, "\"observatory\"") != NULL);
        assert(strstr(content, "\"roundRobin\"") != NULL);
        assert(strstr(content, "\"balancerTag\": \"wan_balancer\"") != NULL);
        printf("    -> Generated Xray multi-server config with active roundRobin load balancing.\n");

        /* Switch strategy to leastPing failover */
        wan.proxy.strategy = PROXY_STRATEGY_FAILOVER;
        rc = proxy_manager_generate_config(&wan, 0, out_path, sizeof(out_path));
        assert(rc == 0);

        f = fopen(out_path, "r");
        assert(f != NULL);
        n = fread(content, 1, sizeof(content) - 1, f);
        content[n] = '\0';
        fclose(f);

        assert(strstr(content, "\"leastPing\"") != NULL);
        printf("    -> Successfully switched and verified leastPing observatory failover strategy.\n");
    }

    /* 3. Test High-Speed RAM DNS Cache Functions */
    {
        printf("\n[3/3] Testing High-Speed In-Memory RAM DNS Cache...\n");
        extern uint32_t dns_compute_question_hash(const unsigned char *buf, size_t len);
        const unsigned char sample_query[] = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
        uint32_t h1 = dns_compute_question_hash(sample_query, sizeof(sample_query) - 1);
        assert(h1 != 0);

        /* Same domain in mixed-case should yield same hash */
        const unsigned char sample_query_upper[] = "\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x47\x4f\x4f\x47\x4c\x45\x03\x43\x4f\x4d\x00\x00\x01\x00\x01";
        uint32_t h2 = dns_compute_question_hash(sample_query_upper, sizeof(sample_query_upper) - 1);
        assert(h1 == h2);
        printf("    -> Case-insensitive DNS question FNV-1a hash verified: 0x%08x == 0x%08x\n", h1, h2);
    }

    printf("\n=================================================================\n");
    printf("   ALL MULTI-SERVER PROXY & DNS CACHE TESTS PASSED (100%%)       \n");
    printf("=================================================================\n");
    return 0;
}
