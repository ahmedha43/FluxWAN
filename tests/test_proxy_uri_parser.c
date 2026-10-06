#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "fluxwan.h"
#include "proxy_manager.h"

int main(void) {
    printf("=========================================\n");
    printf("   TESTING PROXY URI PARSER & ENGINE     \n");
    printf("=========================================\n");

    /* Test 1: VLESS with WebSocket, TLS, and Zero-Rating SNI */
    {
        const char *vless_uri = "vless://a1b2c3d4-e5f6-7890-abcd-ef0123456789@198.51.100.1:443?type=ws&security=tls&sni=portal.oodi.iq&host=portal.oodi.iq&path=%2Fvless-ws#Oodi_Zero";
        wan_proxy_config_t cfg;
        int rc = proxy_manager_parse_uri(vless_uri, &cfg);
        assert(rc == 0);
        assert(cfg.proto == PROXY_PROTO_VLESS);
        assert(strcmp(cfg.server, "198.51.100.1") == 0);
        assert(cfg.port == 443);
        assert(strcmp(cfg.uuid, "a1b2c3d4-e5f6-7890-abcd-ef0123456789") == 0);
        assert(strcmp(cfg.sni, "portal.oodi.iq") == 0);
        assert(strcmp(cfg.host, "portal.oodi.iq") == 0);
        assert(strcmp(cfg.path, "/vless-ws") == 0);
        assert(strcmp(cfg.transport, "ws") == 0);
        assert(strcmp(cfg.security, "tls") == 0);
        printf("[PASS] Test 1: VLESS URI with zero-rated SNI parsed successfully.\n");
    }

    /* Test 2: Trojan with custom SNI and Port 8443 */
    {
        const char *trojan_uri = "trojan://super_secret_pass@203.0.113.5:8443?security=tls&sni=free.zain.com#Zain_Bypass";
        wan_proxy_config_t cfg;
        int rc = proxy_manager_parse_uri(trojan_uri, &cfg);
        assert(rc == 0);
        assert(cfg.proto == PROXY_PROTO_TROJAN);
        assert(strcmp(cfg.server, "203.0.113.5") == 0);
        assert(cfg.port == 8443);
        assert(strcmp(cfg.uuid, "super_secret_pass") == 0);
        assert(strcmp(cfg.sni, "free.zain.com") == 0);
        printf("[PASS] Test 2: Trojan URI parsed successfully.\n");
    }

    /* Test 3: Shadowsocks URI */
    {
        const char *ss_uri = "ss://chacha20-ietf-poly1305:mypassword@192.0.2.1:8388#Shadowsocks";
        wan_proxy_config_t cfg;
        int rc = proxy_manager_parse_uri(ss_uri, &cfg);
        assert(rc == 0);
        assert(cfg.proto == PROXY_PROTO_SHADOWSOCKS);
        assert(strcmp(cfg.server, "192.0.2.1") == 0);
        assert(cfg.port == 8388);
        printf("[PASS] Test 3: Shadowsocks URI parsed successfully.\n");
    }

    printf("=========================================\n");
    printf("   ALL PROXY URI TESTS PASSED (100%%)    \n");
    printf("=========================================\n");
    return 0;
}
