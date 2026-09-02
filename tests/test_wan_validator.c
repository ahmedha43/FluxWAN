/* ===========================================================================
 * FluxWAN — WAN Port Exclusivity & Multi-Session Validation Unit Tests
 * =========================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "fluxwan.h"
#include "config.h"

static void test_valid_multi_pppoe_on_same_port(void) {
    printf("[Test 1/4] Testing 3 PPPoE sessions sharing eth1...");
    fluxwan_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.lan.name, "eth0");

    cfg.wan_count = 3;
    cfg.wans[0].type = WAN_TYPE_PPPOE; strcpy(cfg.wans[0].name, "eth1"); strcpy(cfg.wans[0].label, "WAN1_Fiber_ISP1");
    cfg.wans[1].type = WAN_TYPE_PPPOE; strcpy(cfg.wans[1].name, "eth1"); strcpy(cfg.wans[1].label, "WAN2_Fiber_ISP2");
    cfg.wans[2].type = WAN_TYPE_PPPOE; strcpy(cfg.wans[2].name, "eth1"); strcpy(cfg.wans[2].label, "WAN3_Fiber_ISP3");

    char err[256] = {0};
    bool valid = config_validate_wan_attachments(&cfg, err, sizeof(err));
    printf(" [%s] (Expected: VALID)\n", valid ? "PASS" : "FAIL");
    assert(valid == true);
}

static void test_reject_two_dhcp_on_same_port(void) {
    printf("[Test 2/4] Testing REJECTION of 2 DHCP clients on eth1...");
    fluxwan_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.lan.name, "eth0");

    cfg.wan_count = 2;
    cfg.wans[0].type = WAN_TYPE_DHCP; strcpy(cfg.wans[0].name, "eth1"); strcpy(cfg.wans[0].label, "WAN1_Starlink");
    cfg.wans[1].type = WAN_TYPE_DHCP; strcpy(cfg.wans[1].name, "eth1"); strcpy(cfg.wans[1].label, "WAN2_Fiber");

    char err[256] = {0};
    bool valid = config_validate_wan_attachments(&cfg, err, sizeof(err));
    printf(" [%s] - Error caught: '%s'\n", !valid ? "PASS" : "FAIL", err);
    assert(valid == false);
}

static void test_reject_dhcp_and_static_conflict(void) {
    printf("[Test 3/4] Testing REJECTION of DHCP + Static mix on eth1...");
    fluxwan_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.lan.name, "eth0");

    cfg.wan_count = 2;
    cfg.wans[0].type = WAN_TYPE_DHCP;   strcpy(cfg.wans[0].name, "eth1"); strcpy(cfg.wans[0].label, "WAN1_DHCP");
    cfg.wans[1].type = WAN_TYPE_STATIC; strcpy(cfg.wans[1].name, "eth1"); strcpy(cfg.wans[1].label, "WAN2_Static");

    char err[256] = {0};
    bool valid = config_validate_wan_attachments(&cfg, err, sizeof(err));
    printf(" [%s] - Error caught: '%s'\n", !valid ? "PASS" : "FAIL", err);
    assert(valid == false);
}

static void test_reject_lan_and_wan_sharing(void) {
    printf("[Test 4/4] Testing REJECTION of LAN port (eth0) assigned to WAN...");
    fluxwan_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.lan.name, "eth0");

    cfg.wan_count = 1;
    cfg.wans[0].type = WAN_TYPE_DHCP; strcpy(cfg.wans[0].name, "eth0"); strcpy(cfg.wans[0].label, "WAN1_BadLAN");

    char err[256] = {0};
    bool valid = config_validate_wan_attachments(&cfg, err, sizeof(err));
    printf(" [%s] - Error caught: '%s'\n", !valid ? "PASS" : "FAIL", err);
    assert(valid == false);
}

int main(void) {
    printf("======================================================================\n");
    printf("       FluxWAN C Backend WAN Port Allocation & Exclusivity Tests       \n");
    printf("======================================================================\n\n");

    test_valid_multi_pppoe_on_same_port();
    test_reject_two_dhcp_on_same_port();
    test_reject_dhcp_and_static_conflict();
    test_reject_lan_and_wan_sharing();

    printf("\n======================================================================\n");
    printf("       ALL WAN ATTACHMENT BACKEND VALIDATION TESTS PASSED 100%%!       \n");
    printf("======================================================================\n\n");
    return 0;
}
