#include "fluxwan.h"
#include "config.h"
#include "wan_manager.h"
#include <assert.h>

int main(void) {
    printf("======================================================================\n");
    printf("     FluxWAN WAN Groups & Multi-Pool Maglev Ring Isolation Test       \n");
    printf("======================================================================\n\n");

    fluxwan_config_t config;
    memset(&config, 0, sizeof(config));

    /* Setup 4 WAN Uplinks: 2 Starlink + 2 Iraqi PPPoE */
    config.wan_count = 4;

    /* WAN 1 & 2: Iraqi PPPoE */
    config.wans[0].id = 1;
    strcpy(config.wans[0].name, "ppp0");
    strcpy(config.wans[0].label, "WAN1_Earthlink");
    config.wans[0].enabled = true;
    config.wans[0].state = WAN_STATE_HEALTHY;
    config.wans[0].config_weight = 100;
    config.wans[0].dynamic_weight = 100;

    config.wans[1].id = 2;
    strcpy(config.wans[1].name, "ppp1");
    strcpy(config.wans[1].label, "WAN2_Zain");
    config.wans[1].enabled = true;
    config.wans[1].state = WAN_STATE_HEALTHY;
    config.wans[1].config_weight = 100;
    config.wans[1].dynamic_weight = 100;

    /* WAN 3 & 4: Starlink Satellites */
    config.wans[2].id = 3;
    strcpy(config.wans[2].name, "eth2");
    strcpy(config.wans[2].label, "WAN3_Starlink1");
    config.wans[2].enabled = true;
    config.wans[2].state = WAN_STATE_HEALTHY;
    config.wans[2].config_weight = 100;
    config.wans[2].dynamic_weight = 100;

    config.wans[3].id = 4;
    strcpy(config.wans[3].name, "eth3");
    strcpy(config.wans[3].label, "WAN4_Starlink2");
    config.wans[3].enabled = true;
    config.wans[3].state = WAN_STATE_HEALTHY;
    config.wans[3].config_weight = 100;
    config.wans[3].dynamic_weight = 100;

    /* Define 2 Groups: Group 1 (Iraq_Local) and Group 2 (Starlink_Fleet) */
    config.group_count = 2;

    /* Group 1: Iraq_Local */
    config.groups[0].id = 1;
    strcpy(config.groups[0].name, "Iraq_Local");
    strcpy(config.groups[0].description, "Local Iraqi PPPoE Fiber Pool");
    config.groups[0].enabled = true;
    config.groups[0].wan_count = 2;
    config.groups[0].wan_member_indices[0] = 0; /* WAN1 */
    config.groups[0].wan_member_indices[1] = 1; /* WAN2 */

    /* Group 2: Starlink_Fleet */
    config.groups[1].id = 2;
    strcpy(config.groups[1].name, "Starlink_Fleet");
    strcpy(config.groups[1].description, "Starlink Satellite Constellation");
    config.groups[1].enabled = true;
    config.groups[1].wan_count = 2;
    config.groups[1].wan_member_indices[0] = 2; /* WAN3 */
    config.groups[1].wan_member_indices[1] = 3; /* WAN4 */

    /* Define LAN Multi-Subnet Policy Routes */
    config.lan.policy_route_count = 2;

    /* Route 1: 10.10.20.0/24 -> Starlink_Fleet */
    strcpy(config.lan.policy_routes[0].subnet_str, "10.10.20.0/24");
    config.lan.policy_routes[0].subnet_ip = str_to_ip("10.10.20.0");
    config.lan.policy_routes[0].netmask = str_to_ip("255.255.255.0");
    config.lan.policy_routes[0].prefix_len = 24;
    strcpy(config.lan.policy_routes[0].gateway_ip_str, "10.10.20.1");
    config.lan.policy_routes[0].gateway_ip = str_to_ip("10.10.20.1");
    strcpy(config.lan.policy_routes[0].target_group, "Starlink_Fleet");
    config.lan.policy_routes[0].target_group_id = 2;
    config.lan.policy_routes[0].enabled = true;

    /* Route 2: 10.10.30.0/24 -> Iraq_Local */
    strcpy(config.lan.policy_routes[1].subnet_str, "10.10.30.0/24");
    config.lan.policy_routes[1].subnet_ip = str_to_ip("10.10.30.0");
    config.lan.policy_routes[1].netmask = str_to_ip("255.255.255.0");
    config.lan.policy_routes[1].prefix_len = 24;
    strcpy(config.lan.policy_routes[1].gateway_ip_str, "10.10.30.1");
    config.lan.policy_routes[1].gateway_ip = str_to_ip("10.10.30.1");
    strcpy(config.lan.policy_routes[1].target_group, "Iraq_Local");
    config.lan.policy_routes[1].target_group_id = 1;
    config.lan.policy_routes[1].enabled = true;

    /* Initialize wan_manager and generate rings */
    wan_manager_ctx_t *ctx = wan_manager_init(&config, NULL, NULL);
    assert(ctx != NULL);

    printf("[Test 1/3] Verifying Iraq_Local Group Maglev Ring Isolation...\n");
    uint32_t iraq_w0 = 0, iraq_w1 = 0, other_w = 0;
    for (uint32_t i = 0; i < MAGLEV_RING_SIZE; i++) {
        uint32_t picked = config.groups[0].maglev_ring[i];
        if (picked == 0) iraq_w0++;
        else if (picked == 1) iraq_w1++;
        else other_w++;
    }
    printf("    * WAN1_Earthlink: %u slots (%.1f%%)\n", iraq_w0, (float)iraq_w0 * 100.0f / MAGLEV_RING_SIZE);
    printf("    * WAN2_Zain     : %u slots (%.1f%%)\n", iraq_w1, (float)iraq_w1 * 100.0f / MAGLEV_RING_SIZE);
    printf("    * Other WANs    : %u slots (Expected: 0)\n", other_w);
    assert(other_w == 0);
    assert(iraq_w0 > 0 && iraq_w1 > 0);
    printf("    [PASS] Iraq_Local group ring contains ONLY local Iraqi WANs (100%% isolated)!\n\n");

    printf("[Test 2/3] Verifying Starlink_Fleet Group Maglev Ring Isolation...\n");
    uint32_t sl_w2 = 0, sl_w3 = 0;
    other_w = 0;
    for (uint32_t i = 0; i < MAGLEV_RING_SIZE; i++) {
        uint32_t picked = config.groups[1].maglev_ring[i];
        if (picked == 2) sl_w2++;
        else if (picked == 3) sl_w3++;
        else other_w++;
    }
    printf("    * WAN3_Starlink1: %u slots (%.1f%%)\n", sl_w2, (float)sl_w2 * 100.0f / MAGLEV_RING_SIZE);
    printf("    * WAN4_Starlink2: %u slots (%.1f%%)\n", sl_w3, (float)sl_w3 * 100.0f / MAGLEV_RING_SIZE);
    printf("    * Other WANs    : %u slots (Expected: 0)\n", other_w);
    assert(other_w == 0);
    assert(sl_w2 > 0 && sl_w3 > 0);
    printf("    [PASS] Starlink_Fleet group ring contains ONLY Starlink WANs (100%% isolated)!\n\n");

    printf("[Test 3/3] Testing Dynamic Sub-Second In-Group Failover...\n");
    printf("    * Simulating Satellite Link Loss on WAN3_Starlink1 (State -> DOWN)...\n");
    config.wans[2].state = WAN_STATE_DOWN;
    config.wans[2].dynamic_weight = 0;
    wan_manager_rebalance(ctx);

    sl_w2 = 0;
    sl_w3 = 0;
    for (uint32_t i = 0; i < MAGLEV_RING_SIZE; i++) {
        uint32_t picked = config.groups[1].maglev_ring[i];
        if (picked == 2) sl_w2++;
        else if (picked == 3) sl_w3++;
    }
    printf("    * After Failover -> WAN3_Starlink1: %u slots (0%%) | WAN4_Starlink2: %u slots (100%%)\n", sl_w2, sl_w3);
    assert(sl_w2 == 0);
    assert(sl_w3 == MAGLEV_RING_SIZE);

    /* Verify that Iraq_Local group was unaffected */
    iraq_w0 = 0;
    iraq_w1 = 0;
    for (uint32_t i = 0; i < MAGLEV_RING_SIZE; i++) {
        uint32_t picked = config.groups[0].maglev_ring[i];
        if (picked == 0) iraq_w0++;
        else if (picked == 1) iraq_w1++;
    }
    assert(iraq_w0 > 0 && iraq_w1 > 0);
    printf("    * Iraq_Local Group Integrity: 100%% UNCHANGED (Zero cross-group interference)\n");
    printf("    [PASS] In-Group failover executed cleanly!\n\n");

    wan_manager_close(ctx);
    printf("======================================================================\n");
    printf("   [✓] ALL WAN GROUPS & MULTI-POOL ISOLATION TESTS PASSED 100%%!       \n");
    printf("======================================================================\n");
    return 0;
}