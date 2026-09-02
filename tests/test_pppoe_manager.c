#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include "pppoe_manager.h"
#include "fluxwan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int g_connected_count = 0;
static int g_disconnected_count = 0;

static void test_on_connected(int wan_idx, const char *ppp_ifname, uint32_t local_ip, uint32_t remote_ip, void *userdata) {
    (void)userdata;
    printf("  [TEST CB] WAN%d Connected -> ifname=%s, ip=0x%08X, gw=0x%08X\n", wan_idx + 1, ppp_ifname, local_ip, remote_ip);
    g_connected_count++;
}

static void test_on_disconnected(int wan_idx, const char *ppp_ifname, int attempt, void *userdata) {
    (void)userdata;
    printf("  [TEST CB] WAN%d Disconnected -> ifname=%s, attempt=%d\n", wan_idx + 1, ppp_ifname, attempt);
    g_disconnected_count++;
}

static void test_pppoe_init_destroy(void) {
    printf("[+] Testing PPPoE Manager init and destroy...\n");
    pppoe_manager_ctx_t *pctx = pppoe_manager_init();
    assert(pctx != NULL);

    pppoe_session_t *sess = pppoe_get_session(pctx, 0);
    assert(sess != NULL);
    assert(sess->state == PPPOE_STATE_IDLE);
    assert(sess->pppd_pid == -1);
    assert(sess->backoff_s == 15);

    pppoe_manager_destroy(pctx);
    printf("    ✓ Init and destroy passed.\n");
}

static void test_pppoe_multi_session_configuration(void) {
    printf("[+] Testing PPPoE Multi-Session on shared physical port...\n");
    pppoe_manager_ctx_t *pctx = pppoe_manager_init();
    assert(pctx != NULL);

    fluxwan_config_t config;
    memset(&config, 0, sizeof(config));
    config.wan_count = 2;

    /* WAN 1: PPPoE session A on eth1 */
    config.wans[0].id = 1;
    strcpy(config.wans[0].name, "eth1");
    strcpy(config.wans[0].label, "ISP1_Session_A");
    config.wans[0].type = WAN_TYPE_PPPOE;
    strcpy(config.wans[0].ppp_username, "user1@fiber.isp");
    strcpy(config.wans[0].ppp_password, "pass123");
    config.wans[0].enabled = true;

    /* WAN 2: PPPoE session B on SAME eth1 physical port */
    config.wans[1].id = 2;
    strcpy(config.wans[1].name, "eth1");
    strcpy(config.wans[1].label, "ISP1_Session_B");
    config.wans[1].type = WAN_TYPE_PPPOE;
    strcpy(config.wans[1].ppp_username, "user2@fiber.isp");
    strcpy(config.wans[1].ppp_password, "pass456");
    config.wans[1].enabled = true;

    int rc1 = pppoe_session_start(pctx, 0, &config.wans[0]);
    int rc2 = pppoe_session_start(pctx, 1, &config.wans[1]);
    assert(rc1 == 0);
    assert(rc2 == 0);

    pppoe_session_t *s1 = pppoe_get_session(pctx, 0);
    pppoe_session_t *s2 = pppoe_get_session(pctx, 1);
    assert(s1 != NULL);
    assert(s2 != NULL);

    /* Verify distinct PPP interface allocations */
    assert(strcmp(s1->ppp_ifname, "ppp0") == 0);
    assert(strcmp(s2->ppp_ifname, "ppp1") == 0);

    /* Tick the manager to simulate connection */
    pppoe_manager_tick(pctx, &config, test_on_connected, test_on_disconnected, NULL);

    pppoe_session_stop(pctx, 0);
    pppoe_session_stop(pctx, 1);
    pppoe_manager_destroy(pctx);
    printf("    ✓ Multi-session shared port support passed.\n");
}

static void test_pppoe_state_strings(void) {
    printf("[+] Testing PPPoE State Machine String representations...\n");
    assert(strcmp(pppoe_state_str(PPPOE_STATE_IDLE), "IDLE") == 0);
    assert(strcmp(pppoe_state_str(PPPOE_STATE_DIALING), "DIALING") == 0);
    assert(strcmp(pppoe_state_str(PPPOE_STATE_AUTH), "AUTHENTICATING") == 0);
    assert(strcmp(pppoe_state_str(PPPOE_STATE_CONNECTED), "CONNECTED") == 0);
    assert(strcmp(pppoe_state_str(PPPOE_STATE_DISCONNECTED), "DISCONNECTED") == 0);
    assert(strcmp(pppoe_state_str(PPPOE_STATE_RECONNECTING), "RECONNECTING") == 0);
    printf("    ✓ State strings verified.\n");
}

int main(void) {
    printf("====================================================\n");
    printf("      FluxWAN PPPoE Real Session Manager Unit Tests \n");
    printf("====================================================\n");

    test_pppoe_init_destroy();
    test_pppoe_state_strings();
    test_pppoe_multi_session_configuration();

    printf("\n[✓] ALL 3 PPPOE TEST SUITES PASSED (100%% SUCCESS)\n");
    return 0;
}
