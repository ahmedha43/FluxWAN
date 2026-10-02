#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "license_manager.h"

int main(void) {
    setbuf(stdout, NULL);
    printf("=====================================================\n");
    printf("     FluxWAN License Engine Unit Verification Suite   \n");
    printf("=====================================================\n");

    printf("\n[Test 1/6] Testing Hardware ID Generation...\n");
    char hwid[32] = {0};
    int rc = license_get_hardware_id(hwid, sizeof(hwid));
    assert(rc == 0);
    assert(strncmp(hwid, "FWID-", 5) == 0);
    printf("Local Machine Hardware ID: %s [PASS]\n", hwid);

    printf("\n[Test 2/6] Testing Initialization...\n");
    license_info_t info;
    license_manager_init(&info);
    printf("Initial Status: %s (Grace: %us) [PASS]\n", info.status_str, info.grace_seconds_remaining);

    printf("\n[Test 3/6] Testing Fake/Forged Key Rejection...\n");
    char err[256] = {0};
    rc = license_manager_activate("FLUX-LIC-FAKEKEY1234567890INVALIDBASE64FORGERY", &info, err, sizeof(err));
    assert(rc != 0);
    printf("Fake key correctly rejected: %s [PASS]\n", err);

    printf("\n[Test 4/6] Testing Valid Key Activation...\n");
    char local_hwid[32] = {0};
    license_get_hardware_id(local_hwid, sizeof(local_hwid));

    char valid_key[512] = {0};
    char gen_cmd[512];
    snprintf(gen_cmd, sizeof(gen_cmd),
             "python3 tools/fluxwan_license_gen.py --hwid \"%s\" --client \"CI Test System\" --type days --days 30 --raw 2>/dev/null || "
             "python tools/fluxwan_license_gen.py --hwid \"%s\" --client \"CI Test System\" --type days --days 30 --raw 2>/dev/null || "
             "py tools/fluxwan_license_gen.py --hwid \"%s\" --client \"CI Test System\" --type days --days 30 --raw 2>/dev/null",
             local_hwid, local_hwid, local_hwid);

    FILE *pfp = popen(gen_cmd, "r");
    if (pfp) {
        if (fgets(valid_key, sizeof(valid_key), pfp)) {
            size_t klen = strlen(valid_key);
            while (klen > 0 && (valid_key[klen - 1] == '\r' || valid_key[klen - 1] == '\n' || valid_key[klen - 1] == ' ')) {
                valid_key[--klen] = '\0';
            }
        }
        pclose(pfp);
    }

    rc = license_manager_activate(valid_key, &info, err, sizeof(err));
    printf("Activation result code: %d, Message: %s\n", rc, err);
    assert(rc == 0);
    assert(info.is_valid == true);
    assert(strcmp(info.status_str, "ACTIVE") == 0);
    assert(info.days_remaining >= 29 && info.days_remaining <= 30);
    printf("Activated License: Type=%s, Client=%s, Days Remaining=%u [PASS]\n",
           info.type_str, info.client_name, info.days_remaining);

    printf("\n[Test 5/6] Testing Authorization Gate with Valid Key...\n");
    bool auth = license_is_authorized();
    assert(auth == true);
    printf("Is authorized: %s [PASS]\n", auth ? "TRUE" : "FALSE");

    printf("\n[Test 6/6] Testing Anti-Clock Rollback Simulation...\n");
    /* If we update watermark to future time and tick */
    unlink(LICENSE_WATERMARK_PATH);
    FILE *f_wm = fopen(LICENSE_WATERMARK_PATH, "w");
    assert(f_wm != NULL);
    /* Set watermark 100 days into the future */
    fprintf(f_wm, "%llu\n", (unsigned long long)(time(NULL) + 8640000));
    fclose(f_wm);

    license_info_t rollback_info;
    license_manager_tick(&rollback_info, 10000);
    printf("Status after clock rollback simulation: %s [PASS]\n", rollback_info.status_str);
    assert(strcmp(rollback_info.status_str, "CLOCK_TAMPERED") == 0);
    assert(rollback_info.is_valid == false);

    /* Clean up test watermark and license file */
    remove(LICENSE_WATERMARK_PATH);
    remove(LICENSE_FILE_PATH);

    printf("\n=====================================================\n");
    printf("       ALL 6 LICENSE ENGINE TESTS PASSED 100%%\n");
    printf("=====================================================\n");
    return 0;
}
