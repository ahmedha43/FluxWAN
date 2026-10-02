/* ===========================================================================
 * FluxWAN Military-Grade Cryptographic License Engine
 *
 * Implements:
 *   - Ed25519 Signature Verification with Master Public Key
 *   - Hardware ID Fingerprinting (DMI UUID + Disk Serial + CPU + MAC)
 *   - Anti-Clock Rollback & Monotonic Watermark Ledger
 *   - Lifetime & Days-based Subscriptions
 *   - Grace Period Management
 *
 * Copyright (C) 2026 Ahmed Al-Dulaimi. All rights reserved.
 * =========================================================================== */

#include "license_manager.h"
#include "crypto_ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#if defined(__linux__)
#include <sys/ptrace.h>
#include <time.h>
#endif

/* ── Embedded Master Vendor Public Key (Verified by Ahmed Al-Dulaimi) ───── */
static const uint8_t MASTER_PUBLIC_KEY[32] = {
    0x7b, 0x43, 0x59, 0xc6, 0x6e, 0xea, 0x55, 0xdc, 0xff, 0xa1, 0x9f, 0x94, 0xdd, 0x90, 0x0a, 0xed,
    0x9a, 0x8c, 0x86, 0x5d, 0xe3, 0xf5, 0xd2, 0xbc, 0xec, 0x5a, 0xd7, 0x5b, 0xf8, 0x1a, 0x40, 0x69
};

/* Secret Salt for Hardware ID computation */
static const char HWID_SALT[] = "FLUXWAN-SECURE-HARDWARE-ROOT-2026-AHMED-ALDULAIMI";

/* Global cached license state */
static license_info_t g_license_info = {
    .type = LICENSE_TYPE_UNLICENSED,
    .status = LICENSE_STATUS_GRACE,
    .is_valid = false,
    .hwid = "FWID-UNINITIALIZED",
    .client_name = "Unregistered System",
    .max_wans = 3,
    .days_total = 0,
    .days_remaining = 0,
    .issued_at = 0,
    .expires_at = 0,
    .active_seconds_remaining = 0,
    .grace_seconds_remaining = LICENSE_DEFAULT_GRACE_SEC,
    .status_str = "GRACE_PERIOD",
    .type_str = "UNLICENSED"
};

static uint64_t g_boot_timestamp = 0;
static uint64_t g_last_tick_ms = 0;
static char g_cached_hwid[32] = {0};

/* ── Hardware Fingerprint Extraction ────────────────────────────────────── */

static void read_file_trimmed(const char *path, char *buf, size_t max_len) {
    buf[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fgets(buf, max_len, f)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n' || buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
            buf[--len] = '\0';
        }
    }
    fclose(f);
}

int license_get_hardware_id(char *out_hwid, size_t max_len) {
    if (!out_hwid || max_len < 25) return -1;
    if (g_cached_hwid[0] != '\0') {
        strncpy(out_hwid, g_cached_hwid, max_len - 1);
        out_hwid[max_len - 1] = '\0';
        return 0;
    }

    char dmi_uuid[128] = {0};
    char disk_serial[128] = {0};
    char cpu_info[256] = {0};
    char mac_addr[64] = {0};

#if defined(__linux__)
    /* 1. Motherboard / DMI UUID (VMware, KVM, Bare Metal BIOS) */
    read_file_trimmed("/sys/class/dmi/id/product_uuid", dmi_uuid, sizeof(dmi_uuid));
    if (dmi_uuid[0] == '\0') {
        read_file_trimmed("/etc/machine-id", dmi_uuid, sizeof(dmi_uuid));
    }
    if (dmi_uuid[0] == '\0') {
        read_file_trimmed("/var/lib/dbus/machine-id", dmi_uuid, sizeof(dmi_uuid));
    }

    /* 2. Disk Hardware Serial Number */
    read_file_trimmed("/sys/block/sda/device/serial", disk_serial, sizeof(disk_serial));
    if (disk_serial[0] == '\0') {
        read_file_trimmed("/sys/block/nvme0n1/device/serial", disk_serial, sizeof(disk_serial));
    }
    if (disk_serial[0] == '\0') {
        read_file_trimmed("/sys/block/vda/serial", disk_serial, sizeof(disk_serial));
    }

    /* 3. CPU Signature */
    FILE *f_cpu = fopen("/proc/cpuinfo", "r");
    if (f_cpu) {
        char line[256];
        while (fgets(line, sizeof(line), f_cpu)) {
            if (strncmp(line, "model name", 10) == 0 || strncmp(line, "Hardware", 8) == 0) {
                char *colon = strchr(line, ':');
                if (colon) {
                    strncpy(cpu_info, colon + 1, sizeof(cpu_info) - 1);
                    break;
                }
            }
        }
        fclose(f_cpu);
    }

    /* 4. Permanent MAC Address of primary interface */
    read_file_trimmed("/sys/class/net/eth0/address", mac_addr, sizeof(mac_addr));
    if (mac_addr[0] == '\0') {
        read_file_trimmed("/sys/class/net/eth1/address", mac_addr, sizeof(mac_addr));
    }
#else
    strcpy(dmi_uuid, "SIMULATED-DMI-UUID-12345");
    strcpy(disk_serial, "SIMULATED-DISK-SERIAL-67890");
    strcpy(cpu_info, "x86_64 Simulated Architecture");
    strcpy(mac_addr, "00:0c:29:97:41:fc");
#endif

    /* If no DMI UUID could be read, provide deterministic fallback */
    if (dmi_uuid[0] == '\0') strcpy(dmi_uuid, "FLUXWAN-NODEVICE-UUID-DEFAULT");
    if (disk_serial[0] == '\0') strcpy(disk_serial, "FLUXWAN-DISK-DEFAULT-SN");
    if (cpu_info[0] == '\0') strcpy(cpu_info, "Generic-x86-Architecture");
    if (mac_addr[0] == '\0') strcpy(mac_addr, "00:00:00:00:00:00");

    /* Hash together: SALT + DMI_UUID + DISK_SERIAL + CPU_INFO + MAC */
    char combined[1024];
    snprintf(combined, sizeof(combined), "%s|%s|%s|%s|%s",
             HWID_SALT, dmi_uuid, disk_serial, cpu_info, mac_addr);

    uint8_t hash[32];
    crypto_sha256((const uint8_t*)combined, strlen(combined), hash);

    /* Format into standard 16-hex Machine ID: FWID-XXXX-XXXX-XXXX-XXXX */
    snprintf(g_cached_hwid, sizeof(g_cached_hwid), "FWID-%02X%02X-%02X%02X-%02X%02X-%02X%02X",
             hash[0], hash[1], hash[2], hash[3],
             hash[4], hash[5], hash[6], hash[7]);

    strncpy(out_hwid, g_cached_hwid, max_len - 1);
    out_hwid[max_len - 1] = '\0';
    return 0;
}

/* ── Anti-Clock Rollback Watermark Ledger ────────────────────────────────── */

static uint64_t read_watermark(void) {
    uint64_t wm = 0;
    FILE *f = fopen(LICENSE_WATERMARK_PATH, "r");
    if (f) {
        if (fscanf(f, "%llu", (unsigned long long*)&wm) != 1) wm = 0;
        fclose(f);
    }
    return wm;
}

static void update_watermark(uint64_t current_ts) {
    uint64_t existing = read_watermark();
    if (current_ts > existing) {
        FILE *f = fopen(LICENSE_WATERMARK_PATH, "w");
        if (f) {
            fprintf(f, "%llu\n", (unsigned long long)current_ts);
            fclose(f);
        }
    }
}

/* ── License Verification & Parsing ─────────────────────────────────────── */

static int parse_and_verify_license_key(const char *key_str, license_payload_t *out_payload) {
    if (!key_str) return -1;

    /* Skip leading whitespace and optional prefix "FLUX-LIC-" */
    const char *p = key_str;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (strncmp(p, "FLUX-LIC-", 9) == 0) p += 9;

    uint8_t blob[512];
    size_t blob_len = 0;
    if (crypto_base64_decode(p, blob, sizeof(blob), &blob_len) < 0) {
        return -2; /* Base64 decode failed */
    }

    /* Expected: 140 bytes payload + 64 bytes signature = 204 bytes */
    if (blob_len != sizeof(license_payload_t) + 64) {
        return -3; /* Invalid length */
    }

    license_payload_t *payload = (license_payload_t *)blob;
    const uint8_t *signature = blob + sizeof(license_payload_t);

    /* Check Magic Header */
    if (memcmp(payload->magic, "FLIC", 4) != 0) {
        return -4; /* Invalid magic */
    }

    /* Cryptographic Ed25519 Signature Verification */
    if (!crypto_ed25519_verify(signature, (const uint8_t*)payload, sizeof(license_payload_t), MASTER_PUBLIC_KEY)) {
        return -5; /* Digital signature invalid / forged */
    }

    memcpy(out_payload, payload, sizeof(license_payload_t));
    return 0;
}

static void update_license_status_from_payload(const license_payload_t *payload, license_info_t *info) {
    char local_hwid[32];
    license_get_hardware_id(local_hwid, sizeof(local_hwid));

    info->max_wans = payload->max_wans > 0 ? payload->max_wans : 256;
    info->issued_at = payload->issued_at;
    info->expires_at = payload->expires_at;
    info->days_total = payload->days_total;
    strncpy(info->client_name, payload->client_name, sizeof(info->client_name) - 1);
    strncpy(info->hwid, payload->hwid, sizeof(info->hwid) - 1);

    /* 1. Check Hardware ID Binding */
    if (strcasecmp(payload->hwid, local_hwid) != 0) {
        info->status = LICENSE_STATUS_HW_MISMATCH;
        info->is_valid = false;
        strcpy(info->status_str, "HW_MISMATCH");
        strcpy(info->type_str, payload->type == 2 ? "LIFETIME" : "DAYS");
        return;
    }

    /* 2. Check License Type */
    if (payload->type == 2) {
        /* LIFETIME LICENSE */
        info->type = LICENSE_TYPE_LIFETIME;
        info->status = LICENSE_STATUS_ACTIVE;
        info->is_valid = true;
        info->days_remaining = 99999;
        info->active_seconds_remaining = 0xFFFFFFFF;
        strcpy(info->status_str, "ACTIVE");
        strcpy(info->type_str, "LIFETIME");
        return;
    }

    /* 3. DAYS-BASED SUBSCRIPTION */
    info->type = LICENSE_TYPE_DAYS;
    strcpy(info->type_str, "DAYS");

    uint64_t now_ts = (uint64_t)time(NULL);

    /* Check Anti-Clock Rollback */
    uint64_t watermark = read_watermark();
    if (watermark > 0 && now_ts + 300 < watermark) {
        /* Clock was rolled back by more than 5 minutes */
        info->status = LICENSE_STATUS_TAMPERED;
        info->is_valid = false;
        info->days_remaining = 0;
        info->active_seconds_remaining = 0;
        strcpy(info->status_str, "CLOCK_TAMPERED");
        return;
    }

    /* Update watermark to current time */
    update_watermark(now_ts);

    /* Check Expiry */
    if (now_ts >= payload->expires_at) {
        info->status = LICENSE_STATUS_EXPIRED;
        info->is_valid = false;
        info->days_remaining = 0;
        info->active_seconds_remaining = 0;
        strcpy(info->status_str, "EXPIRED");
    } else {
        info->status = LICENSE_STATUS_ACTIVE;
        info->is_valid = true;
        uint64_t rem_sec = payload->expires_at - now_ts;
        info->active_seconds_remaining = rem_sec;
        info->days_remaining = (uint32_t)((rem_sec + 86399) / 86400);
        strcpy(info->status_str, "ACTIVE");
    }
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int license_manager_init(license_info_t *out_info) {
#if defined(__linux__)
    /* Anti-Debugging: Detect and thwart debuggers attaching via ptrace */
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        /* Debugger attached or ptrace restricted */
    }
#endif

    g_boot_timestamp = (uint64_t)time(NULL);
    g_last_tick_ms = 0;

    /* Pre-compute local Hardware ID */
    license_get_hardware_id(g_license_info.hwid, sizeof(g_license_info.hwid));

    /* Check if existing license key file exists */
    FILE *f = fopen(LICENSE_FILE_PATH, "r");
    if (f) {
        char key_buf[1024] = {0};
        if (fgets(key_buf, sizeof(key_buf), f)) {
            license_payload_t payload;
            if (parse_and_verify_license_key(key_buf, &payload) == 0) {
                update_license_status_from_payload(&payload, &g_license_info);
            }
        }
        fclose(f);
    }

    /* If unlicensed, check grace period */
    if (!g_license_info.is_valid) {
        g_license_info.status = LICENSE_STATUS_GRACE;
        g_license_info.grace_seconds_remaining = LICENSE_DEFAULT_GRACE_SEC;
        strcpy(g_license_info.status_str, "GRACE_PERIOD");
    }

    if (out_info) {
        *out_info = g_license_info;
    }
    return g_license_info.is_valid ? 0 : -1;
}

void license_manager_tick(license_info_t *info, uint64_t now_ms) {
    uint32_t elapsed_sec = 0;
    if (g_last_tick_ms > 0 && now_ms > g_last_tick_ms) {
        elapsed_sec = (uint32_t)((now_ms - g_last_tick_ms) / 1000);
        if (elapsed_sec > 0) {
            g_last_tick_ms = now_ms;
        }
    } else {
        g_last_tick_ms = now_ms;
    }

    /* Handle Grace Period for unactivated installations */
    if (!g_license_info.is_valid && g_license_info.status == LICENSE_STATUS_GRACE) {
        if (elapsed_sec > 0) {
            if (g_license_info.grace_seconds_remaining > elapsed_sec) {
                g_license_info.grace_seconds_remaining -= elapsed_sec;
            } else {
                g_license_info.grace_seconds_remaining = 0;
                g_license_info.status = LICENSE_STATUS_UNLICENSED;
                strcpy(g_license_info.status_str, "UNLICENSED");
            }
        }
    }

    /* For Days-based active licenses, update remaining time and watermark */
    if (g_license_info.is_valid && g_license_info.type == LICENSE_TYPE_DAYS) {
        uint64_t now_ts = (uint64_t)time(NULL);
        uint64_t wm = read_watermark();

        /* Detect clock rollback */
        if (wm > 0 && now_ts + 300 < wm) {
            g_license_info.status = LICENSE_STATUS_TAMPERED;
            g_license_info.is_valid = false;
            strcpy(g_license_info.status_str, "CLOCK_TAMPERED");
        } else {
            update_watermark(now_ts);
            if (now_ts >= g_license_info.expires_at) {
                g_license_info.status = LICENSE_STATUS_EXPIRED;
                g_license_info.is_valid = false;
                g_license_info.days_remaining = 0;
                g_license_info.active_seconds_remaining = 0;
                strcpy(g_license_info.status_str, "EXPIRED");
            } else {
                uint64_t rem_sec = g_license_info.expires_at - now_ts;
                g_license_info.active_seconds_remaining = rem_sec;
                g_license_info.days_remaining = (uint32_t)((rem_sec + 86399) / 86400);
            }
        }
    }

    if (info) {
        *info = g_license_info;
    }
}

int license_manager_activate(const char *license_key_str, license_info_t *out_info, char *err_msg, size_t err_len) {
    if (!license_key_str || !license_key_str[0]) {
        if (err_msg) snprintf(err_msg, err_len, "License key string is empty.");
        return -1;
    }

    license_payload_t payload;
    int rc = parse_and_verify_license_key(license_key_str, &payload);
    if (rc != 0) {
        if (err_msg) {
            if (rc == -2) snprintf(err_msg, err_len, "Invalid Base64 format.");
            else if (rc == -3) snprintf(err_msg, err_len, "Invalid license key length.");
            else if (rc == -4) snprintf(err_msg, err_len, "Unrecognized license header.");
            else if (rc == -5) snprintf(err_msg, err_len, "Cryptographic signature verification failed (Untrusted Key).");
            else snprintf(err_msg, err_len, "License verification error (%d).", rc);
        }
        return -1;
    }

    /* Check Hardware ID */
    char local_hwid[32];
    license_get_hardware_id(local_hwid, sizeof(local_hwid));
    if (strcasecmp(payload.hwid, local_hwid) != 0) {
        if (err_msg) {
            snprintf(err_msg, err_len, "License Hardware ID mismatch! Key is for [%s], but this machine is [%s].",
                     payload.hwid, local_hwid);
        }
        return -2;
    }

    /* Check if already expired at time of activation */
    uint64_t now_ts = (uint64_t)time(NULL);
    if (payload.type == 1 && now_ts >= payload.expires_at) {
        if (err_msg) snprintf(err_msg, err_len, "This subscription key has already expired.");
        return -3;
    }

    /* Save verified key to disk */
    mkdir("/opt/fluxwan", 0755);
    mkdir("/opt/fluxwan/config", 0755);
    FILE *f = fopen(LICENSE_FILE_PATH, "w");
    if (f) {
        fprintf(f, "%s\n", license_key_str);
        fclose(f);
    }

    /* Update watermark */
    update_watermark(now_ts);

    /* Update global state */
    update_license_status_from_payload(&payload, &g_license_info);

    if (out_info) {
        *out_info = g_license_info;
    }
    if (err_msg) {
        snprintf(err_msg, err_len, "Success: Activated %s license for %s.",
                 g_license_info.type_str, g_license_info.client_name);
    }
    return 0;
}

const license_info_t *license_get_info(void) {
    return &g_license_info;
}

bool license_is_authorized(void) {
    if (g_license_info.is_valid) return true;
    if (g_license_info.status == LICENSE_STATUS_GRACE && g_license_info.grace_seconds_remaining > 0) {
        return true;
    }
    return false;
}
