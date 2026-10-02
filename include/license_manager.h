#ifndef LICENSE_MANAGER_H
#define LICENSE_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define LICENSE_FILE_PATH       "/opt/fluxwan/config/license.key"
#define LICENSE_WATERMARK_PATH  "/opt/fluxwan/config/.lic_watermark"
#define LICENSE_DEFAULT_GRACE_SEC 1800 /* 30 minutes grace period for unactivated setup */

typedef enum {
    LICENSE_TYPE_UNLICENSED = 0,
    LICENSE_TYPE_DAYS       = 1,
    LICENSE_TYPE_LIFETIME   = 2
} license_type_t;

typedef enum {
    LICENSE_STATUS_UNLICENSED  = 0,
    LICENSE_STATUS_ACTIVE      = 1,
    LICENSE_STATUS_EXPIRED     = 2,
    LICENSE_STATUS_TAMPERED    = 3,
    LICENSE_STATUS_HW_MISMATCH = 4,
    LICENSE_STATUS_GRACE       = 5
} license_status_t;

typedef struct {
    license_type_t   type;
    license_status_t status;
    bool             is_valid;
    char             hwid[32];
    char             client_name[64];
    uint16_t         max_wans;
    uint32_t         days_total;
    uint32_t         days_remaining;
    uint64_t         issued_at;
    uint64_t         expires_at;
    uint64_t         active_seconds_remaining;
    uint32_t         grace_seconds_remaining;
    char             status_str[32];
    char             type_str[32];
} license_info_t;

#pragma pack(push, 1)
typedef struct {
    uint8_t  magic[4];       /* "FLIC" */
    uint8_t  version;        /* 1 */
    uint8_t  type;           /* 1=DAYS, 2=LIFETIME */
    uint16_t max_wans;       /* e.g. 256 */
    uint64_t issued_at;      /* UTC timestamp */
    uint64_t expires_at;     /* UTC timestamp (0 for lifetime) */
    uint32_t days_total;     /* Total days granted */
    char     hwid[32];       /* Hardware ID */
    char     client_name[64];/* Client / Network Name */
    uint8_t  features;       /* Feature bitmask */
    uint8_t  reserved[15];   /* Reserved */
} license_payload_t;
#pragma pack(pop)

/* Initialize license manager, compute local HWID, load existing key, and check status */
int license_manager_init(license_info_t *out_info);

/* Periodic tick called by reactor loop (e.g. every second/minute) to track uptime & anti-rollback */
void license_manager_tick(license_info_t *info, uint64_t now_ms);

/* Activate a new license string (from Web UI or CLI) */
int license_manager_activate(const char *license_key_str, license_info_t *out_info, char *err_msg, size_t err_len);

/* Get current local machine Hardware ID (e.g. "FWID-A1B2-C3D4-E5F6-7890") */
int license_get_hardware_id(char *out_hwid, size_t max_len);

/* Get global cached license info pointer */
const license_info_t *license_get_info(void);

/* Check if system operations are authorized (either valid license or within initial grace period) */
bool license_is_authorized(void);

#endif /* LICENSE_MANAGER_H */
