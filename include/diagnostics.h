#ifndef FLUXWAN_DIAGNOSTICS_H
#define FLUXWAN_DIAGNOSTICS_H

#include "fluxwan.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char interface[MAX_IFNAME_LEN];
    char wan_label[MAX_LABEL_LEN];
    double ping_ms;
    double download_mbps;
    double upload_mbps;
    bool success;
    char error_msg[256];
} speedtest_result_t;

typedef struct {
    uint32_t wan_count;
    double total_download_mbps;
    double total_upload_mbps;
    double min_ping_ms;
    double avg_ping_ms;
    bool success;
    char error_msg[256];
    speedtest_result_t wans[MAX_WANS];
} multiwan_speedtest_result_t;

/**
 * Executes a lightweight multi-stream speedtest bound specifically to `ifname` via SO_BINDTODEVICE.
 * Tests Ping, Download throughput, and Upload throughput.
 */
int diagnostics_run_speedtest(const char *ifname, speedtest_result_t *out);

/**
 * Executes a concurrent, parallel speedtest across all active WAN lines simultaneously.
 * Aggregates combined throughput and provides per-WAN performance breakdown.
 */
int diagnostics_run_multiwan_speedtest(const fluxwan_config_t *config, multiwan_speedtest_result_t *out);

/**
 * Analyzes gaming latency across all enabled WAN uplinks for popular regional game servers.
 * Produces structured JSON output with per-WAN comparisons and marks the champion line.
 */
int diagnostics_run_gaming_analyzer(const fluxwan_config_t *config, char *out_json, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* FLUXWAN_DIAGNOSTICS_H */
