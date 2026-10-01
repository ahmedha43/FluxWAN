#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "fluxwan.h"

#define MAX_WIFI_SCAN_RESULTS 32

typedef struct {
    char ssid[64];
    char bssid[20];
    int signal_dbm;
    int signal_pct;
    uint32_t channel;
    char frequency[16];   /* "2.4 GHz" or "5 GHz" or "6 GHz" */
    char security[32];    /* "WPA2-PSK", "WPA3-SAE", "OPEN", "WPA2/WPA3" */
} wifi_scan_item_t;

typedef struct {
    bool connected;
    char ssid[64];
    char bssid[20];
    int signal_dbm;
    int signal_pct;
    uint32_t channel;
    uint32_t bitrate_mbps;
} wifi_link_status_t;

/**
 * Initialize WiFi subsystem (unblock rfkill if needed).
 */
int wifi_manager_init(void);

/**
 * Scan for available wireless networks on a given WiFi interface (e.g. "wlan0").
 * Returns count of discovered access points.
 */
int wifi_manager_scan(const char *ifname, wifi_scan_item_t *results, uint32_t max_results, uint32_t *count);

/**
 * Connect a WiFi interface to an Access Point / SSID with specified credentials.
 * Starts background wpa_supplicant and obtains DHCP lease.
 */
int wifi_manager_connect(const char *ifname, const char *ssid, const char *password, const char *security);

/**
 * Disconnect a WiFi interface and terminate its wpa_supplicant instance.
 */
int wifi_manager_disconnect(const char *ifname);

/**
 * Query live link status, signal dBm, and connection details for a WiFi interface.
 */
int wifi_manager_get_link_status(const char *ifname, wifi_link_status_t *status);

#endif /* WIFI_MANAGER_H */
