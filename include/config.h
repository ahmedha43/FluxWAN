#ifndef CONFIG_H
#define CONFIG_H

#include "fluxwan.h"

/**
 * Load configuration from JSON file.
 * @param config_path Path to the fluxwan.json file
 * @param out_config Pointer to fluxwan_config_t structure to populate
 * @return 0 on success, negative value on error
 */
int config_load(const char *config_path, fluxwan_config_t *out_config);

/**
 * Save current configuration back to JSON file.
 * @param config_path Path to the fluxwan.json file
 * @param config Pointer to fluxwan_config_t structure
 * @return 0 on success, negative value on error
 */
int config_save(const char *config_path, const fluxwan_config_t *config);

/**
 * Print loaded configuration to stdout (debugging)
 */
void config_print(const fluxwan_config_t *config);

/**
 * Validate WAN physical port allocations according to networking standards:
 * - LAN port exclusivity (cannot be shared with WAN)
 * - DHCP Client: 1 max per physical port (Exclusive L3)
 * - Static IP: 1 max per physical port (Exclusive L3)
 * - PPPoE Client: N multiple sessions allowed on the same physical port
 *
 * @param config Pointer to fluxwan_config_t structure
 * @param err_msg Output buffer for error description (optional)
 * @param err_size Size of err_msg buffer
 * @return true if valid, false if port conflict detected
 */
bool config_validate_wan_attachments(const fluxwan_config_t *config, char *err_msg, size_t err_size);

/**
 * Export complete configuration as a carrier-grade .fwb backup JSON string.
 * Includes metadata header, SHA-256 integrity checksum, and full network topology.
 * @param config Pointer to active fluxwan_config_t structure
 * @param out_json Output buffer for backup JSON string
 * @param max_len Size of out_json buffer
 * @return 0 on success, negative value on error
 */
int config_export_backup(const fluxwan_config_t *config, char *out_json, size_t max_len);

/**
 * Import and validate a backup (.fwb or raw fluxwan.json) string.
 * @param backup_json Incoming backup JSON string
 * @param out_config Pointer to destination fluxwan_config_t structure
 * @param err_msg Output buffer for error or validation messages
 * @param err_size Size of err_msg buffer
 * @return 0 on success, negative value on error
 */
int config_import_backup(const char *backup_json, fluxwan_config_t *out_config, char *err_msg, size_t err_size);

/**
 * Reset router configuration to clean factory defaults.
 * Configures default LAN (eth0 192.168.90.1/24), DHCP pool, and factory admin credentials.
 * @param out_config Destination configuration structure to populate with defaults
 * @return 0 on success
 */
int config_reset_to_defaults(fluxwan_config_t *out_config);

/**
 * Calculate fast checksum for configuration data integrity validation.
 */
uint32_t config_calc_checksum(const char *data);

#endif /* CONFIG_H */
