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

#endif /* CONFIG_H */
