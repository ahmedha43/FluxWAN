#ifndef STICKY_H
#define STICKY_H

#include "fluxwan.h"

typedef struct sticky_table sticky_table_t;

/**
 * Initialize Sticky Session Table
 */
sticky_table_t *sticky_table_init(uint32_t max_entries, uint32_t timeout_sec);

/**
 * Destroy Sticky Session Table
 */
void sticky_table_destroy(sticky_table_t *table);

/**
 * Lookup assigned WAN ID for a given client IP
 * @return WAN ID (>= 1) if sticky entry active, 0 if not found
 */
uint32_t sticky_lookup(sticky_table_t *table, uint32_t client_ip);

/**
 * Bind client IP to specific WAN ID
 */
int sticky_insert(sticky_table_t *table, uint32_t client_ip, uint32_t wan_id);

/**
 * Evict expired sticky entries
 */
void sticky_cleanup_expired(sticky_table_t *table);

#endif /* STICKY_H */
