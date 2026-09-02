#include "sticky.h"

typedef struct sticky_node {
    uint32_t client_ip;
    uint32_t wan_id;
    uint64_t last_seen_sec;
    struct sticky_node *next;
} sticky_node_t;

struct sticky_table {
    sticky_node_t **buckets;
    uint32_t num_buckets;
    uint32_t timeout_sec;
    uint32_t active_count;
};

static uint32_t hash_ip(uint32_t ip, uint32_t num_buckets) {
    uint32_t hash = ip;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    return hash % num_buckets;
}

sticky_table_t *sticky_table_init(uint32_t max_entries, uint32_t timeout_sec) {
    (void)max_entries;
    sticky_table_t *table = calloc(1, sizeof(sticky_table_t));
    if (!table) return NULL;

    table->num_buckets = 1024;
    table->timeout_sec = timeout_sec;
    table->buckets = calloc(table->num_buckets, sizeof(sticky_node_t *));
    if (!table->buckets) {
        free(table);
        return NULL;
    }

    LOG_INFO("Sticky Session Engine initialized (Timeout: %us)", timeout_sec);
    return table;
}

void sticky_table_destroy(sticky_table_t *table) {
    if (!table) return;
    for (uint32_t i = 0; i < table->num_buckets; i++) {
        sticky_node_t *curr = table->buckets[i];
        while (curr) {
            sticky_node_t *tmp = curr;
            curr = curr->next;
            free(tmp);
        }
    }
    free(table->buckets);
    free(table);
}

uint32_t sticky_lookup(sticky_table_t *table, uint32_t client_ip) {
    if (!table || client_ip == 0) return 0;
    uint32_t idx = hash_ip(client_ip, table->num_buckets);
    uint64_t now = (uint64_t)time(NULL);

    sticky_node_t *curr = table->buckets[idx];
    while (curr) {
        if (curr->client_ip == client_ip) {
            if (now - curr->last_seen_sec <= table->timeout_sec) {
                curr->last_seen_sec = now; /* Refresh lease */
                return curr->wan_id;
            }
            return 0; /* Expired */
        }
        curr = curr->next;
    }
    return 0;
}

int sticky_insert(sticky_table_t *table, uint32_t client_ip, uint32_t wan_id) {
    if (!table || client_ip == 0 || wan_id == 0) return -1;
    uint32_t idx = hash_ip(client_ip, table->num_buckets);
    uint64_t now = (uint64_t)time(NULL);

    sticky_node_t *curr = table->buckets[idx];
    while (curr) {
        if (curr->client_ip == client_ip) {
            curr->wan_id = wan_id;
            curr->last_seen_sec = now;
            return 0;
        }
        curr = curr->next;
    }

    sticky_node_t *node = malloc(sizeof(sticky_node_t));
    if (!node) return -1;
    node->client_ip = client_ip;
    node->wan_id = wan_id;
    node->last_seen_sec = now;
    node->next = table->buckets[idx];
    table->buckets[idx] = node;
    table->active_count++;
    return 0;
}

void sticky_cleanup_expired(sticky_table_t *table) {
    if (!table) return;
    uint64_t now = (uint64_t)time(NULL);

    for (uint32_t i = 0; i < table->num_buckets; i++) {
        sticky_node_t **prev_ptr = &table->buckets[i];
        sticky_node_t *curr = table->buckets[i];

        while (curr) {
            if (now - curr->last_seen_sec > table->timeout_sec) {
                sticky_node_t *expired = curr;
                *prev_ptr = curr->next;
                curr = curr->next;
                free(expired);
                if (table->active_count > 0) table->active_count--;
            } else {
                prev_ptr = &curr->next;
                curr = curr->next;
            }
        }
    }
}
