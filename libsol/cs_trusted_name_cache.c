// Trusted-name cache for clear signing. See cs_trusted_name_cache.h.

#include "cs_trusted_name_cache.h"

#include <string.h>

#include "app_mem_utils.h"
#include "os_print.h"

// Entries are allocated on demand; the table is a static array of pointers.
typedef struct cs_trusted_name_cache_table_s {
    cs_trusted_name_t **names;  // grown by one entry per add (APDU-paced)
    size_t count;
} cs_trusted_name_cache_table_t;

static cs_trusted_name_cache_table_t G_trusted_name_cache;

int cs_trusted_name_cache_add(const uint8_t address[PUBKEY_SIZE], const char *name, uint8_t type) {
    if (name == NULL) {
        PRINTF("cs_trusted_name_cache_add: NULL name\n");
        return -1;
    }
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len > CS_TRUSTED_NAME_MAX_LEN) {
        PRINTF("cs_trusted_name_cache_add: invalid name length %u\n", (unsigned) name_len);
        return -1;
    }
    if (cs_trusted_name_cache_find(address) != NULL) {
        PRINTF("cs_trusted_name_cache_add: duplicate address\n");
        return -1;
    }
    // Grow the pointer array to hold exactly one more entry.
    cs_trusted_name_t **grown = APP_MEM_REALLOC(G_trusted_name_cache.names,
                                                (G_trusted_name_cache.count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("cs_trusted_name_cache_add: table growth failed\n");
        return -1;
    }
    G_trusted_name_cache.names = grown;

    cs_trusted_name_t *slot = NULL;
    if (!APP_MEM_CALLOC((void **) &slot, sizeof(*slot))) {
        PRINTF("cs_trusted_name_cache_add: entry allocation failed\n");
        return -1;
    }
    // The name buffer is sized to its exact length and owned by the slot.
    if (!APP_MEM_CALLOC((void **) &slot->name, name_len + 1)) {
        PRINTF("cs_trusted_name_cache_add: name allocation failed\n");
        APP_MEM_FREE_AND_NULL((void **) &slot);
        return -1;
    }
    memcpy(slot->address, address, PUBKEY_SIZE);
    memcpy(slot->name, name, name_len);
    slot->name[name_len] = '\0';
    slot->type = type;

    G_trusted_name_cache.names[G_trusted_name_cache.count] = slot;
    G_trusted_name_cache.count++;
    return 0;
}

const cs_trusted_name_t *cs_trusted_name_cache_find(const uint8_t address[PUBKEY_SIZE]) {
    for (size_t i = 0; i < G_trusted_name_cache.count; i++) {
        if (memcmp(G_trusted_name_cache.names[i]->address, address, PUBKEY_SIZE) == 0) {
            return G_trusted_name_cache.names[i];
        }
    }
    return NULL;
}

size_t cs_trusted_name_cache_count(void) {
    return G_trusted_name_cache.count;
}

void cs_trusted_name_cache_reset(void) {
    for (size_t i = 0; i < G_trusted_name_cache.count; i++) {
        APP_MEM_FREE_AND_NULL((void **) &G_trusted_name_cache.names[i]->name);
        APP_MEM_FREE_AND_NULL((void **) &G_trusted_name_cache.names[i]);
    }
    if (G_trusted_name_cache.names != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &G_trusted_name_cache.names);
    }
    G_trusted_name_cache.count = 0;
}
