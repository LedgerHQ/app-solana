// Address Lookup Table resolution cache for clear signing. See cs_alt_cache.h.
//
// Holds the signed ALT_RESOLUTION descriptors provided during the descriptor
// preload so the finalize step can resolve an ALT-loaded account index to its
// chain-attested concrete public key.

#include "cs_alt_cache.h"

#include <string.h>

#include "app_mem_utils.h"
#include "os_print.h"

// =============================================================================
// Module-global table
// =============================================================================

// Each entry is allocated on demand so the cache only consumes heap
// proportional to the number of ALT resolutions actually provided. The table
// itself is a tiny static array of pointers plus a count.
typedef struct cs_alt_cache_table_s {
    cs_alt_entry_t **entries;  // grown by one entry per add (APDU-paced)
    size_t count;
} cs_alt_cache_table_t;

static cs_alt_cache_table_t G_alt_cache;

int cs_alt_cache_add(const uint8_t alt_address[PUBKEY_SIZE],
                     uint8_t entry_index,
                     const uint8_t resolved_address[PUBKEY_SIZE]) {
    PRINTF("cs_alt_cache_add: entry_index %d, current count %u\n",
           entry_index,
           (unsigned) G_alt_cache.count);
    // The (alt_address, entry_index) key must be unique.
    if (cs_alt_cache_find(alt_address, entry_index) != NULL) {
        PRINTF("cs_alt_cache_add: duplicate (alt_address, entry_index)\n");
        return -1;
    }
    // Grow the pointer array to hold exactly one more entry.
    cs_alt_entry_t **grown = APP_MEM_REALLOC(G_alt_cache.entries,
                                             (G_alt_cache.count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("cs_alt_cache_add: table growth failed\n");
        return -1;
    }
    G_alt_cache.entries = grown;

    cs_alt_entry_t *slot = NULL;
    if (!APP_MEM_CALLOC((void **) &slot, sizeof(*slot))) {
        PRINTF("cs_alt_cache_add: entry allocation failed\n");
        return -1;
    }
    memcpy(slot->alt_address, alt_address, PUBKEY_SIZE);
    slot->entry_index = entry_index;
    memcpy(slot->resolved_address, resolved_address, PUBKEY_SIZE);

    G_alt_cache.entries[G_alt_cache.count] = slot;
    G_alt_cache.count++;
    PRINTF("cs_alt_cache_add: stored entry %u\n", (unsigned) (G_alt_cache.count - 1));
    PRINTF("  alt_address      = %.*H\n", PUBKEY_SIZE, alt_address);
    PRINTF("  entry_index      = %d\n", entry_index);
    PRINTF("  resolved_address = %.*H\n", PUBKEY_SIZE, resolved_address);
    return 0;
}

const uint8_t *cs_alt_cache_find(const uint8_t alt_address[PUBKEY_SIZE], uint8_t entry_index) {
    for (size_t i = 0; i < G_alt_cache.count; i++) {
        if (G_alt_cache.entries[i]->entry_index == entry_index &&
            memcmp(G_alt_cache.entries[i]->alt_address, alt_address, PUBKEY_SIZE) == 0) {
            PRINTF("cs_alt_cache_find: hit at slot %u for entry_index %d\n",
                   (unsigned) i,
                   entry_index);
            return G_alt_cache.entries[i]->resolved_address;
        }
    }
    PRINTF("cs_alt_cache_find: miss for entry_index %d\n", entry_index);
    PRINTF("  alt_address = %.*H\n", PUBKEY_SIZE, alt_address);
    return NULL;
}

size_t cs_alt_cache_count(void) {
    return G_alt_cache.count;
}

void cs_alt_cache_reset(void) {
    PRINTF("cs_alt_cache_reset: releasing %u entries\n", (unsigned) G_alt_cache.count);
    for (size_t i = 0; i < G_alt_cache.count; i++) {
        APP_MEM_FREE_AND_NULL((void **) &G_alt_cache.entries[i]);
    }
    if (G_alt_cache.entries != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &G_alt_cache.entries);
    }
    G_alt_cache.count = 0;
}
