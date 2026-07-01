#include "os.h"
#include "dynamic_token_info.h"
#include "ed25519_helpers.h"
#include "app_mem_utils.h"

void reset_dynamic_token_info(void) {
    if (g_dynamic_token_info != NULL) {
        PRINTF("reset_dynamic_token_info: freeing pool (count=%u)\n",
               (unsigned) g_dynamic_token_info->count);
        if (g_dynamic_token_info->entries != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &g_dynamic_token_info->entries);
        }
        APP_MEM_FREE_AND_NULL((void **) &g_dynamic_token_info);
    }
}

// Append a parsed token descriptor to the pool, growing the backing array
// on demand. The pool struct itself is allocated on the first call.
int dynamic_token_info_add(dynamic_token_info_t *entry) {
    if (g_dynamic_token_info == NULL) {
        if (!APP_MEM_CALLOC((void **) &g_dynamic_token_info,
                            sizeof(dynamic_token_info_pool_t))) {
            PRINTF("dynamic_token_info_add: pool allocation failed\n");
            return -1;
        }
    }

    if (g_dynamic_token_info->count >= g_dynamic_token_info->capacity) {
        size_t new_capacity;
        if (g_dynamic_token_info->capacity == 0) {
            new_capacity = 1;
        } else {
            new_capacity = g_dynamic_token_info->capacity * 2;
        }
        void *grown = APP_MEM_REALLOC(g_dynamic_token_info->entries,
                                      new_capacity * sizeof(dynamic_token_info_t));
        if (grown == NULL) {
            PRINTF("dynamic_token_info_add: realloc failed (capacity=%u)\n",
                   (unsigned) new_capacity);
            return -1;
        }
        g_dynamic_token_info->entries = grown;
        g_dynamic_token_info->capacity = new_capacity;
    }

    memcpy(&g_dynamic_token_info->entries[g_dynamic_token_info->count],
           entry,
           sizeof(dynamic_token_info_t));
    g_dynamic_token_info->count++;
    return 0;
}

// Linear scan over all received entries matching mint + token kind.
static const dynamic_token_info_t *find_entry(const uint8_t *mint_address,
                                              bool is_token_2022_kind) {
    if (g_dynamic_token_info == NULL || mint_address == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < g_dynamic_token_info->count; i++) {
        if (!g_dynamic_token_info->entries[i].received) {
            continue;
        }
        if (memcmp(g_dynamic_token_info->entries[i].mint_address,
                   mint_address,
                   PUBKEY_SIZE) != 0) {
            continue;
        }
        if (is_token_2022_kind != g_dynamic_token_info->entries[i].is_token_2022_kind) {
            continue;
        }
        return &g_dynamic_token_info->entries[i];
    }
    PRINTF("find_entry: no match for mint '%.*H'\n", PUBKEY_SIZE, mint_address);
    return NULL;
}

const char *get_dynamic_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind) {
    const dynamic_token_info_t *found = find_entry(mint_address, is_token_2022_kind);
    if (found == NULL) {
        PRINTF("get_dynamic_token_symbol: no match for mint '%.*H'\n",
               PUBKEY_SIZE,
               mint_address);
        return NULL;
    }
    PRINTF("get_dynamic_token_symbol: mint '%.*H' == ticker '%s'\n",
           PUBKEY_SIZE,
           found->mint_address,
           found->ticker);
    return found->ticker;
}

const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind) {
    const char *symbol = get_dynamic_token_symbol(mint_address, is_token_2022_kind);
    if (symbol == NULL) {
        PRINTF("get_token_symbol: no dynamic match, fallback on hardcoded list\n");
        symbol = get_hardcoded_token_symbol(mint_address);
    }
    return symbol;
}

// Returns the magnitude (decimal places) for a given mint, or -1 if not found.
int get_token_magnitude(const uint8_t *mint_address, bool is_token_2022_kind) {
    const dynamic_token_info_t *found = find_entry(mint_address, is_token_2022_kind);
    if (found == NULL) {
        PRINTF("get_token_magnitude: no match for mint '%.*H'\n",
               PUBKEY_SIZE,
               mint_address);
        return -1;
    }
    return (int) found->magnitude;
}

const uint8_t *get_dynamic_token_mint_address(const char *symbol, bool *is_token_2022_kind) {
    if (g_dynamic_token_info == NULL || symbol == NULL) {
        PRINTF("get_dynamic_token_mint_address: pool empty or NULL symbol\n");
        return NULL;
    }
    for (size_t i = 0; i < g_dynamic_token_info->count; i++) {
        if (!g_dynamic_token_info->entries[i].received) {
            continue;
        }
        if (strcmp(symbol, g_dynamic_token_info->entries[i].ticker) != 0) {
            continue;
        }
        *is_token_2022_kind = g_dynamic_token_info->entries[i].is_token_2022_kind;
        return g_dynamic_token_info->entries[i].mint_address;
    }
    PRINTF("get_dynamic_token_mint_address: no match for symbol '%s'\n", symbol);
    return NULL;
}

const uint8_t *get_token_mint_address(const char *symbol, bool *is_token_2022_kind) {
    const uint8_t *mint_address = get_dynamic_token_mint_address(symbol, is_token_2022_kind);
    if (mint_address == NULL) {
        PRINTF("get_token_mint_address: no dynamic match, fallback on hardcoded data\n");
        mint_address = get_hardcoded_token_mint_address(symbol, is_token_2022_kind);
    }
    return mint_address;
}
