// Token-account-state cache for clear signing. See cs_token_account_cache.h.
//
// Holds the signed TOKEN_ACCOUNT_STATE descriptors provided during the
// descriptor preload so the finalize step can resolve a token account to its
// chain-attested mint (and thus a ticker/decimals) when the mint is not an
// in-transaction account.

#include "cs_token_account_cache.h"

#include <string.h>

#include "app_mem_utils.h"
#include "os_print.h"

// =============================================================================
// Module-global table
// =============================================================================

// Each entry is allocated on demand so the cache only consumes heap
// proportional to the number of token account states actually provided. The
// table itself is a tiny static array of pointers plus a count.
typedef struct cs_token_account_cache_table_s {
    cs_token_account_t *accounts[CS_MAX_TOKEN_ACCOUNTS];
    uint8_t count;
} cs_token_account_cache_table_t;

static cs_token_account_cache_table_t G_token_account_cache;

int cs_token_account_cache_add(const uint8_t account_address[32],
                               const uint8_t mint[32],
                               const uint8_t owner[32],
                               uint64_t pre_balance) {
    // The account_address key must be unique.
    if (cs_token_account_cache_find(account_address) != NULL) {
        PRINTF("cs_token_account_cache_add: duplicate account address\n");
        return -1;
    }
    if (G_token_account_cache.count >= CS_MAX_TOKEN_ACCOUNTS) {
        PRINTF("cs_token_account_cache_add: cache full (max %d)\n", CS_MAX_TOKEN_ACCOUNTS);
        return -1;
    }

    cs_token_account_t *slot = NULL;
    if (!APP_MEM_CALLOC((void **) &slot, sizeof(*slot))) {
        PRINTF("cs_token_account_cache_add: entry allocation failed\n");
        return -1;
    }
    memcpy(slot->account_address, account_address, 32);
    memcpy(slot->mint, mint, 32);
    memcpy(slot->owner, owner, 32);
    slot->pre_balance = pre_balance;

    G_token_account_cache.accounts[G_token_account_cache.count] = slot;
    G_token_account_cache.count++;
    return 0;
}

const cs_token_account_t *cs_token_account_cache_find(const uint8_t account_address[32]) {
    for (uint8_t i = 0; i < G_token_account_cache.count; i++) {
        if (memcmp(G_token_account_cache.accounts[i]->account_address, account_address, 32) == 0) {
            return G_token_account_cache.accounts[i];
        }
    }
    return NULL;
}

uint8_t cs_token_account_cache_count(void) {
    return G_token_account_cache.count;
}

void cs_token_account_cache_reset(void) {
    for (uint8_t i = 0; i < G_token_account_cache.count; i++) {
        APP_MEM_FREE_AND_NULL((void **) &G_token_account_cache.accounts[i]);
    }
    G_token_account_cache.count = 0;
}
