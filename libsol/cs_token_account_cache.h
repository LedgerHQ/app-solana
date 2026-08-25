#pragma once

// Token-account-state cache for clear signing.
//
// Owns the signed TOKEN_ACCOUNT_STATE descriptors streamed by PROVIDE TOKEN
// ACCOUNT STATE (0x27) during the Phase A descriptor preload. Each descriptor
// binds a token account address to its chain-attested pre-balance, and to its
// mint and owner where the account exists, letting the finalize step resolve a
// token amount's ticker and decimals when the mint is not itself an
// in-transaction account (e.g. a plain SPL transfer that only references the
// source/destination token accounts).
//
// The cache lives on the heap (allocated on demand, released on reset) and is
// session-scoped, mirroring cs_enum_cache and the instruction template table.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sol/pubkey.h"

// One cached token account state, keyed by account_address. Every field is the
// chain-attested value committed to by the HSM signature verified at ingest.
typedef struct cs_token_account_s {
    uint8_t account_address[PUBKEY_SIZE];
    // An account that does not exist yet has no mint and no owner on chain, so a
    // descriptor attesting one carries neither. The field behind a false flag is
    // zeroed, never an attested key.
    bool has_mint;
    uint8_t mint[PUBKEY_SIZE];
    bool has_owner;
    uint8_t owner[PUBKEY_SIZE];
    uint64_t pre_balance;
} cs_token_account_t;

// Store one token account state keyed by account_address. A NULL `mint` or `owner`
// is a field the descriptor omitted. Returns 0 on success, -1 when the pool cannot
// allocate or the key already exists (duplicate descriptor).
int cs_token_account_cache_add(const uint8_t account_address[PUBKEY_SIZE],
                               const uint8_t *mint,
                               const uint8_t *owner,
                               uint64_t pre_balance);

// Find the cached token account state matching account_address. Returns NULL
// when no descriptor was provided for that account.
const cs_token_account_t *cs_token_account_cache_find(const uint8_t account_address[PUBKEY_SIZE]);

// Number of cached token account states.
size_t cs_token_account_cache_count(void);

// Cached token account state at `index`, for callers enumerating the whole cache.
// Returns NULL when the index is past the end.
const cs_token_account_t *cs_token_account_cache_at(size_t index);

// Release the cache, returning to the empty state. Safe when none allocated.
void cs_token_account_cache_reset(void);
