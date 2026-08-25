#pragma once

// Session-scoped cache of the trusted names streamed by PROVIDE TRUSTED NAME,
// binding an address to a human-readable name for the render step. Heap-backed,
// allocated on demand and released on reset.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sol/pubkey.h"

// `type` is kept so a PARAM_TRUSTED_NAME field can enforce its type allow-list.
// The source is not stored: ingest only accepts CRYPTO_ASSET_LIST.
// `name` is heap-allocated to strlen(name) + 1, owned by this entry, so a short
// name costs a short buffer.
typedef struct cs_trusted_name_s {
    uint8_t address[PUBKEY_SIZE];
    uint8_t type;
    char *name;
} cs_trusted_name_t;

// Store one trusted name, given as `name_len` bytes that need not be NUL-terminated: the
// entry owns the terminated copy, so callers hand over the descriptor's bytes directly.
// Returns -1 when out of memory, the name is empty, or the key is duplicated.
int cs_trusted_name_cache_add(const uint8_t address[PUBKEY_SIZE],
                              const char *name,
                              size_t name_len,
                              uint8_t type);

// Returns the entry matching address, or NULL when none was provided.
const cs_trusted_name_t *cs_trusted_name_cache_find(const uint8_t address[PUBKEY_SIZE]);

size_t cs_trusted_name_cache_count(void);

// Release the cache. Safe when none allocated.
void cs_trusted_name_cache_reset(void);
