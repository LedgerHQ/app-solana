#pragma once

// Session-scoped cache of the trusted names streamed by PROVIDE TRUSTED NAME,
// binding an address to a human-readable name for the render step. Heap-backed,
// allocated on demand and released on reset.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Maximum accepted name length, excluding the NUL terminator. This is a
// validation bound only: storage is sized to the actual name (see `name`).
#define CS_TRUSTED_NAME_MAX_LEN 64

// `type` is kept so a PARAM_TRUSTED_NAME field can enforce its type allow-list.
// The source is not stored: ingest only accepts CRYPTO_ASSET_LIST.
// `name` is heap-allocated to strlen(name) + 1, owned by this entry, so a short
// name costs a short buffer.
typedef struct cs_trusted_name_s {
    uint8_t address[32];
    uint8_t type;
    char *name;
} cs_trusted_name_t;

// Store one trusted name (`name` NUL-terminated, at most CS_TRUSTED_NAME_MAX_LEN
// long). Returns -1 when out of memory, name invalid, or key duplicated.
int cs_trusted_name_cache_add(const uint8_t address[32], const char *name, uint8_t type);

// Returns the entry matching address, or NULL when none was provided.
const cs_trusted_name_t *cs_trusted_name_cache_find(const uint8_t address[32]);

uint8_t cs_trusted_name_cache_count(void);

// Release the cache. Safe when none allocated.
void cs_trusted_name_cache_reset(void);
