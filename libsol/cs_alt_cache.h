#pragma once

// Address Lookup Table (ALT) resolution cache for clear signing.
//
// Owns the signed ALT_RESOLUTION descriptors streamed by PROVIDE ALT RESOLUTION
// (0x28) during the Phase A descriptor preload. Each descriptor binds a single
// ALT entry, keyed by (alt_address, entry_index), to the concrete public key it
// resolves to. Versioned (v0) transactions reference accounts loaded from an ALT
// by an index beyond the statically listed keys; the finalize step maps such an
// index back to its (alt_address, entry_index) origin and looks up the attested
// resolved address here.
//
// The cache lives on the heap (allocated on demand, released on reset) and is
// session-scoped, mirroring cs_token_account_cache and the enum cache.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sol/parser.h"

// One cached ALT resolution, keyed by (alt_address, entry_index). The
// resolved_address is the chain-attested value committed to by the HSM
// signature verified at ingest.
typedef struct cs_alt_entry_s {
    uint8_t alt_address[PUBKEY_SIZE];
    uint8_t entry_index;
    uint8_t resolved_address[PUBKEY_SIZE];
} cs_alt_entry_t;

// Store one ALT resolution keyed by (alt_address, entry_index). Returns 0 on
// success, -1 when the pool cannot allocate or the key already exists
// (duplicate descriptor).
int cs_alt_cache_add(const uint8_t alt_address[PUBKEY_SIZE],
                     uint8_t entry_index,
                     const uint8_t resolved_address[PUBKEY_SIZE]);

// Find the resolved 32-byte address for (alt_address, entry_index). Returns a
// pointer to the cached resolved address, or NULL when no descriptor was
// provided for that entry.
const uint8_t *cs_alt_cache_find(const uint8_t alt_address[PUBKEY_SIZE], uint8_t entry_index);

// Number of cached ALT resolutions.
size_t cs_alt_cache_count(void);

// Release the cache, returning to the empty state. Safe when none allocated.
void cs_alt_cache_reset(void);
