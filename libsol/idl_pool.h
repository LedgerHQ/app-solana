#pragma once

// IDL type pool.
//
// Owns the parsed form of the "IDL type pool" descriptor (the IDL_TYPE_POOL
// payload shipped by the CAL backend inside an INSTRUCTION_INFO TLV). The raw
// descriptor is parsed once into a module-global array of structured entries;
// the IDL walker reads it back through the getters below.
//
// The parsed entries borrow into the caller's raw pool bytes: that buffer MUST
// stay alive from idl_pool_provide() until idl_pool_reset(). Only one pool is
// loaded at a time; providing a new one replaces the previous.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "idl_kinds.h"

// A single parsed IDL_TYPE_POOL entry. Pointer fields borrow into the caller's
// raw pool bytes; only the entry array itself is owned by this module.
typedef struct idl_pool_entry_s {
    uint8_t kind;             // IDL_KIND_*
    uint16_t fixed_size;      // BYTES_FIXED/STRING_FIXED byte size, ARRAY_FIXED count
    uint8_t encoding;         // STRING_FIXED/STRING_PREFIXED encoding (unused by the walk)
    uint8_t len_kind;         // STRING_PREFIXED/ARRAY_PREFIXED length kind
    uint8_t flag_kind;        // OPTION_DYNAMIC/OPTION_FIXED flag kind
    uint8_t disc_kind;        // ENUM discriminator kind
    uint16_t total_variants;  // ENUM total variant count
    const uint8_t *refs;      // pointer into pool bytes: ref_count contiguous u8 indices
    uint8_t ref_count;
    const uint8_t *sentinel;  // OPTION_ZEROABLE sentinel bytes
    uint8_t sentinel_len;
    const uint8_t *enum_id;  // ENUM identifier bytes
    uint8_t enum_id_len;
} idl_pool_entry_t;

// Parse the raw IDL_TYPE_POOL payload (`u8 count || entries`) into the
// module-global parsed pool, replacing any previously parsed pool. The raw
// `pool` bytes are borrowed and MUST stay alive until idl_pool_reset().
// `root_index` selects the pool entry that is the root argument struct.
//
// Returns 0 on success, -1 on invalid arguments, a malformed pool, a
// root_index out of range, or allocator out-of-space.
int idl_pool_provide(const uint8_t *pool, size_t pool_size, uint8_t root_index);

// True once a pool has been parsed and is ready to walk.
bool idl_pool_ready(void);

// Number of parsed entries (0 until a pool is provided).
uint8_t idl_pool_count(void);

// Pool index of the root argument struct (meaningful only when ready).
uint8_t idl_pool_root_index(void);

// Borrow the parsed entry at `index`, or NULL when no pool is loaded or
// `index` is out of range. The returned pointer is valid until idl_pool_reset().
const idl_pool_entry_t *idl_pool_entry(uint8_t index);

// Free the parsed pool and return the module to the empty state. Safe to call
// when no pool is loaded.
void idl_pool_reset(void);
