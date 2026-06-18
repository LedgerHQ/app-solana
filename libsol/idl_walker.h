#pragma once

// IDL walker (scaffolding).
//
// The walker decodes the raw argument bytes of a Solana instruction using the
// trimmed, kind-driven "IDL type pool" descriptor shipped by the CAL backend
// inside an INSTRUCTION_INFO TLV, and emits the displayable leaf values
// referenced by the instruction's DISPLAY_FIELD / VALUE_FLOW_PORT
// substructures.
//
// This file currently provides ONLY the scaffolding around the future walk:
//   - forwarding of the IDL type pool descriptor (from TLV reception),
//   - forwarding of the instruction data buffer (from transaction reception),
//   - forwarding of the produced leaves to the consumer (mock output for now).
// The actual type-tree walk and enum-variant handling are intentionally left
// unimplemented.
//
// Sizing policy: there is NO arbitrary cap on any input or output length. All
// variable-size storage is dynamically allocated, so the only size-related
// failure is the allocator running out of space.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// One decoded output leaf: a value located at a packed argument path.
//
// Both buffers are owned by the walker and freed by idl_walker_reset(). The
// raw value bytes are kept verbatim; formatting (amount, datetime, enum label,
// ...) is the consumer's responsibility, driven by the matching DISPLAY_FIELD.
typedef struct idl_leaf_s {
    uint8_t *path;       // packed argument path (u8 step_count || packed steps)
    size_t path_size;    // length of `path` in bytes
    uint8_t *value;      // raw little-endian leaf value bytes
    size_t value_size;   // length of `value` in bytes
} idl_leaf_t;

// Walker context. Zero-initialize through idl_walker_init() before use and
// release every allocation through idl_walker_reset() afterwards.
typedef struct idl_walker_s {
    // --- Input: IDL type pool descriptor (from INSTRUCTION_INFO TLV) --------
    uint8_t *pool;        // owned copy of the IDL_TYPE_POOL bytes
    size_t pool_size;     // length of `pool` in bytes
    uint8_t root_index;   // IDL_ROOT_TYPE: pool index of the root arg struct
    bool pool_ready;      // a pool descriptor has been forwarded

    // --- Input: instruction data (from transaction reception) --------------
    uint8_t *data;        // owned copy of the raw instruction data buffer
    size_t data_size;     // length of `data` in bytes
    bool data_ready;      // an instruction data buffer has been forwarded

    // --- Output: decoded leaves --------------------------------------------
    idl_leaf_t *leaves;   // owned array of produced leaves
    size_t leaf_count;    // number of valid entries in `leaves`
} idl_walker_t;

// Reset the context to a clean, empty state WITHOUT freeing. Call once on a
// fresh (uninitialized) context before the first use.
void idl_walker_init(idl_walker_t *walker);

// Forward the IDL type pool descriptor into the walker. The bytes are copied
// into an owned buffer, so the caller may release its own storage afterwards.
// Re-forwarding replaces any previously stored pool.
//
// Returns 0 on success, -1 on invalid arguments or allocator out-of-space.
int idl_walker_provide_pool(idl_walker_t *walker,
                            const uint8_t *pool,
                            size_t pool_size,
                            uint8_t root_index);

// Forward the raw instruction data buffer into the walker. The bytes are
// copied into an owned buffer. Re-forwarding replaces any previously stored
// data.
//
// Returns 0 on success, -1 on invalid arguments or allocator out-of-space.
int idl_walker_provide_instruction_data(idl_walker_t *walker,
                                        const uint8_t *data,
                                        size_t data_size);

// Run the walk and forward the produced leaves. Requires that both a pool
// descriptor and an instruction data buffer have been forwarded.
//
// SCAFFOLDING: the real type-tree walk is not implemented yet, so this emits
// deterministic mock leaves derived from the forwarded inputs.
//
// Returns 0 on success, -1 on missing inputs or allocator out-of-space.
int idl_walker_run(idl_walker_t *walker);

// Free every owned allocation and return the context to the empty state. Safe
// to call multiple times and on a zero-initialized context.
void idl_walker_reset(idl_walker_t *walker);
