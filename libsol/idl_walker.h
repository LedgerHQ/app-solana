#pragma once

// IDL walker.
//
// The walker decodes the raw argument bytes of a Solana instruction using the
// trimmed, kind-driven "IDL type pool" descriptor shipped by the CAL backend
// inside an INSTRUCTION_INFO TLV, and emits the displayable leaf values
// referenced by the instruction's DISPLAY_FIELD / VALUE_FLOW_PORT
// substructures.
//
// Output is delivered as the walk progresses: every decoded leaf is handed to
// a caller-supplied callback, so the consumer can match it against the
// instruction's DISPLAY_FIELD set and format it immediately, holding on to
// nothing it does not display. The walker never materializes the full set of
// leaves at once.
//
// Enum (IDL_KIND_ENUM) decoding is not implemented yet: hitting an enum entry
// on a reachable path aborts the walk (idl_walker_run returns -1).
//
// Sizing policy: there is NO arbitrary cap on any input or output length. The
// inputs are borrowed (never copied), and leaves are streamed one at a time,
// so the only size-related failure is the allocator running out of space.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "idl_kinds.h"

// One decoded output leaf: a value located at a packed argument path.
//
// This struct is only ever handed to the leaf callback by const pointer, and
// both buffers it points to are valid ONLY for the duration of that call:
//   - `path` is scratch owned by the walker and reclaimed right after the
//     callback returns; copy it if you need to keep it.
//   - `value` is borrowed from a signed buffer that outlives the walk (the
//     instruction data today; an enum-variant descriptor once enums land), so
//     it stays valid after the call too, but treat it as read-only.
// The raw value bytes are kept verbatim; formatting (amount, datetime, enum
// label, ...) is the consumer's responsibility, driven by the matching
// DISPLAY_FIELD.
//
// `kind` carries the source IDL_TYPE_POOL kind code (U8..U128, I8..I128,
// SHORT_U16, BOOL_U8/16/32, F32/F64, PUBKEY_32, STRING_*, BYTES_*, ...; see
// spec/device/idl_descriptor.md). It is REQUIRED to interpret `value`: the raw
// bytes alone are ambiguous (a 1-byte 0xFF is U8 255 or I8 -1; a 2-byte slice
// is a little-endian U16 or a SHORT_U16 varint; 4 bytes are U32 or F32), and
// the DISPLAY_FIELD only says how to *format* the decoded value, not how to
// decode the bytes into it. The consumer switches on `kind` to read `value`,
// then applies the formatter.
typedef struct idl_leaf_s {
    const uint8_t *path;    // packed argument path (u8 step_count || packed steps), scratch
    size_t path_size;       // length of `path` in bytes
    uint8_t kind;           // source IDL_TYPE_POOL kind code (see idl_descriptor.md)
    const uint8_t *value;   // raw leaf value bytes (encoding per `kind`), borrowed
    size_t value_size;      // length of `value` in bytes
} idl_leaf_t;

// Per-leaf callback. Invoked once for every decoded leaf, in walk order.
// `leaf` and the buffers it references are valid only for the duration of the
// call (see idl_leaf_t). `callback_context` is the opaque pointer passed to
// idl_walker_run().
typedef void (*idl_leaf_cb_t)(const idl_leaf_t *leaf, void *callback_context);

// Parsed pool entry view, owned by the walker between provide and reset.
// Defined privately in idl_walker.c.
struct entry_s;

// Walker context. Zero-initialize through idl_walker_init() before use and
// release every allocation through idl_walker_reset() afterwards.
typedef struct idl_walker_s {
    // --- Parsed IDL type pool descriptor -----------------------------------
    // The entry array is owned by the walker; its internal pointers borrow
    // into the caller's pool bytes, which MUST stay alive until reset.
    struct entry_s *entries;  // owned parsed pool entries, NULL until provided
    uint8_t entry_count;      // number of parsed entries
    uint8_t root_index;       // IDL_ROOT_TYPE: pool index of the root arg struct
    bool pool_ready;          // a pool descriptor has been parsed

    // --- Input: instruction data (from transaction reception) --------------
    const uint8_t *data;  // borrowed raw instruction data buffer (caller-owned)
    size_t data_size;     // length of `data` in bytes
    bool data_ready;      // an instruction data buffer has been forwarded
} idl_walker_t;

// Reset the context to a clean, empty state WITHOUT freeing. Call once on a
// fresh (uninitialized) context before the first use.
void idl_walker_init(idl_walker_t *walker);

// Parse the IDL type pool descriptor and store it in the walker. The pool
// bytes are borrowed: the caller MUST keep the buffer alive until
// idl_walker_reset(), because the parsed entries point into it. Re-forwarding
// frees any previously parsed pool and replaces it.
//
// Returns 0 on success, -1 on invalid arguments, a malformed pool, a
// root_index out of range, or allocator out-of-space.
int idl_walker_provide_pool(idl_walker_t *walker,
                            const uint8_t *pool,
                            size_t pool_size,
                            uint8_t root_index);

// Forward the raw instruction data buffer into the walker. The pointer is
// borrowed: the caller MUST keep the buffer alive until idl_walker_reset().
// Re-forwarding replaces any previously stored data reference.
//
// Returns 0 on success, -1 on invalid arguments.
int idl_walker_provide_instruction_data(idl_walker_t *walker,
                                        const uint8_t *data,
                                        size_t data_size);

// Run the walk, delivering each decoded leaf to `leaf_callback` (with
// `callback_context` threaded through). Requires that both a pool descriptor
// and an instruction data buffer have been forwarded. `leaf_callback` may be
// NULL to run the walk for its side effects (e.g. cursor validation) without
// emitting anything.
//
// The walk returns -1 on any descriptor/data inconsistency:
// a read past the end of the instruction data, a leftover or missing byte
// once the walk completes (cursor must land exactly on the end of the data),
// a malformed pool, or an unsupported kind (e.g. IDL_KIND_ENUM).
//
// Returns 0 on success, -1 on missing inputs, a failed walk, or allocator
// out-of-space.
int idl_walker_run(idl_walker_t *walker, idl_leaf_cb_t leaf_callback, void *callback_context);

// Free the owned parsed pool, drop the borrowed data reference, and return the
// context to the empty state. Safe to call multiple times and on a
// zero-initialized context.
void idl_walker_reset(idl_walker_t *walker);
