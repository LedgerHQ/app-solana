#pragma once

// IDL walker.
//
// Decodes the raw argument bytes of a Solana instruction against the
// kind-driven IDL type pool descriptor, matching each decoded leaf's path
// against the provided match_paths. Matched leaves are written to the resolved
// output array. The pool descriptor is owned by the idl_pool module (provide
// before walking, reset after). The walker is stateless across calls.
//
// Enum (IDL_KIND_ENUM) entries are decoded against the enum-variant cache
// (cs_enum_cache): the discriminator selects a variant, whose display name is
// emitted as the enum leaf and whose PAYLOAD_KIND drives cursor advancement —
// EMPTY consumes nothing, RAW_SIZE skips a fixed byte count, and INLINE
// descends the variant's self-contained inline type descriptor (its fields
// become leaves under the enum). A discriminator with no cached variant aborts
// the walk (returns -1).
//
// Resolved value pointers are borrowed, not copied. Most leaves point into the
// instruction data buffer passed to idl_walker_run(). The exception is an enum
// leaf, whose value is the variant name owned by the enum-variant cache: it
// stays valid only as long as that cache does (until cs_enum_cache_reset()).
// A caller must keep BOTH the data buffer and the enum cache alive until it has
// finished consuming the resolved leaves.

#include <stddef.h>
#include <stdint.h>

// One path to match during the walk (input, read-only). `path` is borrowed for
// the duration of idl_walker_run() only; the caller owns the bytes.
typedef struct {
    const uint8_t *path;
    uint8_t path_size;
} idl_match_path_t;

// One resolved leaf value produced by the walk (output).
typedef struct {
    uint8_t kind;          // IDL kind code
    const uint8_t *value;  // borrowed bytes: instruction data, or the enum
                           // variant name from the cache for IDL_KIND_ENUM
    size_t value_size;
} idl_resolved_leaf_t;

// Run the walk over `data` (`data_size` bytes) against the pool currently
// loaded in the idl_pool module.
//
// INPUT:
//   program_id   — 32-byte program id, used as the enum-variant cache key
//   match_paths  — array of paths to look for (read-only, not modified)
//   match_count  — number of entries in match_paths
//
// OUTPUT:
//   resolved     — caller-allocated array of at least match_count entries;
//                  on success, resolved[i] holds the leaf that matched
//                  match_paths[i] (or kind=0 / value=NULL if not reached)
//   resolved_count — number of slots that were actually filled
//
// A pool must have been provided via idl_pool_provide(). `data` may be NULL
// only when `data_size` is 0. The data buffer is borrowed for the duration of
// the call only.
//
// Returns 0 on success, -1 on error.
int idl_walker_run(const uint8_t *data,
                   size_t data_size,
                   const uint8_t program_id[32],
                   const idl_match_path_t *match_paths,
                   size_t match_count,
                   idl_resolved_leaf_t *resolved,
                   size_t *resolved_count);
