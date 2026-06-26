#pragma once

// IDL walker.
//
// Decodes the raw argument bytes of a Solana instruction against the
// kind-driven IDL type pool descriptor, matching each decoded leaf's path
// against the provided match_paths. Matched leaves are written to the resolved
// output array. The pool descriptor is owned by the idl_pool module (provide
// before walking, reset after). The walker is stateless across calls.
//
// Enum (IDL_KIND_ENUM) decoding is not implemented yet: hitting an enum entry
// on a reachable path aborts the walk (idl_walker_run returns -1).
//
// The value pointers in resolved leaves borrow from the instruction data buffer
// passed to idl_walker_run(); they remain valid as long as that buffer lives.

#include <stddef.h>
#include <stdint.h>

#define IDL_MATCH_PATH_MAX_SIZE 16

// One path to match during the walk (input, read-only).
// Layout is intentionally identical to cs_display_field_t so callers can cast.
typedef struct {
    uint8_t path[IDL_MATCH_PATH_MAX_SIZE];
    uint8_t path_size;
} idl_match_path_t;

// One resolved leaf value produced by the walk (output).
typedef struct {
    uint8_t kind;           // IDL kind code
    const uint8_t *value;   // raw bytes, borrowed from instruction data
    size_t value_size;
} idl_resolved_leaf_t;

// Run the walk over `data` (`data_size` bytes) against the pool currently
// loaded in the idl_pool module.
//
// INPUT:
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
                   const idl_match_path_t *match_paths,
                   uint8_t match_count,
                   idl_resolved_leaf_t *resolved,
                   uint8_t *resolved_count);
