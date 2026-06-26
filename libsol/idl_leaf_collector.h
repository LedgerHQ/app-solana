#pragma once

// IDL leaf collector — data types for the walker's path-matching output.
//
// The caller loads match_paths (from display fields), passes the struct to
// idl_walker_run(), and after the walk reads out resolved[] for leaves that
// matched. Leaves whose path did not match any slot are silently discarded.
//
// The value pointers in resolved[] borrow from the instruction data buffer
// passed to idl_walker_run(); they remain valid as long as that buffer lives.

#include <stddef.h>
#include <stdint.h>

#define IDL_LEAF_COLLECTOR_MAX_FIELDS 8
#define IDL_LEAF_COLLECTOR_MAX_PATH   16

// One resolved leaf value after a successful path match.
typedef struct {
    uint8_t kind;           // IDL kind code (required to interpret value)
    const uint8_t *value;   // raw bytes, borrowed from instruction data
    size_t value_size;
} idl_resolved_leaf_t;

// Walker input/output: paths to match (set before walk) and resolved values
// (filled during walk, one slot per match_path entry).
typedef struct {
    struct {
        uint8_t data[IDL_LEAF_COLLECTOR_MAX_PATH];
        uint8_t size;
    } match_paths[IDL_LEAF_COLLECTOR_MAX_FIELDS];
    uint8_t match_count;

    idl_resolved_leaf_t resolved[IDL_LEAF_COLLECTOR_MAX_FIELDS];
    uint8_t resolved_count;
} idl_leaf_collector_t;
