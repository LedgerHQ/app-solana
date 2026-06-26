#pragma once

// IDL walker.
//
// Decodes the raw argument bytes of a Solana instruction against the
// kind-driven IDL type pool descriptor and collects the decoded leaf values
// into the provided collector. The pool descriptor is owned by the idl_pool
// module (provide before walking, reset after). The walker is stateless across
// calls.
//
// Enum (IDL_KIND_ENUM) decoding is not implemented yet: hitting an enum entry
// on a reachable path aborts the walk (idl_walker_run returns -1).

#include <stddef.h>
#include <stdint.h>

#include "idl_leaf_collector.h"

// Run the walk over `data` (`data_size` bytes) against the pool currently
// loaded in the idl_pool module, collecting matched leaves into `collector`.
//
// A pool must have been provided via idl_pool_provide(). `data` may be NULL
// only when `data_size` is 0. The data buffer is borrowed for the duration of
// the call only.
//
// The walk returns -1 on any descriptor/data inconsistency: a read past the
// end of the instruction data, a leftover or missing byte once the walk
// completes (cursor must land exactly on the end of the data), or an
// unsupported kind (e.g. IDL_KIND_ENUM).
//
// Returns 0 on success, -1 on invalid arguments, a missing pool, a failed
// walk, or allocator out-of-space.
int idl_walker_run(const uint8_t *data,
                   size_t data_size,
                   idl_leaf_collector_t *collector);
