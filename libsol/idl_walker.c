// IDL walker (scaffolding). See idl_walker.h for the contract.
//
// Only the plumbing around the future walk is implemented here: forwarding the
// IDL type pool descriptor in, forwarding the instruction data in, and
// streaming produced leaves out through a per-leaf callback. The leaves are
// mock content because the kind-driven type-tree walk (and enum-variant
// handling) is not implemented yet.
//
// Inputs are borrowed, never copied: the caller keeps the pool and instruction
// data buffers alive until idl_walker_reset(). Leaves are streamed one at a
// time and never retained, so the only size-driven failure path is the
// allocator returning NULL (out of space) for a leaf's scratch path.

#include <string.h>

#include "idl_walker.h"
#include "util.h"
#include "app_mem_utils.h"

// Number of leading instruction-data bytes exposed through a mock leaf value.
#define MOCK_LEAF_VALUE_MAX 4

void idl_walker_init(idl_walker_t *walker) {
    if (walker == NULL) {
        return;
    }
    memset(walker, 0, sizeof(*walker));
}

int idl_walker_provide_pool(idl_walker_t *walker,
                            const uint8_t *pool,
                            size_t pool_size,
                            uint8_t root_index) {
    if (walker == NULL) {
        return -1;
    }
    if (pool == NULL && pool_size > 0) {
        PRINTF("idl_walker_provide_pool: NULL pool with non-zero size\n");
        return -1;
    }

    // Borrow the caller's buffer; it must outlive the walk (until reset).
    walker->pool = pool;
    walker->pool_size = pool_size;
    walker->root_index = root_index;
    walker->pool_ready = true;

    PRINTF("idl_walker: received IDL type pool (size=%d, root_index=%d)\n",
           walker->pool_size,
           walker->root_index);
    return 0;
}

int idl_walker_provide_instruction_data(idl_walker_t *walker,
                                        const uint8_t *data,
                                        size_t data_size) {
    if (walker == NULL) {
        return -1;
    }
    if (data == NULL && data_size > 0) {
        PRINTF("idl_walker_provide_instruction_data: NULL data with non-zero size\n");
        return -1;
    }

    // Borrow the caller's buffer; it must outlive the walk (until reset).
    walker->data = data;
    walker->data_size = data_size;
    walker->data_ready = true;

    PRINTF("idl_walker: received instruction data (size=%d)\n", walker->data_size);
    return 0;
}

// SCAFFOLDING: emit one deterministic mock leaf derived from the forwarded
// inputs (path = single step to root_index, value = leading instruction-data
// bytes, borrowed) through `cb`. Replaced with the real kind-driven walk
// later. The scratch path is reclaimed before returning, so nothing outlives
// the callback. Returns 0 on success, -1 on out-of-space.
static int emit_mock_leaves(idl_walker_t *walker, idl_leaf_cb_t cb, void *ctx) {
    // path = { step_count = 1, single u8 step value = root_index }
    uint8_t *path = APP_MEM_ALLOC(2);
    if (path == NULL) {
        PRINTF("idl_walker: leaf path allocation failed\n");
        return -1;
    }
    path[0] = 0x01;
    path[1] = walker->root_index;

    size_t value_size = walker->data_size;
    if (value_size > MOCK_LEAF_VALUE_MAX) {
        value_size = MOCK_LEAF_VALUE_MAX;
    }

    idl_leaf_t leaf = {
        .path = path,
        .path_size = 2,
        // Borrow into the instruction data; no copy. NULL when data is empty.
        .value = (value_size > 0) ? walker->data : NULL,
        .value_size = value_size,
    };

    PRINTF("idl_walker: leaf path=%.*H value=%.*H\n",
           leaf.path_size,
           leaf.path,
           leaf.value_size,
           leaf.value);
    if (cb != NULL) {
        cb(&leaf, ctx);
    }

    APP_MEM_FREE(path);
    return 0;
}

int idl_walker_run(idl_walker_t *walker, idl_leaf_cb_t cb, void *ctx) {
    if (walker == NULL) {
        return -1;
    }
    if (!walker->pool_ready || !walker->data_ready) {
        PRINTF("idl_walker_run: missing inputs (pool_ready=%d, data_ready=%d)\n",
               walker->pool_ready,
               walker->data_ready);
        return -1;
    }

    return emit_mock_leaves(walker, cb, ctx);
}

void idl_walker_reset(idl_walker_t *walker) {
    if (walker == NULL) {
        return;
    }
    // pool and data are borrowed; just drop the references, never free them.
    walker->pool = NULL;
    walker->pool_size = 0;
    walker->root_index = 0;
    walker->pool_ready = false;

    walker->data = NULL;
    walker->data_size = 0;
    walker->data_ready = false;
}
