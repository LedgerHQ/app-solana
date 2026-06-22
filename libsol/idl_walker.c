// IDL walker (scaffolding). See idl_walker.h for the contract.
//
// Only the plumbing around the future walk is implemented here: forwarding the
// IDL type pool descriptor in, forwarding the instruction data in, and
// forwarding produced leaves out. The leaves are mock content because the
// kind-driven type-tree walk (and enum-variant handling) is not implemented
// yet.
//
// Inputs are borrowed, never copied: the caller keeps the pool and instruction
// data buffers alive until idl_walker_reset(). Only the output leaves are
// dynamically allocated, so the only size-driven failure path is the allocator
// returning NULL (out of space).

#include <string.h>

#include "idl_walker.h"
#include "util.h"
#include "app_mem_utils.h"

// Number of leading instruction-data bytes exposed through a mock leaf value.
#define MOCK_LEAF_VALUE_MAX 4

static void free_leaves(idl_walker_t *walker) {
    if (walker->leaves != NULL) {
        for (size_t i = 0; i < walker->leaf_count; i++) {
            // `value` is borrowed (points into the instruction data); only the
            // synthesized `path` is owned.
            APP_MEM_FREE(walker->leaves[i].path);
        }
        APP_MEM_FREE(walker->leaves);
        walker->leaves = NULL;
    }
    walker->leaf_count = 0;
}

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
// bytes, borrowed). Replaces this with the real kind-driven walk later.
static int produce_mock_leaves(idl_walker_t *walker) {
    idl_leaf_t *leaves = APP_MEM_ALLOC(sizeof(idl_leaf_t));
    if (leaves == NULL) {
        PRINTF("idl_walker: leaf array allocation failed\n");
        return -1;
    }
    memset(leaves, 0, sizeof(idl_leaf_t));

    // path = { step_count = 1, single u8 step value = root_index }
    leaves[0].path = APP_MEM_ALLOC(2);
    if (leaves[0].path == NULL) {
        PRINTF("idl_walker: leaf path allocation failed\n");
        APP_MEM_FREE(leaves);
        return -1;
    }
    leaves[0].path[0] = 0x01;
    leaves[0].path[1] = walker->root_index;
    leaves[0].path_size = 2;

    size_t value_size = walker->data_size;
    if (value_size > MOCK_LEAF_VALUE_MAX) {
        value_size = MOCK_LEAF_VALUE_MAX;
    }
    if (value_size > 0) {
        // Borrow into the instruction data; no copy.
        leaves[0].value = walker->data;
        leaves[0].value_size = value_size;
    }

    walker->leaves = leaves;
    walker->leaf_count = 1;
    return 0;
}

int idl_walker_run(idl_walker_t *walker) {
    if (walker == NULL) {
        return -1;
    }
    if (!walker->pool_ready || !walker->data_ready) {
        PRINTF("idl_walker_run: missing inputs (pool_ready=%d, data_ready=%d)\n",
               walker->pool_ready,
               walker->data_ready);
        return -1;
    }

    // Drop any output from a previous run before producing a new one.
    free_leaves(walker);

    if (produce_mock_leaves(walker) != 0) {
        return -1;
    }

    // Forward the produced leaves to the consumer (printed for now).
    for (size_t i = 0; i < walker->leaf_count; i++) {
        PRINTF("idl_walker: leaf %d path=%.*H value=%.*H\n",
               i,
               walker->leaves[i].path_size,
               walker->leaves[i].path,
               walker->leaves[i].value_size,
               walker->leaves[i].value);
    }
    return 0;
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

    free_leaves(walker);
}
