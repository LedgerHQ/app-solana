// IDL walker (scaffolding). See idl_walker.h for the contract.
//
// Only the plumbing around the future walk is implemented here: forwarding the
// IDL type pool descriptor in, forwarding the instruction data in, and
// forwarding produced leaves out. The leaves are mock content because the
// kind-driven type-tree walk (and enum-variant handling) is not implemented
// yet.
//
// Every variable-size buffer is dynamically allocated, so the only size-driven
// failure path is the allocator returning NULL (out of space).

#include <string.h>

#include "idl_walker.h"
#include "util.h"
#include "app_mem_utils.h"

// Number of leading instruction-data bytes echoed into a mock leaf value.
#define MOCK_LEAF_VALUE_MAX 4

static void free_leaves(idl_walker_t *walker) {
    if (walker->leaves != NULL) {
        for (size_t i = 0; i < walker->leaf_count; i++) {
            APP_MEM_FREE(walker->leaves[i].path);
            APP_MEM_FREE(walker->leaves[i].value);
        }
        APP_MEM_FREE(walker->leaves);
        walker->leaves = NULL;
    }
    walker->leaf_count = 0;
}

// Copy `size` bytes from `src` into a freshly owned buffer at `*dst`, replacing
// (and freeing) any previous content. A zero-length input leaves `*dst` NULL.
// Returns 0 on success, -1 on out-of-space.
static int copy_into(uint8_t **dst, size_t *dst_size, const uint8_t *src, size_t size) {
    APP_MEM_FREE_AND_NULL((void **) dst);
    *dst_size = 0;
    if (size == 0) {
        return 0;
    }
    uint8_t *buf = APP_MEM_ALLOC(size);
    if (buf == NULL) {
        PRINTF("idl_walker: allocation of %d bytes failed\n", size);
        return -1;
    }
    memcpy(buf, src, size);
    *dst = buf;
    *dst_size = size;
    return 0;
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

    walker->pool_ready = false;
    if (copy_into(&walker->pool, &walker->pool_size, pool, pool_size) != 0) {
        return -1;
    }
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

    walker->data_ready = false;
    if (copy_into(&walker->data, &walker->data_size, data, data_size) != 0) {
        return -1;
    }
    walker->data_ready = true;

    PRINTF("idl_walker: received instruction data (size=%d)\n", walker->data_size);
    return 0;
}

// SCAFFOLDING: emit one deterministic mock leaf derived from the forwarded
// inputs (path = single step to root_index, value = leading instruction-data
// bytes). Replaces this with the real kind-driven walk later.
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
        leaves[0].value = APP_MEM_ALLOC(value_size);
        if (leaves[0].value == NULL) {
            PRINTF("idl_walker: leaf value allocation failed\n");
            APP_MEM_FREE(leaves[0].path);
            APP_MEM_FREE(leaves);
            return -1;
        }
        memcpy(leaves[0].value, walker->data, value_size);
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
    APP_MEM_FREE_AND_NULL((void **) &walker->pool);
    walker->pool_size = 0;
    walker->root_index = 0;
    walker->pool_ready = false;

    APP_MEM_FREE_AND_NULL((void **) &walker->data);
    walker->data_size = 0;
    walker->data_ready = false;

    free_leaves(walker);
}
