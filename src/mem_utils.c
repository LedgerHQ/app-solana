#include <stdint.h>
#include "app_mem_utils.h"
#include "mem_utils.h"

// The reception buffer is allocated from this pool, so it must hold a full off-chain message
// (MAX_OFFCHAIN_MESSAGE_LENGTH, ~15 KB) as a single block, on top of the per-block header and
// alignment overhead and any concurrent clear-signing allocations. 18 KB covers all of that while
// staying under the allocator's ~32 KB ceiling.
#define SIZE_MEM_BUFFER (1024 * 18)

static uint8_t mem_buffer[SIZE_MEM_BUFFER] __attribute__((aligned(sizeof(intmax_t))));

int app_mem_init(void) {
    if (mem_utils_init(mem_buffer, sizeof(mem_buffer))) {
        return 0;
    } else {
        return -1;
    }
}
