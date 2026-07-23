#include <stdint.h>
#include "app_mem_utils.h"
#include "mem_utils.h"

// Now that the reception buffer is allocated from this pool instead of a static array, the pool
// must hold a full off-chain message (MAX_OFFCHAIN_MESSAGE_LENGTH). The allocator rounds a request
// up to its power-of-two size class, so a ~15 KB block needs the 16384-byte segment to exist, which
// requires (pool - heap header) >= 16384. 18 KB satisfies that and leaves clear-signing headroom.
#define SIZE_MEM_BUFFER (1024 * 18)

static uint8_t mem_buffer[SIZE_MEM_BUFFER] __attribute__((aligned(sizeof(intmax_t))));

int app_mem_init(void) {
    if (mem_utils_init(mem_buffer, sizeof(mem_buffer))) {
        return 0;
    } else {
        return -1;
    }
}
