#include <stdint.h>
#include "app_mem_utils.h"
#include "mem_utils.h"

#define SIZE_MEM_BUFFER (1024 * 4)

static uint8_t mem_buffer[SIZE_MEM_BUFFER] __attribute__((aligned(sizeof(intmax_t))));

int app_mem_init(void) {
    if (mem_utils_init(mem_buffer, sizeof(mem_buffer))) {
        return 0;
    } else {
        return -1;
    }
}
