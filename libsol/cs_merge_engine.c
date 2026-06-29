#include <string.h>

#include "cs_merge_engine.h"
#include "os_print.h"

int cs_merge_engine_run(const cs_instruction_result_t *walked_instructions,
                        size_t walked_instructions_count,
                        bool *survivors) {
    if (walked_instructions == NULL && walked_instructions_count > 0) {
        PRINTF("cs_merge_engine_run: NULL input with non-zero count\n");
        return -1;
    }
    if (survivors == NULL && walked_instructions_count > 0) {
        PRINTF("cs_merge_engine_run: NULL survivors output\n");
        return -1;
    }

    // MVP: all instructions survive — no value-flow port matching or hide-rule
    // evaluation yet.
    for (size_t i = 0; i < walked_instructions_count; i++) {
        survivors[i] = true;
    }

    PRINTF("cs_merge_engine_run: %d instructions, all survive (MVP)\n",
           (int) walked_instructions_count);
    return 0;
}
