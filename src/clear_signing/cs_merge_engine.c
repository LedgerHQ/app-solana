#include <os.h>
#include <string.h>

#include "cs_merge_engine.h"

static bool G_cs_merge_engine_finalized = false;

void cs_merge_engine_reset(void) {
    G_cs_merge_engine_finalized = false;
}

int cs_merge_engine_run(const cs_instruction_result_t *walked_instructions,
                        size_t walked_instructions_count) {
    // MVP: all instructions survive — no value-flow port matching or hide-rule
    // evaluation yet. We just validate the input and mark finalized.
    if (walked_instructions == NULL && walked_instructions_count > 0) {
        PRINTF("cs_merge_engine_run: NULL input with non-zero count\n");
        return -1;
    }

    PRINTF("cs_merge_engine_run: %d instructions, all survive (MVP)\n",
           (int) walked_instructions_count);
    G_cs_merge_engine_finalized = true;
    return 0;
}

bool cs_merge_engine_finalized(void) {
    return G_cs_merge_engine_finalized;
}
