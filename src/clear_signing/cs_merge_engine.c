#include <os.h>
#include <string.h>

#include "cs_merge_engine.h"
#include "app_mem_utils.h"

typedef struct cs_merge_engine_s {
    cs_display_element_t elements[CS_MAX_DISPLAY_ELEMENTS];
    uint8_t element_count;
} cs_merge_engine_t;

static cs_merge_engine_t *G_cs_merge_engine = NULL;

void cs_merge_engine_reset(void) {
    if (G_cs_merge_engine != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &G_cs_merge_engine);
    }
}

int cs_merge_engine_run(const cs_instruction_result_t *walked_instructions,
                       size_t walked_instructions_count) {
    cs_merge_engine_reset();

    if (!APP_MEM_CALLOC((void **) &G_cs_merge_engine, sizeof(cs_merge_engine_t))) {
        PRINTF("cs_merge_engine_run: allocation failed\n");
        return -1;
    }

    (void) walked_instructions;
    (void) walked_instructions_count;

    cs_display_element_t *element = &G_cs_merge_engine->elements[0];
    strlcpy(element->title, "Transaction", sizeof(element->title));
    strlcpy(element->value, "Generic clear signing", sizeof(element->value));
    G_cs_merge_engine->element_count = 1;
    return 0;
}

size_t cs_merge_engine_element_count(void) {
    if (G_cs_merge_engine == NULL) {
        return 0;
    }
    return G_cs_merge_engine->element_count;
}

const cs_display_element_t *cs_merge_engine_element(size_t index) {
    if (G_cs_merge_engine == NULL) {
        PRINTF("cs_merge_engine_element: engine not run\n");
        return NULL;
    }
    if (index >= G_cs_merge_engine->element_count) {
        PRINTF("cs_merge_engine_element: index %u out of range\n", index);
        return NULL;
    }
    return &G_cs_merge_engine->elements[index];
}
