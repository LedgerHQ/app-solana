#pragma once

// Display merge engine for clear signing.
//
// Receives the per-instruction resolved leaf values produced by walking the
// transaction and decides which display elements to emit. The presence of at
// least one produced element is the session's "finalized" marker: PROMPT UI
// DISPLAY refuses to render until the engine has run.

#include <stddef.h>
#include <stdint.h>

#include "idl_leaf_collector.h"
#include "cs_instruction_template.h"

#define CS_MAX_DISPLAY_ELEMENTS 8
#define CS_DISPLAY_TITLE_SIZE   32
#define CS_DISPLAY_VALUE_SIZE   64

// One key/value pair rendered on the review screen.
typedef struct cs_display_element_s {
    char title[CS_DISPLAY_TITLE_SIZE];
    char value[CS_DISPLAY_VALUE_SIZE];
} cs_display_element_t;

// Per-instruction walk result: the template that matched and the collected
// display-field leaf values resolved during the walk.
typedef struct cs_instruction_result_s {
    const cs_instruction_template_t *template;
    idl_leaf_collector_t collected;
} cs_instruction_result_t;

// Build the display elements from instruction results. Returns 0 on success,
// -1 on failure (engine left empty). Discards any previous output.
int cs_merge_engine_run(const cs_instruction_result_t *results, size_t result_count);

// Number of produced display elements. Zero means the engine has not run, which
// the session treats as "not finalized".
size_t cs_merge_engine_element_count(void);

// Fetch a produced element by index, or NULL when out of range.
const cs_display_element_t *cs_merge_engine_element(size_t index);

// Release the produced elements and return to the empty state.
void cs_merge_engine_reset(void);
