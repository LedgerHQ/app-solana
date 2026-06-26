#pragma once

// Display renderer for clear signing.
//
// Receives survived instruction results (post-merge) and formats each resolved
// leaf into a human-readable title/value pair for the NBGL review screen.
// The presence of at least one element is the session's "finalized" marker.

#include <stddef.h>
#include <stdint.h>

#include "cs_merge_engine.h"

#define CS_MAX_DISPLAY_ELEMENTS 8
#define CS_DISPLAY_TITLE_SIZE   32
#define CS_DISPLAY_VALUE_SIZE   64

// One key/value pair rendered on the review screen.
typedef struct cs_display_element_s {
    char title[CS_DISPLAY_TITLE_SIZE];
    char value[CS_DISPLAY_VALUE_SIZE];
} cs_display_element_t;

// Format all resolved leaves from survived instructions into display elements.
// Returns 0 on success, -1 on failure. Discards any previous output.
int cs_display_renderer_run(const cs_instruction_result_t *walked_instructions,
                            size_t walked_instructions_count);

// Number of produced display elements. Zero means not yet rendered.
size_t cs_display_renderer_element_count(void);

// Fetch a produced element by index, or NULL when out of range.
const cs_display_element_t *cs_display_renderer_element(size_t index);

// Release produced elements and return to empty state.
void cs_display_renderer_reset(void);
