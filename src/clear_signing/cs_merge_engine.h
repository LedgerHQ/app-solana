#pragma once

// Display merge engine for clear signing.
//
// Folds the captured transaction and its matched instruction templates into the
// key/value elements rendered at PROMPT UI DISPLAY (0x0B). The presence of at
// least one produced element is the session's "finalized" marker: PROMPT UI
// DISPLAY refuses to render until the engine has run.
//
// This is a shell. It currently emits a single element with hardcoded strings;
// the real engine will merge walked argument values into the template display
// fields.

#include <stddef.h>

#define CS_MAX_DISPLAY_ELEMENTS 8
#define CS_DISPLAY_TITLE_SIZE   32
#define CS_DISPLAY_VALUE_SIZE   64

// One key/value pair rendered on the review screen.
typedef struct cs_display_element_s {
    char title[CS_DISPLAY_TITLE_SIZE];
    char value[CS_DISPLAY_VALUE_SIZE];
} cs_display_element_t;

// Build the display elements for the current session. Returns 0 on success, -1
// on allocation failure (engine left empty). Discards any previous output.
int cs_merge_engine_run(void);

// Number of produced display elements. Zero means the engine has not run, which
// the session treats as "not finalized".
size_t cs_merge_engine_element_count(void);

// Fetch a produced element by index, or NULL when out of range.
const cs_display_element_t *cs_merge_engine_element(size_t index);

// Release the produced elements and return to the empty state.
void cs_merge_engine_reset(void);
