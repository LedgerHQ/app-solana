#pragma once

// Display renderer for clear signing.
//
// Receives survived instruction results (post-merge) and formats each resolved
// leaf into a structured representation: a list of instruction groups each
// holding key/value fields, plus optional transaction-level fields (fees).
// The NBGL flat-index callback is computed on the fly from this structure.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cs_merge_engine.h"

// One rendered key/value pair on the review screen. Heap-allocated, freed on reset.
typedef struct cs_rendered_field_s {
    char *title;
    char *value;
} cs_rendered_field_t;

// One instruction group: intent, optional program, and rendered fields.
typedef struct cs_display_instruction_s {
    char *intent;
    char *program;  // NULL for native programs
    cs_rendered_field_t *fields;
    size_t field_count;
    size_t field_capacity;
} cs_display_instruction_t;

// Transaction-level trailing fields (fees, etc).
typedef struct cs_display_transaction_fields_s {
    cs_rendered_field_t *fields;
    size_t field_count;
    size_t field_capacity;
} cs_display_transaction_fields_t;

// Flat element returned by the NBGL translation layer.
typedef struct cs_display_flat_element_s {
    const char *title;
    const char *value;
    bool centered_info;
    bool force_page_start;
} cs_display_flat_element_t;

// Format all resolved leaves from survived instructions into instruction groups.
// Only instructions where survivors[i] == true are rendered.
// Returns 0 on success, -1 on failure.
int cs_display_renderer_run(const cs_instruction_result_t *walked_instructions,
                            size_t walked_instructions_count,
                            const bool *survivors);

// Append a transaction-level field (fees, etc) after all instruction groups.
int cs_display_renderer_append_transaction_field(const char *title, const char *value);

// Number of instruction groups rendered.
size_t cs_display_renderer_instruction_count(void);

// Fetch an instruction group by index, or NULL when out of range.
const cs_display_instruction_t *cs_display_renderer_instruction(size_t index);

// Access the transaction-level trailing fields.
const cs_display_transaction_fields_t *cs_display_renderer_transaction_fields(void);

// Total flat element count for the NBGL callback (separators + fields).
size_t cs_display_renderer_flat_count(void);

// Translate a flat NBGL index into a display element with layout flags.
// Returns 0 on success, -1 when index is out of range.
int cs_display_renderer_flat_element(size_t index, cs_display_flat_element_t *out);

// Release all produced data and return to empty state.
void cs_display_renderer_reset(void);
