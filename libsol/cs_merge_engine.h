#pragma once

// Merge engine for clear signing.
//
// Receives the per-instruction resolved leaf values and decides which
// instructions survive (MVP: all survive). Value-flow port matching and
// hide-rule evaluation will be added here later.
//
// Output is a caller-provided bool array: survivors[i] == true means
// walked_instructions[i] should be rendered.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "idl_walker.h"
#include "cs_instruction_template.h"

// Per-instruction walk result: the template that matched and the resolved
// display-field leaf values.
typedef struct cs_instruction_result_s {
    const cs_instruction_template_t *template;
    idl_resolved_leaf_t *resolved;  // heap, sized to resolved_count; owned by the finalize walk
    size_t resolved_count;
    // Per display-field resolved mint pubkey, heap array sized to resolved_count,
    // indexed like `resolved`. Non-NULL entry only for TOKEN_AMOUNT fields whose
    // TOKEN reference resolved to a mint.
    const uint8_t **field_mint;
} cs_instruction_result_t;

// Run the merge engine on walked instructions. Fills survivors[i] = true for
// each instruction that should be displayed. Returns 0 on success, -1 on failure.
int cs_merge_engine_run(const cs_instruction_result_t *walked_instructions,
                        size_t walked_instructions_count,
                        bool *survivors);
