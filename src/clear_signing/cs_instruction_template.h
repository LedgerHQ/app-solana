#pragma once

// Instruction template table for clear signing.
//
// Owns the signed INSTRUCTION_INFO templates streamed by PROVIDE INSTRUCTION
// INFO (0x06) / SUBSTRUCTURE (0x10) and consumed at PROMPT UI DISPLAY (0x0B).
//
// A template is assembled in two phases. PROVIDE INSTRUCTION INFO opens a single
// in-flight builder and fills its committed fields (program_id, discriminator,
// IDL pool). PROVIDE INSTRUCTION SUBSTRUCTURE then streams the substructures,
// folding them into the substructure hash accumulator and appending display
// paths to the builder. Only once the accumulated hash matches the descriptor's
// committed target is the builder copied into the committed array. Templates in
// that array are therefore always whole and walker-ready; an in-flight builder
// that never completes is never visible to PROMPT UI DISPLAY.
//
// The table lives on the heap (allocated on first open, released on reset) and
// is session-scoped, mirroring cs_transaction_t.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Fixed capacities. Inputs exceeding these fail closed rather than truncate.
#define CS_MAX_INSTRUCTION_TEMPLATES 4
#define CS_MAX_IDL_TYPE_POOL_SIZE    512
#define CS_MAX_DISCRIMINATOR_SIZE    8
#define CS_MAX_DISPLAY_FIELDS        8
#define CS_MAX_ARGUMENT_PATH_SIZE    16

// One displayed field's argument path, in the packed
// `u8 step_count || packed steps` encoding emitted by the IDL walker. Only
// fields sourced from an ARGUMENT_PATH are stored here; ACCOUNT_PATH / CONSTANT
// sources carry no walker path and are not recorded.
typedef struct cs_display_field_s {
    uint8_t path[CS_MAX_ARGUMENT_PATH_SIZE];
    uint8_t path_size;
} cs_display_field_t;

// One complete instruction template, keyed by (program_id, discriminator).
// Only ever exposed once fully assembled, so every field is valid.
typedef struct cs_instruction_template_s {
    uint8_t program_id[32];
    uint8_t discriminator[CS_MAX_DISCRIMINATOR_SIZE];
    uint8_t discriminator_size;
    uint8_t idl_type_pool[CS_MAX_IDL_TYPE_POOL_SIZE];
    size_t idl_type_pool_size;
    uint8_t idl_root_type;
    cs_display_field_t display_fields[CS_MAX_DISPLAY_FIELDS];
    uint8_t display_field_count;
} cs_instruction_template_t;

// Open a fresh in-flight builder committed to `target_hash` (the SHA-256 the
// signed INSTRUCTION_INFO descriptor expects over its substructures) and start
// the matching substructure hash accumulation. Returns the zeroed builder for
// the caller to fill, or NULL when the committed array is already full or the
// table cannot be allocated. Discards any previous unfinished builder.
cs_instruction_template_t *cs_instruction_template_open(
    const uint8_t target_hash[32]);

// The in-flight builder being assembled, or NULL when none is open.
cs_instruction_template_t *cs_instruction_template_current(void);

// Append one argument path to the in-flight builder's display-field list.
// Returns 0 on success, -1 when no builder is open, the path is too long, or
// the slot is full.
int cs_instruction_template_add_display_path(const uint8_t *path, size_t path_size);

// Promote the in-flight builder into the committed array. Must be called only
// once the substructure accumulation has matched the committed target. Returns 0
// on success, -1 when no builder is open or the array is full.
int cs_instruction_template_commit(void);

// Number of committed (whole, walker-ready) templates.
uint8_t cs_instruction_template_committed_count(void);

// True while a builder is open but not yet committed.
bool cs_instruction_template_pending(void);

// Find the committed template whose program_id matches and whose discriminator
// is a prefix of `data`. Returns NULL when none matches.
const cs_instruction_template_t *cs_instruction_template_find(
    const uint8_t program_id[32],
    const uint8_t *data,
    size_t data_size);

// Release the table and the substructure accumulator, returning to the empty
// state. Safe when no table is allocated.
void cs_instruction_template_table_reset(void);
