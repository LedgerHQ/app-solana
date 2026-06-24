#pragma once

// Session-scoped clear-signing context.
//
// Bridges the three clear-signing actors across the APDU stream:
//   - the serialized transaction captured by SIGN MESSAGE GENERIC PREVIEW (0x0A),
//   - the signed INSTRUCTION_INFO templates and their DISPLAY_FIELD argument
//     paths streamed by the PROVIDE INSTRUCTION INFO / SUBSTRUCTURE APDUs,
//   - consumed at PROMPT UI DISPLAY (0x0B) time, where the IDL walker decodes
//     each transaction instruction against the matching template.
//
// The descriptor APDUs reuse the shared G_command.message assembly buffer, so
// the serialized transaction is copied here at 0x0A time before that buffer is
// overwritten by the descriptor stream. The whole context lives on the heap and
// is released by clear_signing_context_reset().

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cx.h"

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

// One instruction template, keyed by (program_id, discriminator).
typedef struct cs_instruction_template_s {
    uint8_t program_id[32];
    uint8_t discriminator[CS_MAX_DISCRIMINATOR_SIZE];
    uint8_t discriminator_size;
    uint8_t idl_type_pool[CS_MAX_IDL_TYPE_POOL_SIZE];
    size_t idl_type_pool_size;
    uint8_t idl_root_type;
    uint8_t substructures_hash[32];   // target hash from the signed INSTRUCTION_INFO
    cx_sha256_t substructures_ctx;    // running accumulator over received substructures
    cs_display_field_t display_fields[CS_MAX_DISPLAY_FIELDS];
    uint8_t display_field_count;
    bool complete;                    // running hash has matched substructures_hash
} cs_instruction_template_t;

typedef struct clear_signing_context_s {
    uint8_t *transaction;   // heap copy of the serialized message captured at 0x0A
    size_t transaction_size;
    cs_instruction_template_t templates[CS_MAX_INSTRUCTION_TEMPLATES];
    uint8_t template_count;
} clear_signing_context_t;

extern clear_signing_context_t *G_clear_signing_context;

// Release the context and return to the empty state. Safe when none is loaded.
void clear_signing_context_reset(void);

// Reset any previous context, allocate a fresh one, and store a copy of the
// serialized transaction. Returns 0 on success, -1 on invalid input or
// allocation failure (context left empty).
int clear_signing_context_begin(const uint8_t *transaction, size_t transaction_size);

// Open and zero a new template slot, returning it. Returns NULL when no context
// is active or all slots are used.
cs_instruction_template_t *clear_signing_context_new_template(void);

// The most recently opened template (the substructure stream target), or NULL.
cs_instruction_template_t *clear_signing_context_current_template(void);

// Append one argument path to the current template's display-field list.
// Returns 0 on success, -1 when no template is active, the path is too long, or
// the slot is full.
int clear_signing_context_add_display_path(const uint8_t *path, size_t path_size);

// Find the template whose program_id matches and whose discriminator is a prefix
// of `data`. Returns NULL when none matches.
const cs_instruction_template_t *clear_signing_context_find_template(
    const uint8_t program_id[32],
    const uint8_t *data,
    size_t data_size);
