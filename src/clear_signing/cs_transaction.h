#pragma once

// Session-scoped captured transaction for clear signing.
//
// Holds the serialized transaction captured by SIGN MESSAGE GENERIC PREVIEW
// (0x0A) so it survives the descriptor APDU stream, which reuses the shared
// G_command.message assembly buffer. The instruction templates streamed by
// PROVIDE INSTRUCTION INFO / SUBSTRUCTURE live in cs_instruction_template, and
// the display elements built at finalize time live in cs_merge_engine; all are
// consumed at PROMPT UI DISPLAY (0x0B) time and released together by
// cs_transaction_reset().

#include <stddef.h>
#include <stdint.h>
#include "globals.h"

typedef struct cs_transaction_s {
    uint8_t *transaction;   // heap copy of the serialized message captured at 0x0A
    size_t transaction_size;
    uint32_t derivation_path[MAX_BIP32_PATH_LENGTH];
    uint32_t derivation_path_length;
} cs_transaction_t;

// Returns the current transaction context, or NULL if no session is active.
const cs_transaction_t *cs_transaction_get(void);

// Release the captured transaction and the whole clear-signing session (instruction
// templates and merge engine) and return to the empty state. Safe when none is loaded.
void cs_transaction_reset(void);

// Reset the full CS session (transaction, templates, renderer) and return to IDLE.
void cs_session_reset(void);

// Check that the CS session is in the expected state.
// Returns the appropriate error SW on mismatch, or 0 when the state is valid.
int cs_check_state(cs_session_state_t expected);

// Reset any previous session, allocate a fresh context, and store a copy of the
// serialized transaction and derivation path. Returns 0 on success, -1 on invalid
// input or allocation failure (session left empty).
int cs_transaction_begin(const uint8_t *transaction,
                         size_t transaction_size,
                         const uint32_t *derivation_path,
                         uint32_t derivation_path_length);
