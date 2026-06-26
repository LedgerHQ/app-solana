#pragma once

// Session-scoped clear-signing context.
//
// Holds the serialized transaction captured by SIGN MESSAGE GENERIC PREVIEW
// (0x0A) so it survives the descriptor APDU stream, which reuses the shared
// G_command.message assembly buffer. The instruction templates streamed by
// PROVIDE INSTRUCTION INFO / SUBSTRUCTURE live in cs_instruction_template; both
// are consumed at PROMPT UI DISPLAY (0x0B) time and released together by
// clear_signing_context_reset().

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct clear_signing_context_s {
    uint8_t *transaction;   // heap copy of the serialized message captured at 0x0A
    size_t transaction_size;
    bool finalized;         // set by FINALIZE GENERIC CLEAR SIGNING after validation
} clear_signing_context_t;

extern clear_signing_context_t *G_clear_signing_context;

// Release the context and return to the empty state. Safe when none is loaded.
void clear_signing_context_reset(void);

// Reset any previous context, allocate a fresh one, and store a copy of the
// serialized transaction. Returns 0 on success, -1 on invalid input or
// allocation failure (context left empty).
int clear_signing_context_begin(const uint8_t *transaction, size_t transaction_size);
