#pragma once

#include "sol/parser.h"

// Raw transaction view.
//
// When a transaction cannot be clear-signed and blind signing is enabled, this
// module lets the UI enumerate the raw deserialized message instead of only
// showing a hash. It produces a flat, on-demand list of (title, value) pairs:
//
//   "Message Hash"      -> <base58 sha256 of the signed message>
//   "Fee payer"         -> <base58 of account 0>
//   "Instructions"      -> <count>
//   "Ix N program"      -> <base58 program id>
//   "Ix N account J/K"  -> <base58 account> (signer, writable)
//   "Ix N data C/T"     -> <hex chunk of instruction data>
//
// Signer/writable flags are derived positionally from the header (read-only
// accounts get no flag); lookup-table accounts (absent from the message) render
// as "lookup table account #N".

// Minimum size of the value buffer that raw_message_render_pair writes into.
// Large enough for a base58 pubkey plus its " (signer, writable)" suffix and
// for one hex data chunk (64 bytes -> 128 hex chars + NUL).
#define RAW_MESSAGE_VALUE_BUF_SIZE 160

// Set up the raw view over a message body. The pointers must stay valid until
// the review completes (they point into the persistent G_command buffer). When
// `short_pubkeys` is set, pubkeys are truncated like the normal review screens.
// Writes the pair count to `*out_pairs`; returns non-zero if the message is
// empty, malformed, or too large to enumerate (the caller then falls back to
// hash-only).
int raw_message_init(const uint8_t *body,
                     size_t body_length,
                     const MessageHeader *header,
                     const Hash *message_hash,
                     bool short_pubkeys,
                     size_t *out_pairs);

// Render display pair `index` (< the count returned by raw_message_init) into
// the caller-provided `title` and `value` buffers (both NUL-terminated on
// success). `value_len` must be at least RAW_MESSAGE_VALUE_BUF_SIZE. Returns 0
// on success, non-zero if `index` is out of range or rendering failed.
int raw_message_render_pair(size_t index,
                            char *title,
                            size_t title_len,
                            char *value,
                            size_t value_len);

// True if display pair `index` is the first pair of an instruction (other than
// the first instruction), so the review can start it on a new page
// (forcePageStart): the leading pairs (hash, fee payer, count) pack with
// instruction 1, and instructions 2+ each begin on a fresh page, keeping pages
// aligned to instruction boundaries.
bool raw_message_starts_instruction(size_t index);
