#pragma once

// Clear-signing substructure hash accumulator.
//
// An INSTRUCTION_INFO descriptor (PROVIDE INSTRUCTION INFO, 0x06) commits to the
// set of substructure TLVs that will follow it (PROVIDE INSTRUCTION SUBSTRUCTURE,
// 0x10) by carrying their SHA-256 as a single target digest. This module owns the
// running SHA-256 over the received substructure TLVs and reports when that
// running digest reaches the committed target.
//
// Templates are streamed strictly sequentially: a 0x06 opens a template, its
// 0x10 substructures fill it, then the next 0x06 opens the next. Only one
// accumulation is ever live, so a single module-global context backs all
// templates. The context is owned here; there is nothing to free.
//
// Lifecycle:
//   cs_substructure_begin()  at each 0x06, after the target digest is extracted
//   cs_substructure_update() at each 0x10, over the substructure TLV bytes
//   cs_substructure_is_complete() polled after each update to latch the template
//   cs_substructure_reset()  at session teardown

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cx.h"

// Start a fresh accumulation committed to `target_hash` (the SHA-256 the signed
// INSTRUCTION_INFO descriptor expects over its substructures). Discards any
// in-progress accumulation.
void cs_substructure_begin(const uint8_t target_hash[CX_SHA256_SIZE]);

// Fold `size` bytes of one substructure TLV into the running digest. Calling
// this without a live accumulation is a caller-sequencing breach: returns -1 and
// folds nothing rather than silently dropping the data. Returns 0 on success.
int cs_substructure_update(const uint8_t *data, size_t size);

// Compare the running digest against the committed target, writing the verdict
// to `*complete`. The running context is cloned and finalized, never consumed,
// so this may be polled repeatedly. Calling this without a live accumulation is
// a caller-sequencing breach: returns -1 and leaves `*complete` untouched.
// Returns 0 on success.
int cs_substructure_check_complete(bool *complete);

// Drop any in-progress accumulation and return to the inactive state.
void cs_substructure_reset(void);
