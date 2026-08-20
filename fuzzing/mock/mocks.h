#pragma once

#include "cx_errors.h"
#include "ox_ec.h"
#include "os_task.h"
#include <string.h>
#include <setjmp.h>
#include "exceptions.h"
#include <stdio.h>
#include <stdint.h>

#include "fuzz_defs.h"

/* Installs the restored contents of the heap-held state and the NVRAM settings.
 * Call from fuzz_app_reset() after app_mem_init(). */
void fuzz_install_restored_state(void);

/* Typed mirror of the Solana message layout. Absolution models G_command.message
 * as a flat uint8_t[] with one domain shared by every element, which cannot say
 * "this byte is a count and those 32 are a key". The struct exists only to give
 * the invariant per-field granularity, so a mutation at a given offset always
 * means the same field.
 *
 * It carries no domain overrides: every field is attacker-supplied and nothing is
 * derived from anything else, so a length may disagree with what follows it and an
 * index may exceed the count that bounds it. Those disagreements are what the app's
 * checks exist to catch.
 *
 * No version byte: parse_version() consumes one only when the first byte has 0x80
 * set, so num_required_signatures doubles as the marker and both legacy and
 * versioned messages stay reachable. */
#define FUZZ_MSG_PUBKEYS  4
#define FUZZ_MSG_IX       3
#define FUZZ_MSG_ACCOUNTS 8
#define FUZZ_MSG_DATA     64

typedef struct {
    uint8_t program_id_index;
    uint8_t accounts_len;
    uint8_t accounts[FUZZ_MSG_ACCOUNTS];
    uint8_t data_len;
    uint8_t data[FUZZ_MSG_DATA];
} fuzz_msg_ix_t;

typedef struct {
    uint8_t num_required_signatures;
    uint8_t num_readonly_signed;
    uint8_t num_readonly_unsigned;
    uint8_t pubkeys_len;
    uint8_t pubkeys[FUZZ_MSG_PUBKEYS][32];
    uint8_t blockhash[32];
    uint8_t instructions_len;
    fuzz_msg_ix_t ix[FUZZ_MSG_IX];
} fuzz_msg_t;

extern fuzz_msg_t fuzz_backing_msg;
