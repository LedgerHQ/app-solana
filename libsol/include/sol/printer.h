#pragma once

#include "sol/parser.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define SUMMARY_LENGTH       7
#define TITLE_SIZE           32
#define BASE58_PUBKEY_LENGTH 45
#define BASE58_PUBKEY_SHORT  (SUMMARY_LENGTH + 2 + SUMMARY_LENGTH + 1)
#define SIGNATURE_LENGTH     64
#define HASH_LENGTH          32
#define PUBKEY_LENGTH        HASH_LENGTH
#define PRIVATEKEY_LENGTH    HASH_LENGTH

int print_token_amount(uint64_t amount,
                       const char *asset,
                       uint8_t decimals,
                       char *out,
                       size_t out_length);

int print_amount(uint64_t amount, char *out, size_t out_length);

int print_i64(int64_t i64, char *out, size_t out_length);

int print_u64(uint64_t u64, char *out, size_t out_length);

int print_sized_string(const SizedString *string, char *out, size_t out_length);

int print_string(const char *in, char *out, size_t out_length);

int print_summary(const char *in,
                  char *out,
                  size_t out_length,
                  size_t left_length,
                  size_t right_length);

int print_timestamp(int64_t, char *out, size_t out_length);

int encode_base58(const void *in, size_t length, char *out, size_t maxoutlen);

// Encode a byte buffer as an uppercase hex string; returns the number of bytes
// written (including the NUL) on success, -1 otherwise. Copied verbatim from the
// SDK's format_hex so libsol stays self-contained:
// https://github.com/LedgerHQ/ledger-secure-sdk/blob/3ff3ddcbd4506cfdf97ec36fdb72f9914107b1e7/lib_standard_app/format.c#L156
int encode_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len);

bool amount_as_string_is_greater_or_equal(const char *a, const char *b);
