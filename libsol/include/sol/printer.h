#pragma once

#include "sol/parser.h"
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
