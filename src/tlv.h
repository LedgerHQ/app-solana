#pragma once

#include <cx.h>
#include <os.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

// List of TLV tags recognized by the Solana application
#define TLV_TAGS                 \
    X(STRUCT_TYPE, 0x01)         \
    X(STRUCT_VERSION, 0x02)      \
    X(TRUSTED_NAME_TYPE, 0x70)   \
    X(TRUSTED_NAME_SOURCE, 0x71) \
    X(TRUSTED_NAME_NFT_ID, 0x72) \
    X(TRUSTED_NAME, 0x20)        \
    X(CHAIN_ID, 0x23)            \
    X(ADDRESS, 0x22)             \
    X(SOURCE_CONTRACT, 0x73)     \
    X(CHALLENGE, 0x12)           \
    X(NOT_VALID_AFTER, 0x10)     \
    X(SIGNER_KEY_ID, 0x13)       \
    X(SIGNER_ALGO, 0x14)         \
    X(SIGNATURE, 0x15)

// Parsed TLV data
typedef struct tlv_out_s {
    uint8_t struct_type;
    uint8_t struct_version;
    buffer_t encoded_token_address;
    buffer_t encoded_owner_address;
    buffer_t encoded_mint_address;

    uint64_t chain_id;
    uint32_t challenge;
    uint8_t name_type;
    uint8_t name_source;

    uint8_t key_id;
    uint8_t sig_algorithm;
    buffer_t input_sig;
} tlv_out_t;
