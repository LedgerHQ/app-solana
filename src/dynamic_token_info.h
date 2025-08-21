#pragma once

#include "sol/printer.h"
#include "token_info.h"
#include "tlv_use_case_dynamic_descriptor.h"

typedef struct dynamic_token_info_s {
    bool received;
    char ticker[MAX_TICKER_SIZE + 1];
    uint8_t magnitude;
    bool is_token_2022_kind;
    char encoded_mint_address[BASE58_PUBKEY_LENGTH];
    uint8_t mint_address[PUBKEY_LENGTH];
    // Not used currently
    // extension_code_value_t extensions[EXTENSION_CODE_VALUE_COUNT];
} dynamic_token_info_t;

extern dynamic_token_info_t g_dynamic_token_info;

const char *get_dynamic_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind);
const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind);

const uint8_t *get_dynamic_token_mint_address(const char *symbol, bool *is_token_2022_kind);
const uint8_t *get_token_mint_address(const char *symbol, bool *is_token_2022_kind);
