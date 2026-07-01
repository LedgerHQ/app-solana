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
} dynamic_token_info_t;

typedef struct dynamic_token_info_pool_s {
    dynamic_token_info_t *entries;
    size_t count;
    size_t capacity;
} dynamic_token_info_pool_t;

extern dynamic_token_info_pool_t *g_dynamic_token_info;

void reset_dynamic_token_info(void);

// Append a new entry to the dynamic pool. Returns 0 on success, -1 on OOM.
int dynamic_token_info_add(dynamic_token_info_t *entry);

const char *get_dynamic_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind);
const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind);

// Returns the magnitude (decimals) for a given mint, or -1 if not found.
int get_token_magnitude(const uint8_t *mint_address, bool is_token_2022_kind);

const uint8_t *get_dynamic_token_mint_address(const char *symbol, bool *is_token_2022_kind);
const uint8_t *get_token_mint_address(const char *symbol, bool *is_token_2022_kind);
