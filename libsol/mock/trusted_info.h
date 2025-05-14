#pragma once

#include "sol/printer.h"

// ATA DESCRIPTOR //

typedef struct trusted_info_s {
    bool received;
    char encoded_owner_address[BASE58_PUBKEY_LENGTH];
    uint8_t owner_address[PUBKEY_LENGTH];
    char encoded_token_address[BASE58_PUBKEY_LENGTH];
    uint8_t token_address[PUBKEY_LENGTH];
    char encoded_mint_address[BASE58_PUBKEY_LENGTH];
    uint8_t mint_address[PUBKEY_LENGTH];
} trusted_info_t;

// extern trusted_info_t g_trusted_info;

bool check_ata_agaisnt_trusted_info(const uint8_t src_account[PUBKEY_LENGTH],
                                    const uint8_t mint_account[PUBKEY_LENGTH],
                                    const uint8_t dest_account[PUBKEY_LENGTH],
                                    bool is_token_2022);

int get_transfer_to_address(char **to_address);

// DYNAMIC TOKEN //

#define MAX_TICKER_SIZE 32
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

// extern dynamic_token_info_t g_dynamic_token_info;

const char *get_dynamic_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind);
