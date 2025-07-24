#pragma once

#include "sol/printer.h"
#include "tlv_use_case_dynamic_descriptor.h"

typedef struct trusted_info_s {
    bool received;
    char encoded_owner_address[BASE58_PUBKEY_LENGTH];
    uint8_t owner_address[PUBKEY_LENGTH];
    char encoded_token_address[BASE58_PUBKEY_LENGTH];
    uint8_t token_address[PUBKEY_LENGTH];
    char encoded_mint_address[BASE58_PUBKEY_LENGTH];
    uint8_t mint_address[PUBKEY_LENGTH];
} trusted_info_t;

extern trusted_info_t g_trusted_info;

bool check_ata_against_trusted_info(const uint8_t src_account[PUBKEY_LENGTH],
                                    const uint8_t mint_account[PUBKEY_LENGTH],
                                    const uint8_t dest_account[PUBKEY_LENGTH],
                                    bool is_token_2022);

int get_transfer_to_address(const char **to_address);
