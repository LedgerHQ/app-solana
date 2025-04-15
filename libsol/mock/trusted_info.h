#pragma once

#include "sol/printer.h"

typedef struct trusted_info_s {
    bool received;
    char encoded_owner_address[BASE58_PUBKEY_LENGTH];
    uint8_t owner_address[PUBKEY_LENGTH];
    char encoded_token_address[BASE58_PUBKEY_LENGTH];
    uint8_t token_address[PUBKEY_LENGTH];
    char encoded_mint_address[BASE58_PUBKEY_LENGTH];
    uint8_t mint_address[PUBKEY_LENGTH];
} trusted_info_t;

bool check_ata_agaisnt_trusted_info(const uint8_t src_account[PUBKEY_LENGTH],
                                    const uint8_t mint_account[PUBKEY_LENGTH],
                                    const uint8_t dest_account[PUBKEY_LENGTH],
                                    bool is_token_2022);

int get_transfer_to_address(char **to_address);
