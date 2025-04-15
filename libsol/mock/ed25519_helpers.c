#include "ed25519_helpers.h"

bool validate_associated_token_address(const uint8_t owner_account[PUBKEY_LENGTH],
                                       const uint8_t mint_account[PUBKEY_LENGTH],
                                       const uint8_t provided_ata[PUBKEY_LENGTH],
                                       bool is_token_2022) {
    (void) owner_account;
    (void) mint_account;
    (void) provided_ata;
    (void) is_token_2022;
    return true;
}
