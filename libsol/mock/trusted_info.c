#include "trusted_info.h"

bool check_ata_against_trusted_info(const uint8_t src_account[PUBKEY_LENGTH],
                                    const uint8_t mint_account[PUBKEY_LENGTH],
                                    const uint8_t dest_account[PUBKEY_LENGTH],
                                    bool is_token_2022) {
    (void) src_account;
    (void) mint_account;
    (void) dest_account;
    (void) is_token_2022;
    return true;
}

const char *address = "trusted_address";

int get_transfer_to_address(const char **to_address) {
    *to_address = address;
    return 0;
}
