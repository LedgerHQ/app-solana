#include "trusted_info.h"

bool check_ata_agaisnt_trusted_info(const uint8_t src_account[PUBKEY_LENGTH],
                                    const uint8_t mint_account[PUBKEY_LENGTH],
                                    const uint8_t dest_account[PUBKEY_LENGTH],
                                    bool is_token_2022) {
    (void) src_account;
    (void) mint_account;
    (void) dest_account;
    (void) is_token_2022;
    return true;
}

int get_transfer_to_address(char **to_address) {
    (void) to_address;
    return 0;
}
