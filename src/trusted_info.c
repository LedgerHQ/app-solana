#include "os.h"
#include "trusted_info.h"
#include "ed25519_helpers.h"

bool check_ata_agaisnt_trusted_info(const uint8_t src_account[PUBKEY_LENGTH],
                                    const uint8_t mint_account[PUBKEY_LENGTH],
                                    const uint8_t dest_account[PUBKEY_LENGTH],
                                    bool is_token_2022) {
    UNUSED(src_account);
    // Here we will check the content of the SPL transaction against the received descriptor
    if (!g_trusted_info.received) {
        PRINTF("Descriptor info is required for a SPL transfer\n");
        return false;
    }

    // We have received a destination ATA, we will validate it by comparing it against the
    // derivation of the owner address + mint address
    // We must have received the owner address from the descriptor for this

    PRINTF("=== TX INFO ===\n");
    PRINTF("src_account           = %.*H\n", PUBKEY_LENGTH, src_account);
    PRINTF("mint_account          = %.*H\n", PUBKEY_LENGTH, mint_account);
    PRINTF("dest_account          = %.*H\n", PUBKEY_LENGTH, dest_account);

    PRINTF("=== TRUSTED INFO ===\n");
    PRINTF("encoded_owner_address = %s\n", g_trusted_info.encoded_owner_address);
    PRINTF("owner_address         = %.*H\n", PUBKEY_LENGTH, g_trusted_info.owner_address);
    PRINTF("encoded_token_address = %s\n", g_trusted_info.encoded_token_address);
    PRINTF("token_address         = %.*H\n", PUBKEY_LENGTH, g_trusted_info.token_address);
    PRINTF("encoded_mint_address  = %s\n", g_trusted_info.encoded_mint_address);
    PRINTF("mint_address          = %.*H\n", PUBKEY_LENGTH, g_trusted_info.mint_address);

    if (memcmp(g_trusted_info.mint_address, mint_account, PUBKEY_LENGTH) != 0) {
        PRINTF("Mint address does not match with mint address in descriptor\n");
        return false;
    }

    if (memcmp(g_trusted_info.token_address, dest_account, PUBKEY_LENGTH) != 0) {
        PRINTF("Token address does not match with token address in descriptor\n");
        return false;
    }

    if (!validate_associated_token_address(g_trusted_info.owner_address,
                                           mint_account,
                                           dest_account,
                                           is_token_2022)) {
        return false;
    }

    return true;
}

int get_transfer_to_address(char **to_address) {
    // Already checked in parsing step but let's be secure
    if (!g_trusted_info.received) {
        PRINTF("Descriptor info is required for a SPL transfer\n");
        return -1;
    }

    *to_address = g_trusted_info.encoded_owner_address;
    return 0;
}

const char *get_dynamic_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind) {
    if (!g_dynamic_token_info.received) {
        return NULL;
    }

    // We have received a descriptor that should apply to the current token. use it.
    if (memcmp(g_dynamic_token_info.mint_address, mint_address, PUBKEY_SIZE) != 0) {
        PRINTF("Received dynamic token info for token '%.*H' != token '%.*H'\n",
               PUBKEY_SIZE,
               g_dynamic_token_info.mint_address,
               PUBKEY_SIZE,
               mint_address);
        return NULL;
    }

    if (is_token_2022_kind != g_dynamic_token_info.is_token_2022_kind) {
        PRINTF("Token kind mismatch %d != %d\n",
               is_token_2022_kind,
               g_dynamic_token_info.is_token_2022_kind);
        return NULL;
    }

    PRINTF("Using dynamic token info to map token '%.*H' == ticker '%s'\n",
           PUBKEY_SIZE,
           g_dynamic_token_info.mint_address,
           g_dynamic_token_info.ticker);
    return g_dynamic_token_info.ticker;
}
