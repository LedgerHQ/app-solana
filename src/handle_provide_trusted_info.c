#include <os.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "globals.h"
#include "utils.h"
#include "handle_get_challenge.h"
#include "base58.h"
#include "trusted_info.h"
#include "tlv_use_case_trusted_name.h"

#include "sol/printer.h"

#include "macros.h"
#include "os_pki.h"
#include "ledger_pki.h"

#include "handle_provide_trusted_info.h"

trusted_info_t g_trusted_info;

static int handle_provide_trusted_info_internal(void) {
    explicit_bzero(&g_trusted_info, sizeof(g_trusted_info));

    tlv_trusted_name_out_t tlv_output = {0};

    // Convert G_command to buffer_t format. 0 copy
    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    if (tlv_use_case_trusted_name(&payload, &tlv_output) != TLV_TRUSTED_NAME_SUCCESS) {
        PRINTF("tlv_use_case_trusted_name failed\n");
        return -1;
    }

    // Check solana specific required tags
    if (!tlv_output.source_contract_received || !tlv_output.challenge_received) {
        PRINTF("Error: missing Solana required fields\n");
        return -1;
    }

    uint32_t expected_challenge = get_challenge();
    if (tlv_output.challenge != expected_challenge) {
        PRINTF("Error: wrong challenge, received %u expected %u\n",
               tlv_output.challenge,
               expected_challenge);
        return -1;
    }

    if (tlv_output.trusted_name_type != TLV_TRUSTED_NAME_TYPE_CONTEXT_ADDRESS) {
        PRINTF("Error: unsupported name type %d\n", tlv_output.trusted_name_type);
        return -1;
    }

    if (tlv_output.trusted_name_source != TLV_TRUSTED_NAME_SOURCE_DYNAMIC_RESOLVER) {
        PRINTF("Error: unsupported name source %d\n", tlv_output.trusted_name_source);
        return -1;
    }

    // We have received 3 addresses in string base58 format.
    // We will save this decode them and save both the encoded and decoded format.
    // We could save just one but as we need to decode them to ensure they are valid we save both

    if (copy_and_decode_pubkey(tlv_output.address,
                               g_trusted_info.encoded_owner_address,
                               g_trusted_info.owner_address) != 0) {
        PRINTF("copy_and_decode_pubkey error for encoded_owner_address\n");
        return -1;
    }

    if (copy_and_decode_pubkey(tlv_output.trusted_name,
                               g_trusted_info.encoded_token_address,
                               g_trusted_info.token_address) != 0) {
        PRINTF("copy_and_decode_pubkey error for encoded_token_address\n");
        return -1;
    }

    if (copy_and_decode_pubkey(tlv_output.source_contract,
                               g_trusted_info.encoded_mint_address,
                               g_trusted_info.mint_address) != 0) {
        PRINTF("copy_and_decode_pubkey error for encoded_mint_address\n");
        return -1;
    }

    g_trusted_info.received = true;

    PRINTF("=== TRUSTED INFO ===\n");
    PRINTF("encoded_owner_address = %s\n", g_trusted_info.encoded_owner_address);
    PRINTF("owner_address         = %.*H\n", PUBKEY_LENGTH, g_trusted_info.owner_address);
    PRINTF("encoded_token_address = %s\n", g_trusted_info.encoded_token_address);
    PRINTF("token_address         = %.*H\n", PUBKEY_LENGTH, g_trusted_info.token_address);
    PRINTF("encoded_mint_address  = %s\n", g_trusted_info.encoded_mint_address);
    PRINTF("mint_address          = %.*H\n", PUBKEY_LENGTH, g_trusted_info.mint_address);

    return 0;
}

// Wrapper around handle_provide_trusted_info_internal to handle the challenge reroll
void handle_provide_trusted_info(void) {
    int ret = handle_provide_trusted_info_internal();
    // prevent brute-force guesses
    roll_challenge();
    // TODO: use no throw model
    if (ret == 0) {
        THROW(ApduReplySuccess);
    } else {
        THROW(ApduReplySolanaInvalidTrustedInfo);
    }
}
