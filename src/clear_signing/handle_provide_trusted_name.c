#include <os.h>
#include <stdint.h>
#include <string.h>

#include "handle_provide_trusted_name.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "cs_transaction.h"
#include "cs_trusted_name_cache.h"
#include "tlv_use_case_trusted_name.h"

#include "sol/printer.h"
#include "sol/pubkey.h"
#include "reply.h"

// Chain id carried by a Solana mainnet trusted-name descriptor.
#define SOLANA_CHAIN_ID 900

static int handle_provide_trusted_name_internal(void) {
    tlv_trusted_name_out_t tlv_output = {0};

    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    // Parses the TLV and verifies the descriptor signature against the PKI.
    if (tlv_use_case_trusted_name(&payload, &tlv_output) != TLV_TRUSTED_NAME_SUCCESS) {
        PRINTF("tlv_use_case_trusted_name failed\n");
        return -1;
    }

    if (tlv_output.trusted_name_type != TLV_TRUSTED_NAME_TYPE_SMART_CONTRACT &&
        tlv_output.trusted_name_type != TLV_TRUSTED_NAME_TYPE_TOKEN) {
        PRINTF("Error: unsupported name type %d\n", tlv_output.trusted_name_type);
        return -1;
    }

    // CAL assets are static, so no challenge is checked.
    if (tlv_output.trusted_name_source != TLV_TRUSTED_NAME_SOURCE_CRYPTO_ASSET_LIST) {
        PRINTF("Error: unsupported name source %d\n", tlv_output.trusted_name_source);
        return -1;
    }

    if (tlv_output.chain_id != SOLANA_CHAIN_ID) {
        PRINTF("Error: unexpected chain id %llu\n", tlv_output.chain_id);
        return -1;
    }

    // The address is a raw Solana public key, not base58.
    if (tlv_output.address.size != PUBKEY_SIZE) {
        PRINTF("Error: unexpected address size %u\n", (unsigned) tlv_output.address.size);
        return -1;
    }

    if (tlv_output.trusted_name.size == 0 ||
        tlv_output.trusted_name.size > CS_TRUSTED_NAME_MAX_LEN) {
        PRINTF("Error: invalid name size %u\n", (unsigned) tlv_output.trusted_name.size);
        return -1;
    }

    // The name is displayed verbatim; require printable ASCII.
    for (uint16_t i = 0; i < tlv_output.trusted_name.size; i++) {
        if (tlv_output.trusted_name.ptr[i] < 0x20 || tlv_output.trusted_name.ptr[i] > 0x7E) {
            PRINTF("Error: non-printable byte 0x%02x in trusted name\n",
                   tlv_output.trusted_name.ptr[i]);
            return -1;
        }
    }

    // The cache needs a NUL-terminated string.
    char name[CS_TRUSTED_NAME_MAX_LEN + 1] = {0};
    memcpy(name, tlv_output.trusted_name.ptr, tlv_output.trusted_name.size);
    name[tlv_output.trusted_name.size] = '\0';

    if (cs_trusted_name_cache_add(tlv_output.address.ptr, name, tlv_output.trusted_name_type) !=
        0) {
        PRINTF("cs_trusted_name_cache_add failed\n");
        return -1;
    }

    PRINTF("=== TRUSTED NAME ===\n");
    PRINTF("name    = %s\n", name);
    PRINTF("type    = %d\n", tlv_output.trusted_name_type);
    PRINTF("source  = %d\n", tlv_output.trusted_name_source);
    PRINTF("address = %.*H\n", PUBKEY_SIZE, tlv_output.address.ptr);

    return 0;
}

int handle_provide_trusted_name(void) {
    PRINTF("handle_provide_trusted_name\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return reply_sw(state_err);
    }

    if (handle_provide_trusted_name_internal() != 0) {
        return reply_sw(ApduReplySolanaInvalidTrustedName);
    }
    return reply_sw(ApduReplySuccess);
}
