#include <os.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "globals.h"
#include "utils.h"
#include "handle_get_challenge.h"
#include "base58.h"
#include "trusted_info.h"

#include "sol/printer.h"

#include "macros.h"
#include "tlv.h"
#include "tlv_utils.h"
#include "os_pki.h"
#include "ledger_pki.h"

#include "handle_provide_trusted_info.h"

#define TYPE_ADDRESS      0x06
#define TYPE_DYN_RESOLVER 0x06

#define STRUCT_TYPE_TRUSTED_NAME 0x03
#define ALGO_SECP256K1           1

#define KEY_ID_TEST 0x00
#define KEY_ID_PROD 0x07

trusted_info_t g_trusted_info;

static void trusted_info_reset(trusted_info_t *trusted_info) {
    explicit_bzero(trusted_info, sizeof(*trusted_info));
}

static bool handle_struct_type(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->struct_type);
}

static bool handle_struct_version(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->struct_version);
}

static bool handle_challenge(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_uint32_from_tlv_data(data, &tlv_extracted->challenge);
}

static bool handle_sign_key_id(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->key_id);
}

static bool handle_sign_algo(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->sig_algorithm);
}

static bool handle_signature(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data, &tlv_extracted->input_sig, 1, 0);
}

static bool handle_source_contract(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->encoded_mint_address,
                                    1,
                                    BASE58_PUBKEY_LENGTH - 1);
}

static bool handle_trusted_name(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->encoded_token_address,
                                    1,
                                    BASE58_PUBKEY_LENGTH - 1);
}

static bool handle_address(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->encoded_owner_address,
                                    1,
                                    BASE58_PUBKEY_LENGTH - 1);
}

static bool handle_chain_id(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    switch (data->length) {
        case 1:
            tlv_extracted->chain_id = data->value[0];
            return true;
        case 2:
            tlv_extracted->chain_id = (data->value[0] << 8) | data->value[1];
            return true;
        default:
            PRINTF("Error while parsing chain ID: length = %d\n", data->length);
            return false;
    }
}

static bool handle_trusted_name_type(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->name_type);
}

static bool handle_trusted_name_source(const tlv_data_t *data, tlv_out_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->name_source);
}

static int copy_and_decode_pubkey(const buffer_t in_encoded_address,
                                  char *out_encoded_address,
                                  uint8_t *decoded_address) {
    int res;

    // Should be caught at parsing but let's double check
    if (in_encoded_address.size >= BASE58_PUBKEY_LENGTH) {
        PRINTF("Input address size exceeds buffer length\n");
        return -1;
    }

    // Should be caught at parsing but let's double check
    if (in_encoded_address.size == 0) {
        PRINTF("Input address size is 0\n");
        return -1;
    }

    // Save the encoded address
    memset(out_encoded_address, 0, BASE58_PUBKEY_LENGTH);
    memcpy(out_encoded_address, in_encoded_address.ptr, in_encoded_address.size);

    // Decode and save the decoded address
    res = base58_decode(out_encoded_address,
                        strlen(out_encoded_address),
                        decoded_address,
                        PUBKEY_LENGTH);
    if (res != PUBKEY_LENGTH) {
        PRINTF("base58_decode error, %d != PUBKEY_LENGTH %d\n", res, PUBKEY_LENGTH);
        return -1;
    }

    return 0;
}

static int verify_struct(const tlv_out_t *tlv_extracted, uint32_t received_tags_flags) {
    if (!(get_tag_flag(STRUCT_TYPE) & received_tags_flags)) {
        PRINTF("Error: no struct type specified!\n");
        return -1;
    }
    if (!(get_tag_flag(STRUCT_VERSION) & received_tags_flags)) {
        PRINTF("Error: no struct version specified!\n");
        return -1;
    }

    uint32_t expected_challenge = get_challenge();

#ifdef TRUSTED_NAME_TEST_KEY
    uint8_t valid_key_id = KEY_ID_TEST;
#else
    uint8_t valid_key_id = KEY_ID_PROD;
#endif

    switch (tlv_extracted->struct_version) {
        case 2:
            if (!RECEIVED_REQUIRED_TAGS(received_tags_flags,
                                        STRUCT_TYPE,
                                        STRUCT_VERSION,
                                        TRUSTED_NAME_TYPE,
                                        TRUSTED_NAME_SOURCE,
                                        TRUSTED_NAME,
                                        CHAIN_ID,
                                        ADDRESS,
                                        CHALLENGE,
                                        SIGNER_KEY_ID,
                                        SIGNER_ALGO,
                                        SIGNATURE)) {
                PRINTF("Error: missing required fields in struct version 2\n");
                return -1;
            }
            if (tlv_extracted->challenge != expected_challenge) {
                // No risk printing it as DEBUG cannot be used in prod
                PRINTF("Error: wrong challenge, received %u expected %u\n",
                       tlv_extracted->challenge,
                       expected_challenge);
                return -1;
            }
            if (tlv_extracted->struct_type != STRUCT_TYPE_TRUSTED_NAME) {
                PRINTF("Error: unexpected struct type %d\n", tlv_extracted->struct_type);
                return -1;
            }
            if (tlv_extracted->name_type != TYPE_ADDRESS) {
                PRINTF("Error: unsupported name type %d\n", tlv_extracted->name_type);
                return -1;
            }
            if (tlv_extracted->name_source != TYPE_DYN_RESOLVER) {
                PRINTF("Error: unsupported name source %d\n", tlv_extracted->name_source);
                return -1;
            }
            if (tlv_extracted->sig_algorithm != ALGO_SECP256K1) {
                PRINTF("Error: unsupported sig algorithm %d\n", tlv_extracted->sig_algorithm);
                return -1;
            }
            if (tlv_extracted->key_id != valid_key_id) {
                PRINTF("Error: wrong metadata key ID %u\n", tlv_extracted->key_id);
                return -1;
            }
            break;
        default:
            PRINTF("Error: unsupported struct version %d\n", tlv_extracted->struct_version);
            return -1;
    }
    return 0;
}

static ApduReply handle_provide_trusted_info_internal(void) {
    // Main structure that will received the parsed TLV data
    tlv_out_t tlv_extracted;
    memset(&tlv_extracted, 0, sizeof(tlv_extracted));

    // Will be filled by the parser with the flags of received tags
    uint32_t received_tags_flags = 0;

    // The parser will fill it with the hash of the whole TLV payload (except SIGN tag)
    uint8_t tlv_hash[INT256_LENGTH] = {0};

    // Mapping of tags to handler functions. Given to the parser
    tlv_handler_t handlers[TLV_COUNT] = {
        {.tag = STRUCT_TYPE, .func = &handle_struct_type},
        {.tag = STRUCT_VERSION, .func = &handle_struct_version},
        {.tag = TRUSTED_NAME_TYPE, .func = &handle_trusted_name_type},
        {.tag = TRUSTED_NAME_SOURCE, .func = &handle_trusted_name_source},
        {.tag = TRUSTED_NAME_NFT_ID, .func = NULL},
        {.tag = TRUSTED_NAME, .func = &handle_trusted_name},
        {.tag = CHAIN_ID, .func = &handle_chain_id},
        {.tag = ADDRESS, .func = &handle_address},
        {.tag = SOURCE_CONTRACT, .func = &handle_source_contract},
        {.tag = CHALLENGE, .func = &handle_challenge},
        {.tag = NOT_VALID_AFTER, .func = NULL},
        {.tag = SIGNER_KEY_ID, .func = &handle_sign_key_id},
        {.tag = SIGNER_ALGO, .func = &handle_sign_algo},
        {.tag = SIGNATURE, .func = &handle_signature},
    };

    PRINTF("Received chunk of trusted info, length = %d\n", G_command.message_length);

    // Convert G_command to buffer_t format. 0 copy
    buffer_t payload;
    payload.ptr = G_command.message;
    payload.size = G_command.message_length;

    // Call the parser to extract the raw TLV payload into our parsed structure
    if (!parse_tlv(handlers,
                   ARRAY_LENGTH(handlers),
                   &payload,
                   &tlv_extracted,
                   SIGNATURE,
                   tlv_hash,
                   &received_tags_flags)) {
        PRINTF("Failed to parse tlv payload\n");
        return ApduReplySolanaInvalidTrustedInfo;
    }

    // Verify that the fields received are correct in our context
    if (verify_struct(&tlv_extracted, received_tags_flags) != 0) {
        PRINTF("Failed to verify tlv payload\n");
        // return ApduReplySolanaInvalidTrustedInfo;
    }

    // Verify that the signature field of the TLV is the signature of the TLV hash by the key loaded
    // by the PKI
    if (check_signature_with_pubkey(tlv_hash,
                                    INT256_LENGTH,
                                    CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME,
                                    CX_CURVE_SECP256K1,
                                    tlv_extracted.input_sig) != 0) {
        PRINTF("Failed to verify signature of trusted name info\n");
        // return ApduReplySolanaInvalidTrustedInfo;
    }

    // We have received 3 addresses in string base58 format.
    // We will save this decode them and save both the encoded and decoded format.
    // We could save just one but as we need to decode them to ensure they are valid we save both

    if (copy_and_decode_pubkey(tlv_extracted.encoded_owner_address,
                               g_trusted_info.encoded_owner_address,
                               g_trusted_info.owner_address) != 0) {
        PRINTF("copy_and_decode_pubkey error for encoded_owner_address\n");
        return ApduReplySolanaInvalidTrustedInfo;
    }

    if (copy_and_decode_pubkey(tlv_extracted.encoded_token_address,
                               g_trusted_info.encoded_token_address,
                               g_trusted_info.token_address) != 0) {
        PRINTF("copy_and_decode_pubkey error for encoded_token_address\n");
        return ApduReplySolanaInvalidTrustedInfo;
    }

    if (copy_and_decode_pubkey(tlv_extracted.encoded_mint_address,
                               g_trusted_info.encoded_mint_address,
                               g_trusted_info.mint_address) != 0) {
        PRINTF("copy_and_decode_pubkey error for encoded_mint_address\n");
        return ApduReplySolanaInvalidTrustedInfo;
    }

    g_trusted_info.received = true;

    PRINTF("=== TRUSTED INFO ===\n");
    PRINTF("encoded_owner_address = %s\n", g_trusted_info.encoded_owner_address);
    PRINTF("owner_address         = %.*H\n", PUBKEY_LENGTH, g_trusted_info.owner_address);
    PRINTF("encoded_token_address = %s\n", g_trusted_info.encoded_token_address);
    PRINTF("token_address         = %.*H\n", PUBKEY_LENGTH, g_trusted_info.token_address);
    PRINTF("encoded_mint_address  = %s\n", g_trusted_info.encoded_mint_address);
    PRINTF("mint_address          = %.*H\n", PUBKEY_LENGTH, g_trusted_info.mint_address);

    return ApduReplySuccess;
}

// Wrapper around handle_provide_trusted_info_internal to handle the challenge reroll
void handle_provide_trusted_info(void) {
    trusted_info_reset(&g_trusted_info);
    ApduReply ret = handle_provide_trusted_info_internal();
    // prevent brute-force guesses
    roll_challenge();
    // TODO: use no throw model
    THROW(ret);
}
