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
#include "tlv_library.h"
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

// Parsed TLV data
typedef struct tlv_extracted_s {
    // Received tags set by the parser
    TLV_reception_t received_tags;

    // Trusted name output data
    uint8_t struct_type;
    uint8_t struct_version;
    buffer_t encoded_token_address;
    buffer_t encoded_owner_address;
    buffer_t encoded_mint_address;
    uint64_t chain_id;
    uint32_t challenge;
    uint8_t name_type;
    uint8_t name_source;

    // TLV Signature checking related data
    uint8_t key_id;
    uint8_t sig_algorithm;
    buffer_t input_sig;

    // Progressive hash of the received TLVs (except the signature type)
    cx_sha256_t hash_ctx;
} tlv_extracted_t;

static bool handle_struct_type(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->struct_type);
}

static bool handle_struct_version(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->struct_version);
}

static bool handle_challenge(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint32_t_from_tlv_data(data, &tlv_extracted->challenge);
}

static bool handle_sign_key_id(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->key_id);
}

static bool handle_sign_algo(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->sig_algorithm);
}

static bool handle_signature(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data, &tlv_extracted->input_sig, 1, 0);
}

static bool handle_source_contract(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->encoded_mint_address,
                                    1,
                                    BASE58_PUBKEY_LENGTH - 1);
}

static bool handle_trusted_name(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->encoded_token_address,
                                    1,
                                    BASE58_PUBKEY_LENGTH - 1);
}

static bool handle_address(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->encoded_owner_address,
                                    1,
                                    BASE58_PUBKEY_LENGTH - 1);
}

static bool handle_chain_id(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
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

static bool handle_trusted_name_type(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->name_type);
}

static bool handle_trusted_name_source(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->name_source);
}

static bool handle_hash_only(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return true;
}

// clang-format off
// List of TLV tags recognized by the Solana application
#define TLV_TAGS(X)                                                              \
    X(0x01, STRUCT_TYPE,         handle_struct_type,         ENFORCE_UNIQUE_TAG) \
    X(0x02, STRUCT_VERSION,      handle_struct_version,      ENFORCE_UNIQUE_TAG) \
    X(0x70, TRUSTED_NAME_TYPE,   handle_trusted_name_type,   ENFORCE_UNIQUE_TAG) \
    X(0x71, TRUSTED_NAME_SOURCE, handle_trusted_name_source, ENFORCE_UNIQUE_TAG) \
    X(0x72, TRUSTED_NAME_NFT_ID, handle_hash_only,           ENFORCE_UNIQUE_TAG) \
    X(0x20, TRUSTED_NAME,        handle_trusted_name,        ENFORCE_UNIQUE_TAG) \
    X(0x23, CHAIN_ID,            handle_chain_id,            ENFORCE_UNIQUE_TAG) \
    X(0x22, ADDRESS,             handle_address,             ENFORCE_UNIQUE_TAG) \
    X(0x73, SOURCE_CONTRACT,     handle_source_contract,     ENFORCE_UNIQUE_TAG) \
    X(0x12, CHALLENGE,           handle_challenge,           ENFORCE_UNIQUE_TAG) \
    X(0x10, NOT_VALID_AFTER,     handle_hash_only,           ENFORCE_UNIQUE_TAG) \
    X(0x13, SIGNER_KEY_ID,       handle_sign_key_id,         ENFORCE_UNIQUE_TAG) \
    X(0x14, SIGNER_ALGO,         handle_sign_algo,           ENFORCE_UNIQUE_TAG) \
    X(0x15, SIGNATURE,           handle_signature,           ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(TLV_TAGS, parse_tlv_trusted_name)

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

static int verify_struct(const tlv_extracted_t *tlv_extracted) {
    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, STRUCT_TYPE)) {
        PRINTF("Error: no struct type specified!\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, STRUCT_VERSION)) {
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
            if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags,
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
    tlv_extracted_t tlv_extracted = {0};

    PRINTF("Received chunk of trusted info, length = %d\n", G_command.message_length);

    // The parser will fill it with the hash of the whole TLV payload (except SIGN tag)
    cx_sha256_init(&tlv_extracted.hash_ctx);

    // Convert G_command to buffer_t format. 0 copy
    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    // Call the function created by the macro from the TLV lib
    if (!parse_tlv_trusted_name(&payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("Failed to parse tlv payload\n");
        return ApduReplySolanaInvalidTrustedInfo;
    }

    // Finalize hash object filled by the parser
    uint8_t tlv_hash[CX_SHA256_SIZE] = {0};
    CX_ASSERT(cx_hash_final((cx_hash_t *) &tlv_extracted.hash_ctx, tlv_hash));

    // Verify that the fields received are correct in our context
    if (verify_struct(&tlv_extracted) != 0) {
        PRINTF("Failed to verify tlv payload\n");
        return ApduReplySolanaInvalidTrustedInfo;
    }

    // Verify that the signature field of the TLV is the signature of the TLV hash by the key loaded
    // by the PKI
    if (check_signature_with_pubkey(tlv_hash,
                                    CX_SHA256_SIZE,
                                    CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME,
                                    CX_CURVE_SECP256K1,
                                    tlv_extracted.input_sig) != 0) {
        PRINTF("Failed to verify signature of trusted name info\n");
        return ApduReplySolanaInvalidTrustedInfo;
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
