#include <os.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "cx.h"
#include "os_pki.h"
#include "ledger_pki.h"
#include "tlv_use_case_trusted_name.h"

// Progressive hash of the received TLVs (except the signature type)
// We will know the correct format to use at reception of the signer_algo tag. We don't try to
// be clever and just calculate all hash until then.
typedef struct multi_hash_ctx_s {
    cx_sha256_t sha256;
    cx_sha3_t sha3_256;
    cx_sha3_t keccak_256;
    cx_ripemd160_t ripemd160;
    cx_sha512_t sha512;
} multi_hash_ctx_t;

// Output of the multi hash after hash finalize
typedef union multi_hash_finalized_u {
    // Use a union trick to always declare at max size
    uint8_t _sha256[CX_SHA256_SIZE];
    uint8_t _sha3_256[CX_SHA3_256_SIZE];
    uint8_t _keccak_256[CX_KECCAK_256_SIZE];
    uint8_t _ripemd160[CX_RIPEMD160_SIZE];
    uint8_t _sha512[CX_SHA512_SIZE];
    // Generic access at offset 0
    uint8_t hash;
} multi_hash_finalized_t;

static void init_multi_hash_ctx(multi_hash_ctx_t *hash_ctx) {
    // Use CX_ASSERT, none of those functions can reasonably fail
    CX_ASSERT(cx_sha256_init_no_throw(&hash_ctx->sha256));
    CX_ASSERT(cx_sha3_init_no_throw(&hash_ctx->sha3_256, 256));
    CX_ASSERT(cx_keccak_init_no_throw(&hash_ctx->keccak_256, 256));
    CX_ASSERT(cx_ripemd160_init_no_throw(&hash_ctx->ripemd160));
    CX_ASSERT(cx_sha512_init_no_throw(&hash_ctx->sha512));
}

// Feed data into all hash without concern
static void update_multi_hash_ctx(multi_hash_ctx_t *hash_ctx, buffer_t data) {
    // Use CX_ASSERT, none of those functions can reasonably fail
    CX_ASSERT(cx_hash_update((cx_hash_t *) &hash_ctx->sha256, data.ptr, data.size));
    CX_ASSERT(cx_hash_update((cx_hash_t *) &hash_ctx->sha3_256, data.ptr, data.size));
    CX_ASSERT(cx_hash_update((cx_hash_t *) &hash_ctx->keccak_256, data.ptr, data.size));
    CX_ASSERT(cx_hash_update((cx_hash_t *) &hash_ctx->ripemd160, data.ptr, data.size));
    CX_ASSERT(cx_hash_update((cx_hash_t *) &hash_ctx->sha512, data.ptr, data.size));
}

// Select the correct hash to use depending on the requested algorithm and finalize it
static int finalize_hash_for_algo(const multi_hash_ctx_t *hash_ctx,
                                  tlv_trusted_name_signer_algorithm_t signer_algo,
                                  multi_hash_finalized_t *multi_hash_finalized) {
    cx_hash_t *hash;
    switch (signer_algo) {
        case TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_SHA256:
            hash = (cx_hash_t *) &hash_ctx->sha256;
            break;
        case TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_SHA3_256:
        case TLV_TRUSTED_NAME_SIGNER_ALGORITHM_EDDSA_SHA3_256:
            hash = (cx_hash_t *) &hash_ctx->sha3_256;
            break;
        case TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_KECCAK_256:
        case TLV_TRUSTED_NAME_SIGNER_ALGORITHM_EDDSA_KECCAK_256:
            hash = (cx_hash_t *) &hash_ctx->keccak_256;
            break;
        case TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_RIPEMD160:
            hash = (cx_hash_t *) &hash_ctx->ripemd160;
            break;
        case TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_SHA512:
            hash = (cx_hash_t *) &hash_ctx->sha512;
            break;
        default:
            PRINTF("Unknown signer_algo %d\n", signer_algo);
            return -1;
    }

    if (cx_hash_final(hash, &multi_hash_finalized->hash) != CX_OK) {
        PRINTF("cx_hash_final failed for algo %d\n", signer_algo);
        return -1;
    }

    return 0;
}

// Parsed TLV data
typedef struct tlv_extracted_s {
    // Received tags set by the parser
    TLV_reception_t received_tags;

    // Trusted name output data
    tlv_trusted_name_out_t *output;

    // Tags handled by the use case API and not the caller
    uint8_t structure_type;
    uint16_t signer_key_id;
    uint8_t signer_algo;
    buffer_t input_sig;

    // Hash using all protocols at once
    multi_hash_ctx_t hash_ctx;
} tlv_extracted_t;

static bool handle_structure_type(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->structure_type);
}

static bool handle_version(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->output->version);
}

static bool handle_trusted_name_type(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->output->trusted_name_type);
}

static bool handle_trusted_name_source(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->output->trusted_name_source);
}

static bool handle_trusted_name(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->output->trusted_name,
                                    0,
                                    TRUSTED_NAME_STRINGS_MAX_SIZE);
}

static bool handle_chain_id(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint64_t_from_tlv_data(data, &tlv_extracted->output->chain_id);
}

static bool handle_address(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->output->address,
                                    0,
                                    TRUSTED_NAME_STRINGS_MAX_SIZE);
}

static bool handle_nft_id(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data, &tlv_extracted->output->nft_id, NFT_ID_SIZE, NFT_ID_SIZE);
}

static bool handle_source_contract(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->output->source_contract,
                                    0,
                                    TRUSTED_NAME_STRINGS_MAX_SIZE);
}

static bool handle_challenge(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint32_t_from_tlv_data(data, &tlv_extracted->output->challenge);
}

static bool handle_not_valid_after(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    if (data->value.size != sizeof(tlv_extracted->output->not_valid_after)) {
        PRINTF("Invalid handle_not_valid_after format length %d\n", data->value.size);
        return false;
    }
    tlv_extracted->output->not_valid_after.major = data->value.ptr[0];
    tlv_extracted->output->not_valid_after.minor = data->value.ptr[1];
    tlv_extracted->output->not_valid_after.patch = U2BE(data->value.ptr, 2);
    PRINTF("major = %d minor = %d patch = %d\n",
           tlv_extracted->output->not_valid_after.major,
           tlv_extracted->output->not_valid_after.minor,
           tlv_extracted->output->not_valid_after.patch);
    return true;
}

static bool handle_signer_key_id(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint16_t_from_tlv_data(data, &tlv_extracted->signer_key_id);
}

static bool handle_signer_algorithm(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->signer_algo);
}

static bool handle_der_signature(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->input_sig,
                                    DER_SIGNATURE_MIN_SIZE,
                                    DER_SIGNATURE_MAX_SIZE);
}

static bool handle_common(const tlv_data_t *data, tlv_extracted_t *tlv_extracted);

// clang-format off
// List of TLV tags recognized by the Solana application
#define TLV_TAGS(X)                                                                  \
    X(0x01, TAG_STRUCTURE_TYPE,      handle_structure_type,      ENFORCE_UNIQUE_TAG) \
    X(0x02, TAG_VERSION,             handle_version,             ENFORCE_UNIQUE_TAG) \
    X(0x70, TAG_TRUSTED_NAME_TYPE,   handle_trusted_name_type,   ENFORCE_UNIQUE_TAG) \
    X(0x71, TAG_TRUSTED_NAME_SOURCE, handle_trusted_name_source, ENFORCE_UNIQUE_TAG) \
    X(0x20, TAG_TRUSTED_NAME,        handle_trusted_name,        ENFORCE_UNIQUE_TAG) \
    X(0x23, TAG_CHAIN_ID,            handle_chain_id,            ENFORCE_UNIQUE_TAG) \
    X(0x22, TAG_ADDRESS,             handle_address,             ENFORCE_UNIQUE_TAG) \
    X(0x72, TAG_NFT_ID,              handle_nft_id,              ENFORCE_UNIQUE_TAG) \
    X(0x73, TAG_SOURCE_CONTRACT,     handle_source_contract,     ENFORCE_UNIQUE_TAG) \
    X(0x12, TAG_CHALLENGE,           handle_challenge,           ENFORCE_UNIQUE_TAG) \
    X(0x10, TAG_NOT_VALID_AFTER,     handle_not_valid_after,     ENFORCE_UNIQUE_TAG) \
    X(0x13, TAG_SIGNER_KEY_ID,       handle_signer_key_id,       ENFORCE_UNIQUE_TAG) \
    X(0x14, TAG_SIGNER_ALGORITHM,    handle_signer_algorithm,    ENFORCE_UNIQUE_TAG) \
    X(0x15, TAG_DER_SIGNATURE,       handle_der_signature,       ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(TLV_TAGS, &handle_common, parse_tlv_trusted_name)

static bool handle_common(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    if (data->tag != TAG_DER_SIGNATURE) {
        update_multi_hash_ctx(&tlv_extracted->hash_ctx, data->raw);
    }
    return true;
}

static int verify_struct(const tlv_extracted_t *tlv_extracted) {
#ifdef TRUSTED_NAME_TEST_KEY
    uint16_t valid_key_id = TLV_TRUSTED_NAME_SIGNER_KEY_ID_TEST;
#else
    uint16_t valid_key_id = TLV_TRUSTED_NAME_SIGNER_KEY_ID_PROD;
#endif

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, TAG_STRUCTURE_TYPE)) {
        PRINTF("Error: no struct type specified!\n");
        return -1;
    }

    if (tlv_extracted->structure_type != TLV_STRUCTURE_TYPE_TRUSTED_NAME) {
        PRINTF("Error: unexpected struct type %d\n", tlv_extracted->structure_type);
        return -1;
    }

    // Check required fields
    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags,
                                 TAG_VERSION,
                                 TAG_TRUSTED_NAME_TYPE,
                                 TAG_TRUSTED_NAME_SOURCE,
                                 TAG_TRUSTED_NAME,
                                 TAG_CHAIN_ID,
                                 TAG_ADDRESS,
                                 TAG_SIGNER_KEY_ID,
                                 TAG_SIGNER_ALGORITHM,
                                 TAG_DER_SIGNATURE)) {
        PRINTF("Error: missing required fields in struct version 2\n");
        return -1;
    }

    // Forward optional fields to caller application
    tlv_extracted->output->nft_id_received =
        TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, TAG_NFT_ID);
    tlv_extracted->output->source_contract_received =
        TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, TAG_SOURCE_CONTRACT);
    tlv_extracted->output->challenge_received =
        TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, TAG_CHALLENGE);
    tlv_extracted->output->not_valid_after_received =
        TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, TAG_NOT_VALID_AFTER);

    if (tlv_extracted->output->version == 0 || tlv_extracted->output->version > 2) {
        PRINTF("Error: unsupported struct version %d\n", tlv_extracted->output->version);
        return -1;
    }

    if (tlv_extracted->output->source_contract_received && tlv_extracted->output->version < 2) {
        PRINTF("Error: source_contract_received is only supported in v >= 2\n");
        return -1;
    }

    if (tlv_extracted->signer_key_id != valid_key_id) {
        PRINTF("Error: wrong metadata key ID %u\n", tlv_extracted->signer_key_id);
        return -1;
    }

    return 0;
}

static int verify_trusted_name_signature(const tlv_extracted_t *tlv_extracted) {
    // Finalize hash object filled by the parser
    multi_hash_finalized_t multi_hash_finalized;
    if (finalize_hash_for_algo(&tlv_extracted->hash_ctx,
                               tlv_extracted->signer_algo,
                               &multi_hash_finalized) != 0) {
        PRINTF("finalize_hash_for_algo failed\n");
        return -1;
    }

    uint8_t curve;
    if (tlv_extracted->signer_algo == TLV_TRUSTED_NAME_SIGNER_ALGORITHM_EDDSA_SHA3_256 ||
        tlv_extracted->signer_algo == TLV_TRUSTED_NAME_SIGNER_ALGORITHM_EDDSA_KECCAK_256) {
        curve = CX_CURVE_Ed25519;
    } else {
        // ECDSA
        curve = CX_CURVE_SECP256K1;
    }

    // Verify that the signature field of the TLV is the signature of the TLV hash by the key loaded
    // by the PKI
    if (check_signature_with_pubkey(&multi_hash_finalized.hash,
                                    CX_SHA256_SIZE,
                                    CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME,
                                    curve,
                                    tlv_extracted->input_sig) != 0) {
        PRINTF("Failed to verify signature of trusted name info\n");
        return -1;
    }

    return 0;
}

int tlv_use_case_parse_trusted_name_payload(const buffer_t *payload,
                                            tlv_trusted_name_out_t *output) {
    // Main structure that will received the parsed TLV data
    tlv_extracted_t tlv_extracted = {0};
    tlv_extracted.output = output;

    // The parser will fill it with the hash of the whole TLV payload (except SIGN tag)
    init_multi_hash_ctx(&tlv_extracted.hash_ctx);

    // Call the function created by the macro from the TLV lib
    if (!parse_tlv_trusted_name(payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("Failed to parse tlv payload\n");
        return -1;
    }

    // Verify that the fields received are correct in our context
    if (verify_struct(&tlv_extracted) != 0) {
        PRINTF("Failed to verify tlv payload\n");
        return -1;
    }

    // Verify that the fields received are correct in our context
    if (verify_trusted_name_signature(&tlv_extracted) != 0) {
        PRINTF("Failed to verify trusted name signature\n");
        return -1;
    }

    return 0;
}
