#include <os.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "cx.h"
#include "os_pki.h"
#include "ledger_pki.h"
#include "tlv_use_case_dynamic_descriptor.h"

#define TYPE_DYNAMIC_TOKEN 0x90

// Parsed TLV data
typedef struct tlv_extracted_s {
    // Received tags set by the parser
    TLV_reception_t received_tags;

    // Dynamic descriptor output data
    tlv_dynamic_descriptor_out_t *output;

    // Tags handled by the use case API and not the caller
    uint8_t structure_type;
    char application_name[BOLOS_APPNAME_MAX_SIZE_B + 1];

    buffer_t input_sig;

    // Progressive hash of the received TLVs (except the signature type)
    cx_sha256_t hash_ctx;
} tlv_extracted_t;

static bool handle_structure_type(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->structure_type);
}

static bool handle_version(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->output->version);
}

static bool handle_coin_type(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint32_t_from_tlv_data(data, &tlv_extracted->output->coin_type);
}

static bool handle_application_name(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_string_from_tlv_data(data,
                                    tlv_extracted->application_name,
                                    1,
                                    sizeof(tlv_extracted->application_name));
}

static bool handle_ticker(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_string_from_tlv_data(data,
                                    tlv_extracted->output->ticker,
                                    1,
                                    sizeof(tlv_extracted->output->ticker));
}

static bool handle_magnitude(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->output->magnitude);
}

static bool handle_tuid(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data, &tlv_extracted->output->TUID, 0, 0);
}

static bool handle_signature(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_extracted->input_sig,
                                    DER_SIGNATURE_MIN_SIZE,
                                    DER_SIGNATURE_MAX_SIZE);
}

static bool handle_common(const tlv_data_t *data, tlv_extracted_t *tlv_extracted);

// clang-format off
// List of TLV tags recognized by the Solana application
#define TLV_TAGS(X)                                                            \
    X(0x01, TAG_STRUCTURE_TYPE,   handle_structure_type,   ENFORCE_UNIQUE_TAG) \
    X(0x02, TAG_VERSION,          handle_version,          ENFORCE_UNIQUE_TAG) \
    X(0x03, TAG_COIN_TYPE,        handle_coin_type,        ENFORCE_UNIQUE_TAG) \
    X(0x04, TAG_APPLICATION_NAME, handle_application_name, ENFORCE_UNIQUE_TAG) \
    X(0x05, TAG_TICKER,           handle_ticker,           ENFORCE_UNIQUE_TAG) \
    X(0x06, TAG_MAGNITUDE,        handle_magnitude,        ENFORCE_UNIQUE_TAG) \
    X(0x07, TAG_TUID,             handle_tuid,             ENFORCE_UNIQUE_TAG) \
    X(0x08, TAG_SIGNATURE,        handle_signature,        ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(TLV_TAGS, &handle_common, parse_dynamic_token_tag)

static bool handle_common(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    if (data->tag != TAG_SIGNATURE) {
        CX_ASSERT(
            cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw.ptr, data->raw.size));
    }
    return true;
}

tlv_dynamic_descriptor_status_t tlv_use_case_dynamic_descriptor(const buffer_t *payload,
                                                                tlv_dynamic_descriptor_out_t *out) {
    // Parser output
    tlv_extracted_t tlv_extracted = {0};
    tlv_extracted.output = out;

    // The parser will fill it with the hash of the whole TLV payload (except SIGN tag)
    cx_sha256_init(&tlv_extracted.hash_ctx);

    // Call the function created by the macro from the TLV lib
    if (!parse_dynamic_token_tag(payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("Failed to parse tlv payload\n");
        return TLV_DYNAMIC_DESCRIPTOR_PARSING_ERROR;
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags, TAG_STRUCTURE_TYPE)) {
        PRINTF("Error: no struct type specified!\n");
        return TLV_DYNAMIC_DESCRIPTOR_MISSING_STRUCTURE_TAG;
    }

    if (tlv_extracted.structure_type != TYPE_DYNAMIC_TOKEN) {
        PRINTF("Error: unexpected struct type %d\n", tlv_extracted.structure_type);
        return TLV_DYNAMIC_DESCRIPTOR_WRONG_TYPE;
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                 TAG_VERSION,
                                 TAG_COIN_TYPE,
                                 TAG_APPLICATION_NAME,
                                 TAG_TICKER,
                                 TAG_MAGNITUDE,
                                 TAG_TUID,
                                 TAG_SIGNATURE)) {
        PRINTF("Error: missing required fields in struct version 1\n");
        return TLV_DYNAMIC_DESCRIPTOR_MISSING_TAG;
    }

    if (strcmp(tlv_extracted.application_name, APPNAME) != 0) {
        PRINTF("Error: unsupported application name %s\n", tlv_extracted.application_name);
        return TLV_DYNAMIC_DESCRIPTOR_WRONG_APPLICATION_NAME;
    }

    if (tlv_extracted.output->version == 0 || tlv_extracted.output->version > 1) {
        PRINTF("Error: unsupported struct version %d\n", tlv_extracted.output->version);
        return TLV_DYNAMIC_DESCRIPTOR_UNKNOWN_VERSION;
    }

    // Finalize hash object filled by the parser
    uint8_t tlv_hash[CX_SHA256_SIZE] = {0};
    CX_ASSERT(cx_hash_final((cx_hash_t *) &tlv_extracted.hash_ctx, tlv_hash));
    buffer_t hash = {.ptr = tlv_hash, .size = sizeof(tlv_hash)};

    // Verify that the signature field of the TLV is the signature of the TLV hash by the key loaded
    // by the PKI
    check_signature_with_pki_status_t err;
    err = check_signature_with_pki(hash,
                                   CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META,
                                   CX_CURVE_SECP256K1,
                                   tlv_extracted.input_sig);
    if (err != CHECK_SIGNATURE_WITH_PKI_SUCCESS) {
        PRINTF("Failed to verify signature of dynamic token info\n");
        return TLV_DYNAMIC_DESCRIPTOR_SIGNATURE_ERROR | err;
    }

    return TLV_DYNAMIC_DESCRIPTOR_SUCCESS;
}
