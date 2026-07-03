#include <os.h>
#include <cx.h>
#include <stdint.h>
#include <string.h>

#include "handle_provide_enum_variant.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "utils.h"
#include "os_pki.h"
#include "ledger_pki.h"
#include "tlv_library.h"
#include "cs_transaction.h"
#include "cs_enum_cache.h"

#define TYPE_ENUM_VARIANT       0x17
#define MAX_ENUM_ID_LENGTH      64
#define MAX_VARIANT_NAME_LENGTH 64
#define MAX_PAYLOAD_LENGTH      255

typedef struct tlv_out_s {
    TLV_reception_t received_tags;

    uint8_t structure_type;
    uint8_t version;
    uint8_t program_id[32];
    char enum_id[MAX_ENUM_ID_LENGTH + 1];
    uint16_t variant_index;
    char variant_name[MAX_VARIANT_NAME_LENGTH + 1];
    uint8_t payload_kind;
    uint8_t payload[MAX_PAYLOAD_LENGTH];
    size_t payload_size;

    cx_sha256_t hash_ctx;
    buffer_t signature;
} tlv_out_t;

static bool handle_structure_type(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->structure_type);
}

static bool handle_version(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->version);
}

static bool handle_program_id(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, 32, 32)) {
        return false;
    }
    memcpy(out->program_id, temp.ptr, 32);
    return true;
}

static bool handle_enum_id(const tlv_data_t *data, tlv_out_t *out) {
    return get_string_from_tlv_data(data, out->enum_id, 1, sizeof(out->enum_id));
}

static bool handle_variant_index(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint16_t_from_tlv_data(data, &out->variant_index);
}

static bool handle_variant_name(const tlv_data_t *data, tlv_out_t *out) {
    return get_string_from_tlv_data(data, out->variant_name, 1, sizeof(out->variant_name));
}

static bool handle_payload_kind(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->payload_kind);
}

static bool handle_payload(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, 0, MAX_PAYLOAD_LENGTH)) {
        return false;
    }
    out->payload_size = temp.size;
    if (temp.size > 0) {
        memcpy(out->payload, temp.ptr, temp.size);
    }
    return true;
}

static bool handle_signature(const tlv_data_t *data, tlv_out_t *out) {
    return get_buffer_from_tlv_data(data,
                                    &out->signature,
                                    CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH,
                                    CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH);
}

static bool handle_common(const tlv_data_t *data, tlv_out_t *out);

// clang-format off
#define ENUM_VARIANT_TAGS(X) \
    X(0x01, EV_TAG_STRUCT_TYPE,    handle_structure_type, ENFORCE_UNIQUE_TAG) \
    X(0x02, EV_TAG_STRUCT_VERSION, handle_version,        ENFORCE_UNIQUE_TAG) \
    X(0x20, EV_TAG_PROGRAM_ID,     handle_program_id,     ENFORCE_UNIQUE_TAG) \
    X(0x21, EV_TAG_ENUM_ID,        handle_enum_id,        ENFORCE_UNIQUE_TAG) \
    X(0x22, EV_TAG_VARIANT_INDEX,  handle_variant_index,  ENFORCE_UNIQUE_TAG) \
    X(0x23, EV_TAG_VARIANT_NAME,   handle_variant_name,   ENFORCE_UNIQUE_TAG) \
    X(0x24, EV_TAG_PAYLOAD_KIND,   handle_payload_kind,   ENFORCE_UNIQUE_TAG) \
    X(0x25, EV_TAG_PAYLOAD,        handle_payload,        ENFORCE_UNIQUE_TAG) \
    X(0x15, EV_TAG_SIGNATURE,      handle_signature,      ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(ENUM_VARIANT_TAGS, &handle_common, parse_enum_variant)

static bool handle_common(const tlv_data_t *data, tlv_out_t *out) {
    if (data->tag != EV_TAG_SIGNATURE) {
        CX_ASSERT(cx_hash_update((cx_hash_t *) &out->hash_ctx, data->raw.ptr, data->raw.size));
    }
    return true;
}

// Validate PAYLOAD_KIND / PAYLOAD coherence
static bool validate_payload_kind(const tlv_out_t *tlv_extracted) {
    switch (tlv_extracted->payload_kind) {
        case CS_VARIANT_PAYLOAD_EMPTY:
            if (TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, EV_TAG_PAYLOAD)) {
                PRINTF("Error: PAYLOAD present for EMPTY payload_kind\n");
                return false;
            }
            break;
        case CS_VARIANT_PAYLOAD_INLINE:
            if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, EV_TAG_PAYLOAD)) {
                PRINTF("Error: PAYLOAD missing for INLINE payload_kind\n");
                return false;
            }
            break;
        case CS_VARIANT_PAYLOAD_RAW_SIZE:
            if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, EV_TAG_PAYLOAD)) {
                PRINTF("Error: PAYLOAD missing for RAW_SIZE payload_kind\n");
                return false;
            }
            if (tlv_extracted->payload_size != 2) {
                PRINTF("Error: RAW_SIZE payload must be 2 bytes, got %d\n",
                       tlv_extracted->payload_size);
                return false;
            }
            break;
        default:
            PRINTF("Error: unknown payload_kind 0x%02x\n", tlv_extracted->payload_kind);
            return false;
    }
    return true;
}

int handle_provide_enum_variant(void) {
    PRINTF("handle_provide_enum_variant\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return io_send_sw(state_err);
    }

    tlv_out_t tlv_extracted = {0};
    cx_sha256_init(&tlv_extracted.hash_ctx);

    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    if (!parse_enum_variant(&payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("parse_enum_variant failed\n");
        return io_send_sw(ApduReplySolanaInvalidEnumVariant);
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags, EV_TAG_STRUCT_TYPE)) {
        PRINTF("Error: missing struct type\n");
        return io_send_sw(ApduReplySolanaInvalidEnumVariant);
    }

    if (tlv_extracted.structure_type != TYPE_ENUM_VARIANT) {
        PRINTF("Error: unexpected struct type 0x%02x\n", tlv_extracted.structure_type);
        return io_send_sw(ApduReplySolanaInvalidEnumVariant);
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                 EV_TAG_STRUCT_VERSION,
                                 EV_TAG_PROGRAM_ID,
                                 EV_TAG_ENUM_ID,
                                 EV_TAG_VARIANT_INDEX,
                                 EV_TAG_VARIANT_NAME,
                                 EV_TAG_PAYLOAD_KIND,
                                 EV_TAG_SIGNATURE)) {
        PRINTF("Error: missing required fields\n");
        return io_send_sw(ApduReplySolanaInvalidEnumVariant);
    }

    if (tlv_extracted.version != 1) {
        PRINTF("Error: unsupported version %d\n", tlv_extracted.version);
        return io_send_sw(ApduReplySolanaInvalidEnumVariant);
    }

    if (!validate_payload_kind(&tlv_extracted)) {
        return io_send_sw(ApduReplySolanaInvalidEnumVariant);
    }

    // Finalize hash and verify signature
    uint8_t tlv_hash[CX_SHA256_SIZE] = {0};
    CX_ASSERT(cx_hash_final((cx_hash_t *) &tlv_extracted.hash_ctx, tlv_hash));
    buffer_t hash = {.ptr = tlv_hash, .size = sizeof(tlv_hash)};

    uint8_t expected_key_usage = CERTIFICATE_PUBLIC_KEY_USAGE_CALLDATA;
    cx_curve_t curve = CX_CURVE_SECP256K1;
    check_signature_with_pki_status_t err =
        check_signature_with_pki(hash, &expected_key_usage, &curve, tlv_extracted.signature);
    if (err != CHECK_SIGNATURE_WITH_PKI_SUCCESS) {
        PRINTF("Error: signature verification failed (%d)\n", err);
        return io_send_sw(ApduReplySolanaInvalidEnumVariant);
    }

    PRINTF("=== ENUM VARIANT ===\n");
    PRINTF("version       = %d\n", tlv_extracted.version);
    PRINTF("program_id    = %.*H\n", 32, tlv_extracted.program_id);
    PRINTF("enum_id       = %s\n", tlv_extracted.enum_id);
    PRINTF("variant_index = %d\n", tlv_extracted.variant_index);
    PRINTF("variant_name  = %s\n", tlv_extracted.variant_name);
    PRINTF("payload_kind  = 0x%02x\n", tlv_extracted.payload_kind);

    if (cs_enum_cache_add(tlv_extracted.program_id,
                          (const uint8_t *) tlv_extracted.enum_id,
                          strlen(tlv_extracted.enum_id),
                          tlv_extracted.variant_index,
                          tlv_extracted.variant_name,
                          tlv_extracted.payload_kind,
                          tlv_extracted.payload,
                          tlv_extracted.payload_size) != 0) {
        PRINTF("Error: cs_enum_cache_add rejected variant %d\n", tlv_extracted.variant_index);
        return io_send_sw(ApduReplySolanaInvalidEnumVariant);
    }

    return io_send_sw(ApduReplySuccess);
}
