#include <os.h>
#include <cx.h>
#include <stdint.h>
#include <string.h>

#include "handle_provide_alt_resolution.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "utils.h"
#include "handle_get_challenge.h"
#include "os_pki.h"
#include "ledger_pki.h"
#include "tlv_library.h"
#include "cs_transaction.h"
#include "cs_alt_cache.h"
#include "reply.h"
#include "sol/pubkey.h"

#define TYPE_ALT_RESOLUTION 0x16

typedef struct tlv_out_s {
    TLV_reception_t received_tags;

    uint8_t structure_type;
    uint8_t version;
    uint32_t challenge;
    uint8_t alt_address[PUBKEY_SIZE];
    uint8_t entry_index;
    uint8_t resolved_address[PUBKEY_SIZE];

    cx_sha256_t hash_ctx;
    buffer_t signature;
} tlv_out_t;

static bool handle_structure_type(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->structure_type);
}

static bool handle_version(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->version);
}

static bool handle_challenge(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint32_t_from_tlv_data(data, &out->challenge);
}

static bool handle_alt_address(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, PUBKEY_SIZE, PUBKEY_SIZE)) {
        return false;
    }
    memcpy(out->alt_address, temp.ptr, PUBKEY_SIZE);
    return true;
}

static bool handle_entry_index(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->entry_index);
}

static bool handle_resolved_address(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, PUBKEY_SIZE, PUBKEY_SIZE)) {
        return false;
    }
    memcpy(out->resolved_address, temp.ptr, PUBKEY_SIZE);
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
#define ALT_RESOLUTION_TAGS(X) \
    X(0x01, ALT_TAG_STRUCT_TYPE,      handle_structure_type,   ENFORCE_UNIQUE_TAG) \
    X(0x02, ALT_TAG_STRUCT_VERSION,   handle_version,          ENFORCE_UNIQUE_TAG) \
    X(0x12, ALT_TAG_CHALLENGE,        handle_challenge,        ENFORCE_UNIQUE_TAG) \
    X(0x20, ALT_TAG_ALT_ADDRESS,      handle_alt_address,      ENFORCE_UNIQUE_TAG) \
    X(0x21, ALT_TAG_ENTRY_INDEX,      handle_entry_index,      ENFORCE_UNIQUE_TAG) \
    X(0x22, ALT_TAG_RESOLVED_ADDRESS, handle_resolved_address, ENFORCE_UNIQUE_TAG) \
    X(0x15, ALT_TAG_SIGNATURE,        handle_signature,        ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(ALT_RESOLUTION_TAGS, &handle_common, parse_alt_resolution)

static bool handle_common(const tlv_data_t *data, tlv_out_t *out) {
    if (data->tag != ALT_TAG_SIGNATURE) {
        CX_ASSERT(cx_hash_update((cx_hash_t *) &out->hash_ctx, data->raw.ptr, data->raw.size));
    }
    return true;
}

int handle_provide_alt_resolution(void) {
    PRINTF("handle_provide_alt_resolution\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return reply_sw(state_err);
    }

    tlv_out_t tlv_extracted = {0};
    cx_sha256_init(&tlv_extracted.hash_ctx);

    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    if (!parse_alt_resolution(&payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("parse_alt_resolution failed\n");
        return reply_sw(ApduReplySolanaInvalidAltResolution);
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags, ALT_TAG_STRUCT_TYPE)) {
        PRINTF("Error: missing struct type\n");
        return reply_sw(ApduReplySolanaInvalidAltResolution);
    }

    if (tlv_extracted.structure_type != TYPE_ALT_RESOLUTION) {
        PRINTF("Error: unexpected struct type 0x%02x\n", tlv_extracted.structure_type);
        return reply_sw(ApduReplySolanaInvalidAltResolution);
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                 ALT_TAG_STRUCT_VERSION,
                                 ALT_TAG_CHALLENGE,
                                 ALT_TAG_ALT_ADDRESS,
                                 ALT_TAG_ENTRY_INDEX,
                                 ALT_TAG_RESOLVED_ADDRESS,
                                 ALT_TAG_SIGNATURE)) {
        PRINTF("Error: missing required fields\n");
        return reply_sw(ApduReplySolanaInvalidAltResolution);
    }

    if (tlv_extracted.version != 1) {
        PRINTF("Error: unsupported version %d\n", tlv_extracted.version);
        return reply_sw(ApduReplySolanaInvalidAltResolution);
    }

    if (tlv_extracted.challenge != get_challenge()) {
        PRINTF("Error: challenge mismatch %u != %u\n", tlv_extracted.challenge, get_challenge());
        return reply_sw(ApduReplySolanaInvalidAltResolution);
    }

    // Finalize hash and verify signature
    uint8_t tlv_hash[CX_SHA256_SIZE] = {0};
    CX_ASSERT(cx_hash_final((cx_hash_t *) &tlv_extracted.hash_ctx, tlv_hash));
    buffer_t hash = {.ptr = tlv_hash, .size = sizeof(tlv_hash)};

    uint8_t expected_key_usage = CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME;
    cx_curve_t curve = CX_CURVE_SECP256K1;
    check_signature_with_pki_status_t err =
        check_signature_with_pki(hash, &expected_key_usage, &curve, tlv_extracted.signature);
    if (err != CHECK_SIGNATURE_WITH_PKI_SUCCESS) {
        PRINTF("Error: signature verification failed (%d)\n", err);
        return reply_sw(ApduReplySolanaInvalidAltResolution);
    }

    // Consume the challenge to prevent replay
    roll_challenge();

    PRINTF("=== ALT RESOLUTION ===\n");
    PRINTF("version          = %d\n", tlv_extracted.version);
    PRINTF("alt_address      = %.*H\n", PUBKEY_SIZE, tlv_extracted.alt_address);
    PRINTF("entry_index      = %d\n", tlv_extracted.entry_index);
    PRINTF("resolved_address = %.*H\n", PUBKEY_SIZE, tlv_extracted.resolved_address);

    if (cs_alt_cache_add(tlv_extracted.alt_address,
                         tlv_extracted.entry_index,
                         tlv_extracted.resolved_address) != 0) {
        PRINTF("Error: ALT resolution cache rejected entry (full or duplicate)\n");
        return reply_sw(ApduReplySolanaInvalidAltResolution);
    }

    return reply_sw(ApduReplySuccess);
}
