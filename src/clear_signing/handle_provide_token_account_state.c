#include <os.h>
#include <cx.h>
#include <stdint.h>
#include <string.h>

#include "handle_provide_token_account_state.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "utils.h"
#include "handle_get_challenge.h"
#include "os_pki.h"
#include "ledger_pki.h"
#include "tlv_library.h"
#include "cs_transaction.h"
#include "cs_token_account_cache.h"

#define TYPE_TOKEN_ACCOUNT_STATE 0x15

typedef struct tlv_out_s {
    TLV_reception_t received_tags;

    uint8_t structure_type;
    uint8_t version;
    uint32_t challenge;
    uint8_t account_address[32];
    uint8_t mint[32];
    uint8_t owner[32];
    uint64_t pre_balance;

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

static bool handle_account_address(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, 32, 32)) {
        return false;
    }
    memcpy(out->account_address, temp.ptr, 32);
    return true;
}

static bool handle_mint(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, 32, 32)) {
        return false;
    }
    memcpy(out->mint, temp.ptr, 32);
    return true;
}

static bool handle_owner(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, 32, 32)) {
        return false;
    }
    memcpy(out->owner, temp.ptr, 32);
    return true;
}

static bool handle_pre_balance(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint64_t_from_tlv_data(data, &out->pre_balance);
}

static bool handle_signature(const tlv_data_t *data, tlv_out_t *out) {
    return get_buffer_from_tlv_data(data,
                                    &out->signature,
                                    CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH,
                                    CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH);
}

static bool handle_common(const tlv_data_t *data, tlv_out_t *out);

// clang-format off
#define TOKEN_ACCOUNT_STATE_TAGS(X) \
    X(0x01, TAS_TAG_STRUCT_TYPE,     handle_structure_type,   ENFORCE_UNIQUE_TAG) \
    X(0x02, TAS_TAG_STRUCT_VERSION,  handle_version,          ENFORCE_UNIQUE_TAG) \
    X(0x12, TAS_TAG_CHALLENGE,       handle_challenge,        ENFORCE_UNIQUE_TAG) \
    X(0x20, TAS_TAG_ACCOUNT_ADDRESS, handle_account_address,  ENFORCE_UNIQUE_TAG) \
    X(0x21, TAS_TAG_MINT,            handle_mint,             ENFORCE_UNIQUE_TAG) \
    X(0x22, TAS_TAG_OWNER,           handle_owner,            ENFORCE_UNIQUE_TAG) \
    X(0x23, TAS_TAG_PRE_BALANCE,     handle_pre_balance,      ENFORCE_UNIQUE_TAG) \
    X(0x15, TAS_TAG_SIGNATURE,       handle_signature,        ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(TOKEN_ACCOUNT_STATE_TAGS, &handle_common, parse_token_account_state)

static bool handle_common(const tlv_data_t *data, tlv_out_t *out) {
    if (data->tag != TAS_TAG_SIGNATURE) {
        CX_ASSERT(cx_hash_update((cx_hash_t *) &out->hash_ctx, data->raw.ptr, data->raw.size));
    }
    return true;
}

int handle_provide_token_account_state(void) {
    PRINTF("handle_provide_token_account_state\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return io_send_sw(state_err);
    }

    tlv_out_t tlv_extracted = {0};
    cx_sha256_init(&tlv_extracted.hash_ctx);

    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    if (!parse_token_account_state(&payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("parse_token_account_state failed\n");
        return io_send_sw(ApduReplySolanaInvalidTokenAccountState);
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags, TAS_TAG_STRUCT_TYPE)) {
        PRINTF("Error: missing struct type\n");
        return io_send_sw(ApduReplySolanaInvalidTokenAccountState);
    }

    if (tlv_extracted.structure_type != TYPE_TOKEN_ACCOUNT_STATE) {
        PRINTF("Error: unexpected struct type 0x%02x\n", tlv_extracted.structure_type);
        return io_send_sw(ApduReplySolanaInvalidTokenAccountState);
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                 TAS_TAG_STRUCT_VERSION,
                                 TAS_TAG_CHALLENGE,
                                 TAS_TAG_ACCOUNT_ADDRESS,
                                 TAS_TAG_MINT,
                                 TAS_TAG_OWNER,
                                 TAS_TAG_PRE_BALANCE,
                                 TAS_TAG_SIGNATURE)) {
        PRINTF("Error: missing required fields\n");
        return io_send_sw(ApduReplySolanaInvalidTokenAccountState);
    }

    if (tlv_extracted.version != 1) {
        PRINTF("Error: unsupported version %d\n", tlv_extracted.version);
        return io_send_sw(ApduReplySolanaInvalidTokenAccountState);
    }

    if (tlv_extracted.challenge != get_challenge()) {
        PRINTF("Error: challenge mismatch %u != %u\n", tlv_extracted.challenge, get_challenge());
        return io_send_sw(ApduReplySolanaInvalidTokenAccountState);
    }

    // Finalize hash and verify signature
    uint8_t tlv_hash[CX_SHA256_SIZE] = {0};
    CX_ASSERT(cx_hash_final((cx_hash_t *) &tlv_extracted.hash_ctx, tlv_hash));
    buffer_t hash = {.ptr = tlv_hash, .size = sizeof(tlv_hash)};

    // TODO: Use correct key usage once determined (reusing SWAP_TEMPLATE for development)
    uint8_t expected_key_usage = CERTIFICATE_PUBLIC_KEY_USAGE_SWAP_TEMPLATE;
    cx_curve_t curve = CX_CURVE_SECP256K1;
    check_signature_with_pki_status_t err =
        check_signature_with_pki(hash, &expected_key_usage, &curve, tlv_extracted.signature);
    if (err != CHECK_SIGNATURE_WITH_PKI_SUCCESS) {
        PRINTF("Error: signature verification failed (%d)\n", err);
        return io_send_sw(ApduReplySolanaInvalidTokenAccountState);
    }

    // Consume the challenge to prevent replay
    roll_challenge();

    PRINTF("=== TOKEN ACCOUNT STATE ===\n");
    PRINTF("version         = %d\n", tlv_extracted.version);
    PRINTF("account_address = %.*H\n", 32, tlv_extracted.account_address);
    PRINTF("mint            = %.*H\n", 32, tlv_extracted.mint);
    PRINTF("owner           = %.*H\n", 32, tlv_extracted.owner);
    PRINTF("pre_balance     = %llu\n", tlv_extracted.pre_balance);

    if (cs_token_account_cache_add(tlv_extracted.account_address,
                                   tlv_extracted.mint,
                                   tlv_extracted.owner,
                                   tlv_extracted.pre_balance) != 0) {
        PRINTF("Error: cs_token_account_cache_add rejected account\n");
        return io_send_sw(ApduReplySolanaInvalidTokenAccountState);
    }

    return io_send_sw(ApduReplySuccess);
}
