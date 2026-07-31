#include <os.h>
#include <cx.h>
#include <stdint.h>
#include <string.h>

#include "handle_provide_instruction_info.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "utils.h"
#include "os_pki.h"
#include "ledger_pki.h"
#include "tlv_library.h"
#include "tlv_parser_cs_value.h"
#include "cs_instruction_template.h"
#include "reply.h"
#include "sol/pubkey.h"

typedef struct tlv_out_s {
    TLV_reception_t received_tags;

    uint8_t version;
    uint8_t program_id[PUBKEY_SIZE];
    // Views into G_command.message, copied into the template's heap buffers at open time.
    buffer_t discriminator;
    buffer_t operation_type;
    buffer_t program_name;
    uint8_t substructures_hash[CX_SHA256_SIZE];
    buffer_t idl_type_pool;
    uint8_t idl_root_type;
    uint8_t mint_assoc_account;
    uint8_t mint_assoc_mint;
    uint8_t owner_assoc_account;
    // OWNER_ASSOC_OWNER is a VALUE sub-TLV
    cs_value_t owner_assoc_owner;
    bool owner_assoc_owner_parsed;

    cx_sha256_t hash_ctx;
    buffer_t signature;
} tlv_out_t;

static bool handle_version(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->version);
}

static bool handle_program_id(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, PUBKEY_SIZE, PUBKEY_SIZE)) {
        return false;
    }
    memcpy(out->program_id, temp.ptr, PUBKEY_SIZE);
    return true;
}

static bool handle_discriminator(const tlv_data_t *data, tlv_out_t *out) {
    return get_buffer_from_tlv_data(data, &out->discriminator, 0, G_command.message_length);
}

static bool handle_operation_type(const tlv_data_t *data, tlv_out_t *out) {
    return get_buffer_from_tlv_data(data, &out->operation_type, 1, G_command.message_length);
}

static bool handle_program_name(const tlv_data_t *data, tlv_out_t *out) {
    return get_buffer_from_tlv_data(data, &out->program_name, 0, G_command.message_length);
}

static bool handle_substructures_hash(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, CX_SHA256_SIZE, CX_SHA256_SIZE)) {
        return false;
    }
    memcpy(out->substructures_hash, temp.ptr, CX_SHA256_SIZE);
    return true;
}

static bool handle_idl_type_pool(const tlv_data_t *data, tlv_out_t *out) {
    // No copy: keep a view into the message, bounded by the bytes actually received.
    return get_buffer_from_tlv_data(data, &out->idl_type_pool, 1, G_command.message_length);
}

static bool handle_idl_root_type(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->idl_root_type);
}

static bool handle_mint_assoc_account(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->mint_assoc_account);
}

static bool handle_mint_assoc_mint(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->mint_assoc_mint);
}

static bool handle_owner_assoc_account(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->owner_assoc_account);
}

static bool handle_owner_assoc_owner(const tlv_data_t *data, tlv_out_t *out) {
    // OWNER_ASSOC_OWNER is a VALUE sub-TLV
    if (!cs_parse_value_from_buffer(data->value.ptr, data->value.size, &out->owner_assoc_owner)) {
        PRINTF("Error: failed to parse OWNER_ASSOC_OWNER VALUE sub-TLV\n");
        return false;
    }
    out->owner_assoc_owner_parsed = true;
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
#define INSTRUCTION_INFO_TAGS(X) \
    X(0x00, II_TAG_VERSION,             handle_version,             ENFORCE_UNIQUE_TAG) \
    X(0x01, II_TAG_PROGRAM_ID,          handle_program_id,          ENFORCE_UNIQUE_TAG) \
    X(0x02, II_TAG_DISCRIMINATOR,       handle_discriminator,       ENFORCE_UNIQUE_TAG) \
    X(0x03, II_TAG_OPERATION_TYPE,      handle_operation_type,      ENFORCE_UNIQUE_TAG) \
    X(0x04, II_TAG_PROGRAM_NAME,        handle_program_name,        ENFORCE_UNIQUE_TAG) \
    X(0x05, II_TAG_SUBSTRUCTURES_HASH,  handle_substructures_hash,  ENFORCE_UNIQUE_TAG) \
    X(0x06, II_TAG_IDL_TYPE_POOL,       handle_idl_type_pool,       ENFORCE_UNIQUE_TAG) \
    X(0x07, II_TAG_IDL_ROOT_TYPE,       handle_idl_root_type,       ENFORCE_UNIQUE_TAG) \
    X(0x08, II_TAG_MINT_ASSOC_ACCOUNT,  handle_mint_assoc_account,  ENFORCE_UNIQUE_TAG) \
    X(0x09, II_TAG_MINT_ASSOC_MINT,     handle_mint_assoc_mint,     ENFORCE_UNIQUE_TAG) \
    X(0x0A, II_TAG_OWNER_ASSOC_ACCOUNT, handle_owner_assoc_account, ENFORCE_UNIQUE_TAG) \
    X(0x0B, II_TAG_OWNER_ASSOC_OWNER,   handle_owner_assoc_owner,   ENFORCE_UNIQUE_TAG) \
    X(0x15, II_TAG_SIGNATURE,           handle_signature,           ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(INSTRUCTION_INFO_TAGS, &handle_common, parse_instruction_info)

static bool handle_common(const tlv_data_t *data, tlv_out_t *out) {
    if (data->tag != II_TAG_SIGNATURE) {
        CX_ASSERT(cx_hash_update((cx_hash_t *) &out->hash_ctx, data->raw.ptr, data->raw.size));
    }
    return true;
}

int handle_provide_instruction_info(void) {
    PRINTF("handle_provide_instruction_info\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return reply_sw(state_err);
    }

    tlv_out_t tlv_extracted = {0};
    cx_sha256_init(&tlv_extracted.hash_ctx);

    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    if (!parse_instruction_info(&payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("parse_instruction_info failed\n");
        return reply_sw(ApduReplySolanaInvalidInstructionInfo);
    }

    // Check required fields
    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                 II_TAG_VERSION,
                                 II_TAG_PROGRAM_ID,
                                 II_TAG_DISCRIMINATOR,
                                 II_TAG_OPERATION_TYPE,
                                 II_TAG_SUBSTRUCTURES_HASH,
                                 II_TAG_IDL_TYPE_POOL,
                                 II_TAG_IDL_ROOT_TYPE,
                                 II_TAG_SIGNATURE)) {
        PRINTF("Error: missing required fields\n");
        return reply_sw(ApduReplySolanaInvalidInstructionInfo);
    }

    if (tlv_extracted.version != 1) {
        PRINTF("Error: unsupported version %d\n", tlv_extracted.version);
        return reply_sw(ApduReplySolanaInvalidInstructionInfo);
    }

    if (tlv_extracted.discriminator.size > CS_DISCRIMINATOR_MAX_SIZE) {
        PRINTF("Error: discriminator is %d bytes, spec allows %d\n",
               tlv_extracted.discriminator.size,
               CS_DISCRIMINATOR_MAX_SIZE);
        return reply_sw(ApduReplySolanaInvalidInstructionInfo);
    }

    // MINT_ASSOC_ACCOUNT and MINT_ASSOC_MINT must both be present or both absent
    bool has_mint_account = TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                                    II_TAG_MINT_ASSOC_ACCOUNT);
    bool has_mint_mint = TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                                 II_TAG_MINT_ASSOC_MINT);
    if (has_mint_account != has_mint_mint) {
        PRINTF("Error: MINT_ASSOC_ACCOUNT and MINT_ASSOC_MINT must both be present or absent\n");
        return reply_sw(ApduReplySolanaInvalidInstructionInfo);
    }

    // OWNER_ASSOC_ACCOUNT and OWNER_ASSOC_OWNER must both be present or both absent
    bool has_owner_account = TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                                     II_TAG_OWNER_ASSOC_ACCOUNT);
    bool has_owner_owner = TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                                   II_TAG_OWNER_ASSOC_OWNER);
    if (has_owner_account != has_owner_owner) {
        PRINTF("Error: OWNER_ASSOC_ACCOUNT and OWNER_ASSOC_OWNER must both be present or absent\n");
        return reply_sw(ApduReplySolanaInvalidInstructionInfo);
    }

    // Finalize hash and verify signature
    uint8_t tlv_hash[CX_SHA256_SIZE] = {0};
    CX_ASSERT(cx_hash_final((cx_hash_t *) &tlv_extracted.hash_ctx, tlv_hash));
    buffer_t hash = {.ptr = tlv_hash, .size = sizeof(tlv_hash)};

    uint8_t expected_key_usage = CERTIFICATE_PUBLIC_KEY_USAGE_CALLDATA;
    cx_curve_t curve = CX_CURVE_SECP256K1;
    check_signature_with_pki_status_t err = check_signature_with_pki(hash,
                                                                     &expected_key_usage,
                                                                     &curve,
                                                                     tlv_extracted.signature);
    if (err != CHECK_SIGNATURE_WITH_PKI_SUCCESS) {
        PRINTF("Error: signature verification failed (%d)\n", err);
        return reply_sw(ApduReplySolanaInvalidInstructionInfo);
    }

    PRINTF("=== INSTRUCTION INFO ===\n");
    PRINTF("version            = %d\n", tlv_extracted.version);
    PRINTF("program_id         = %.*H\n", PUBKEY_SIZE, tlv_extracted.program_id);
    PRINTF("discriminator      = %.*H\n",
           tlv_extracted.discriminator.size,
           tlv_extracted.discriminator.ptr);
    PRINTF("operation_type     = %.*s\n",
           (int) tlv_extracted.operation_type.size,
           tlv_extracted.operation_type.ptr);
    PRINTF("program_name       = %.*s\n",
           (int) tlv_extracted.program_name.size,
           tlv_extracted.program_name.ptr);
    PRINTF("substructures_hash = %.*H\n", CX_SHA256_SIZE, tlv_extracted.substructures_hash);
    PRINTF("idl_type_pool_size = %d\n", (int) tlv_extracted.idl_type_pool.size);
    PRINTF("idl_root_type      = %d\n", tlv_extracted.idl_root_type);

    // A SIGN MESSAGE GENERIC PREVIEW (0x0A) must have opened the context first.
    cs_instruction_template_t *template = cs_instruction_template_open(
        tlv_extracted.substructures_hash);
    if (template == NULL) {
        PRINTF("Error: no clear-signing context or template capacity exhausted\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }

    memcpy(template->program_id, tlv_extracted.program_id, sizeof(template->program_id));
    if (cs_instruction_template_set_discriminator(tlv_extracted.discriminator.ptr,
                                                  tlv_extracted.discriminator.size) != 0) {
        PRINTF("Error: failed to store discriminator\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (cs_instruction_template_set_operation_type((const char *) tlv_extracted.operation_type.ptr,
                                                   tlv_extracted.operation_type.size) != 0) {
        PRINTF("Error: failed to store operation type\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }
    // PROGRAM_NAME is optional; when absent the header shows the program address.
    if (tlv_extracted.program_name.size > 0) {
        if (cs_instruction_template_set_program_name((const char *) tlv_extracted.program_name.ptr,
                                                     tlv_extracted.program_name.size) != 0) {
            PRINTF("Error: failed to store program name\n");
            return reply_sw(ApduReplySolanaClearSigningIncomplete);
        }
    }
    if (cs_instruction_template_set_idl_type_pool(tlv_extracted.idl_type_pool.ptr,
                                                  tlv_extracted.idl_type_pool.size) != 0) {
        PRINTF("Error: failed to store IDL type pool\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }
    template->idl_root_type = tlv_extracted.idl_root_type;

    if (has_mint_account) {
        if (cs_instruction_template_set_mint_assoc(tlv_extracted.mint_assoc_account,
                                                   tlv_extracted.mint_assoc_mint) != 0) {
            PRINTF("Error: failed to set mint association\n");
            return reply_sw(ApduReplySolanaInvalidInstructionInfo);
        }
    }

    if (has_owner_account) {
        if (cs_instruction_template_set_owner_assoc(tlv_extracted.owner_assoc_account,
                                                    tlv_extracted.owner_assoc_owner.source,
                                                    tlv_extracted.owner_assoc_owner.payload.ptr,
                                                    tlv_extracted.owner_assoc_owner.payload.size) !=
            0) {
            PRINTF("Error: failed to set owner association\n");
            return reply_sw(ApduReplySolanaInvalidInstructionInfo);
        }
    }

    return reply_sw(ApduReplySuccess);
}
