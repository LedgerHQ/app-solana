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

#include "handle_provide_dynamic_descriptor.h"

#define SOLANA_SLIP_44_VALUE 501

// https://ledgerhq.atlassian.net/wiki/spaces/~624b62984fe01d006ba98a93/pages/5603262535/Token+Dynamic+Descriptor#Solana
typedef enum solana_token_type_e {
    TOKEN_LEGACY = 0x00,
    TOKEN_2022 = 0x01,
} solana_token_type_t;

typedef enum extension_code_value_e {
    MINT_CLOSE_AUTHORITY = 0X00,
    TRANSFER_FEES = 0X01,
    DEFAULT_ACCOUNT_STATE = 0X02,
    IMMUTABLE_OWNER = 0X03,
    NON_TRANSFERABLE_TOKENS = 0X04,
    REQUIRED_MEMO_ON_TRANSFER = 0X05,
    REALLOCATE = 0X06,
    INTEREST_BEARING_TOKENS = 0X07,
    PERMANENT_DELEGATE = 0X08,
    CPI_GUARD = 0X09,
    TRANSFER_HOOK = 0X0A,
    METADATA_POINTER = 0X0B,
    METADATA = 0X0C,
    GROUP_POINTER = 0X0D,
    GROUP = 0X0E,
    MEMBER_POINTER = 0X0F,
    MEMBER = 0X10,
    // This works currently as all previous enum values are set and contiguous
    EXTENSION_CODE_VALUE_COUNT,
} extension_code_value_t;

#define TYPE_DYNAMIC_TOKEN 0x90

dynamic_token_info_t g_dynamic_token_info;

static void trusted_info_reset(dynamic_token_info_t *dynamic_token_info) {
    explicit_bzero(dynamic_token_info, sizeof(*dynamic_token_info));
}

typedef struct tlv_TUID_data_s {
    TLV_reception_t received_tags;

    solana_token_type_t token_type;
    buffer_t encoded_mint_address;
    buffer_t extensions;
} tlv_TUID_data_t;

// Parsed TLV data
typedef struct tlv_extracted_s {
    // Received tags set by the parser
    // We will use the same structure for both the dynamic token AND the TUID reception as the tags
    // do not collide
    TLV_reception_t received_tags;

    // Trusted name output data
    uint8_t structure_type;
    uint8_t version;

    uint32_t coin_type;
    // 0 copy is inconvenient for strings because they are not '\0' terminated in the TLV reception
    // format
    char application_name[BOLOS_APPNAME_MAX_SIZE_B + 1];
    char ticker[MAX_TICKER_SIZE + 1];
    uint8_t magnitude;
    tlv_TUID_data_t tlv_TUID_data;

    buffer_t input_sig;

    // Progressive hash of the received TLVs (except the signature type)
    cx_sha256_t hash_ctx;
} tlv_extracted_t;

static bool handle_tuid_token_type_flag(const tlv_data_t *data, tlv_TUID_data_t *tlv_TUID_data) {
    return get_uint8_t_from_tlv_data(data, &tlv_TUID_data->token_type);
}

static bool handle_tuid_mint_address(const tlv_data_t *data, tlv_TUID_data_t *tlv_TUID_data) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_TUID_data->encoded_mint_address,
                                    1,
                                    BASE58_PUBKEY_LENGTH - 1);
}

static bool handle_tuid_ext_code(const tlv_data_t *data, tlv_TUID_data_t *tlv_TUID_data) {
    return get_buffer_from_tlv_data(data,
                                    &tlv_TUID_data->extensions,
                                    0,
                                    EXTENSION_CODE_VALUE_COUNT);
}

// clang-format off
// List of TLV tags recognized by the Solana application
#define TUID_TLV_TAGS(X)                                                           \
    X(0x10, TUID_TOKEN_TYPE_FLAG, handle_tuid_token_type_flag, ENFORCE_UNIQUE_TAG) \
    X(0x11, TUID_MINT_ADDRESS,    handle_tuid_mint_address,    ENFORCE_UNIQUE_TAG) \
    X(0x12, TUID_EXT_CODE,        handle_tuid_ext_code,        ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(TUID_TLV_TAGS, parse_dynamic_token_tuid)

static bool handle_structure_type(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->structure_type);
}

static bool handle_version(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->version);
}

static bool handle_coin_type(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint32_t_from_tlv_data(data, &tlv_extracted->coin_type);
}

static bool handle_application_name(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_string_from_tlv_data(data,
                                    tlv_extracted->application_name,
                                    1,
                                    sizeof(tlv_extracted->application_name));
}

static bool handle_ticker(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_string_from_tlv_data(data, tlv_extracted->ticker, 1, sizeof(tlv_extracted->ticker));
}

static bool handle_magnitude(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    return get_uint8_t_from_tlv_data(data, &tlv_extracted->magnitude);
}

static bool handle_tuid(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &tlv_extracted->hash_ctx, data->raw, data->raw_size));
    buffer_t payload = {.ptr = data->value, .size = data->length};
    return parse_dynamic_token_tuid(&payload,
                                    &tlv_extracted->tlv_TUID_data,
                                    &tlv_extracted->tlv_TUID_data.received_tags);
}

static bool handle_signature(const tlv_data_t *data, tlv_extracted_t *tlv_extracted) {
    return get_buffer_from_tlv_data(data, &tlv_extracted->input_sig, 1, 0);
}

// clang-format off
// List of TLV tags recognized by the Solana application
#define DYNAMIC_TOKEN_TLV_TAGS(X)                                                            \
    X(0x01, DYNAMIC_TOKEN_TAG_STRUCTURE_TYPE,   handle_structure_type,   ENFORCE_UNIQUE_TAG) \
    X(0x02, DYNAMIC_TOKEN_TAG_VERSION,          handle_version,          ENFORCE_UNIQUE_TAG) \
    X(0x03, DYNAMIC_TOKEN_TAG_COIN_TYPE,        handle_coin_type,        ENFORCE_UNIQUE_TAG) \
    X(0x04, DYNAMIC_TOKEN_TAG_APPLICATION_NAME, handle_application_name, ENFORCE_UNIQUE_TAG) \
    X(0x05, DYNAMIC_TOKEN_TAG_TICKER,           handle_ticker,           ENFORCE_UNIQUE_TAG) \
    X(0x06, DYNAMIC_TOKEN_TAG_MAGNITUDE,        handle_magnitude,        ENFORCE_UNIQUE_TAG) \
    X(0x07, DYNAMIC_TOKEN_TAG_TUID,             handle_tuid,             ENFORCE_UNIQUE_TAG) \
    X(0x08, DYNAMIC_TOKEN_TAG_SIGNATURE,        handle_signature,        ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(DYNAMIC_TOKEN_TLV_TAGS, parse_dynamic_token_tag)

static int verify_struct(const tlv_extracted_t *tlv_extracted) {
    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, DYNAMIC_TOKEN_TAG_STRUCTURE_TYPE)) {
        PRINTF("Error: no struct type specified!\n");
        return -1;
    }
    if (tlv_extracted->structure_type != TYPE_DYNAMIC_TOKEN) {
        PRINTF("Error: unexpected struct type %d\n", tlv_extracted->structure_type);
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags, DYNAMIC_TOKEN_TAG_VERSION)) {
        PRINTF("Error: no struct version specified!\n");
        return -1;
    }

    switch (tlv_extracted->version) {
        case 1:
            if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->received_tags,
                                         DYNAMIC_TOKEN_TAG_COIN_TYPE,
                                         DYNAMIC_TOKEN_TAG_APPLICATION_NAME,
                                         DYNAMIC_TOKEN_TAG_TICKER,
                                         DYNAMIC_TOKEN_TAG_MAGNITUDE,
                                         DYNAMIC_TOKEN_TAG_TUID,
                                         DYNAMIC_TOKEN_TAG_SIGNATURE)) {
                PRINTF("Error: missing required fields in struct version 1\n");
                return -1;
            }

            if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted->tlv_TUID_data.received_tags,
                                         TUID_TOKEN_TYPE_FLAG,
                                         TUID_MINT_ADDRESS,
                                         TUID_EXT_CODE)) {
                PRINTF("Error: missing required TUID fields in struct version 1\n");
                return -1;
            }
            if (tlv_extracted->coin_type != SOLANA_SLIP_44_VALUE) {
                PRINTF("Error: unsupported coin type %d\n", tlv_extracted->coin_type);
                return -1;
            }
            if (strcmp(tlv_extracted->application_name, APPNAME) != 0) {
                PRINTF("Error: unsupported application name %s\n", tlv_extracted->application_name);
                return -1;
            }
            if (tlv_extracted->tlv_TUID_data.token_type != TOKEN_LEGACY &&
                tlv_extracted->tlv_TUID_data.token_type != TOKEN_2022) {
                PRINTF("Error: unsupported token type %d\n",
                       tlv_extracted->tlv_TUID_data.token_type);
                return -1;
            }

            for (uint8_t i = 0; i < tlv_extracted->tlv_TUID_data.extensions.size; ++i) {
                PRINTF("tlv_extracted->tlv_TUID_data.extensions\n");
                if (tlv_extracted->tlv_TUID_data.extensions.ptr[i] >= EXTENSION_CODE_VALUE_COUNT) {
                    PRINTF("Unknown extension %d\n",
                           tlv_extracted->tlv_TUID_data.extensions.ptr[i]);
                    return -1;
                }
            }
            break;
        default:
            PRINTF("Error: unsupported struct version %d\n", tlv_extracted->version);
            return -1;
    }
    return 0;
}

static int save_dynamic_token_info(const tlv_extracted_t *tlv_extracted,
                                   dynamic_token_info_t *dynamic_token_info) {
    // We have received the addresses in string base58 format.
    // We will save this decode them and save both the encoded and decoded format.
    // We could save just one but as we need to decode them to ensure they are valid we save both
    if (copy_and_decode_pubkey(tlv_extracted->tlv_TUID_data.encoded_mint_address,
                               dynamic_token_info->encoded_mint_address,
                               dynamic_token_info->mint_address) != 0) {
        PRINTF("copy_and_decode_pubkey error for encoded_mint_address\n");
        return -1;
    }

    // dynamic_token_info->ticker and tlv_extracted->ticker have the same size
    memcpy(dynamic_token_info->ticker, tlv_extracted->ticker, sizeof(dynamic_token_info->ticker));
    // Will never actually be used as we always use the _checked instructions but save it anyway
    dynamic_token_info->magnitude = tlv_extracted->magnitude;
    dynamic_token_info->is_token_2022_kind =
        (tlv_extracted->tlv_TUID_data.token_type == TOKEN_2022);
    dynamic_token_info->received = true;

    PRINTF("=== DYNAMIC TOKEN INFO ===\n");
    PRINTF("ticker               = %s\n", g_dynamic_token_info.ticker);
    PRINTF("token_2022           = %d\n", g_dynamic_token_info.is_token_2022_kind);
    PRINTF("magnitude            = %d\n", g_dynamic_token_info.magnitude);
    PRINTF("encoded_mint_address = %s\n", g_dynamic_token_info.encoded_mint_address);
    PRINTF("mint_address         = %.*H\n", PUBKEY_LENGTH, g_dynamic_token_info.mint_address);
    return 0;
}

void handle_provide_dynamic_descriptor(void) {
    trusted_info_reset(&g_dynamic_token_info);
    // Main structure that will received the parsed TLV data
    tlv_extracted_t tlv_extracted = {0};

    PRINTF("Received trusted info, length = %d\n", G_command.message_length);

    // The parser will fill it with the hash of the whole TLV payload (except SIGN tag)
    cx_sha256_init(&tlv_extracted.hash_ctx);

    // Convert G_command to buffer_t format. 0 copy
    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    // Call the function created by the macro from the TLV lib
    if (!parse_dynamic_token_tag(&payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("Failed to parse tlv payload\n");
        THROW(ApduReplySolanaInvalidDynamicToken);
    }

    // Verify that the fields received are correct in our context
    if (verify_struct(&tlv_extracted) != 0) {
        PRINTF("Failed to verify tlv payload\n");
        THROW(ApduReplySolanaInvalidDynamicToken);
    }

    // Finalize hash object filled by the parser
    uint8_t tlv_hash[CX_SHA256_SIZE] = {0};
    CX_ASSERT(cx_hash_final((cx_hash_t *) &tlv_extracted.hash_ctx, tlv_hash));

    // Verify that the signature field of the TLV is the signature of the TLV hash by the key loaded
    // by the PKI
    if (check_signature_with_pubkey(tlv_hash,
                                    CX_SHA256_SIZE,
                                    CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META,
                                    CX_CURVE_SECP256K1,
                                    tlv_extracted.input_sig) != 0) {
        PRINTF("Failed to verify signature of dynamic token info\n");
        THROW(ApduReplySolanaInvalidDynamicToken);
    }

    if (save_dynamic_token_info(&tlv_extracted, &g_dynamic_token_info) != 0) {
        PRINTF("Failed to save dynamic token info\n");
        THROW(ApduReplySolanaInvalidDynamicToken);
    }

    THROW(ApduReplySuccess);
}
