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
#include "os_pki.h"
#include "ledger_pki.h"
#include "tlv_use_case_dynamic_descriptor.h"

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

typedef struct tlv_TUID_data_s {
    TLV_reception_t received_tags;

    solana_token_type_t token_type;
    buffer_t encoded_mint_address;
    buffer_t extensions;
} tlv_TUID_data_t;

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

DEFINE_TLV_PARSER(TUID_TLV_TAGS, NULL, parse_dynamic_token_tuid)

static int verify_struct_solana(const tlv_dynamic_descriptor_out_t *tlv_output,
                                const tlv_TUID_data_t *tlv_TUID_data) {
    if (tlv_output->coin_type != SOLANA_SLIP_44_VALUE) {
        PRINTF("Error: unsupported coin type %d\n", tlv_output->coin_type);
        return -1;
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_TUID_data->received_tags,
                                 TUID_TOKEN_TYPE_FLAG,
                                 TUID_MINT_ADDRESS,
                                 TUID_EXT_CODE)) {
        PRINTF("Error: missing required TUID fields in struct version 1\n");
        return -1;
    }

    if (tlv_TUID_data->token_type != TOKEN_LEGACY && tlv_TUID_data->token_type != TOKEN_2022) {
        PRINTF("Error: unsupported token type %d\n", tlv_TUID_data->token_type);
        return -1;
    }

    for (uint8_t i = 0; i < tlv_TUID_data->extensions.size; ++i) {
        PRINTF("tlv_TUID_data->extensions\n");
        if (tlv_TUID_data->extensions.ptr[i] >= EXTENSION_CODE_VALUE_COUNT) {
            PRINTF("Unknown extension %d\n", tlv_TUID_data->extensions.ptr[i]);
            return -1;
        }
    }

    return 0;
}

static int save_dynamic_token_info(const tlv_dynamic_descriptor_out_t *tlv_output,
                                   const tlv_TUID_data_t *tlv_TUID_data,
                                   dynamic_token_info_t *dynamic_token_info) {
    // We have received the addresses in string base58 format.
    // We will save this decode them and save both the encoded and decoded format.
    // We could save just one but as we need to decode them to ensure they are valid we save both
    if (copy_and_decode_pubkey(tlv_TUID_data->encoded_mint_address,
                               dynamic_token_info->encoded_mint_address,
                               dynamic_token_info->mint_address) != 0) {
        PRINTF("copy_and_decode_pubkey error for encoded_mint_address\n");
        return -1;
    }

    // dynamic_token_info->ticker and tlv_extracted->ticker have the same size
    memcpy(dynamic_token_info->ticker, tlv_output->ticker, sizeof(dynamic_token_info->ticker));
    // Will never actually be used as we always use the _checked instructions but save it anyway
    dynamic_token_info->magnitude = tlv_output->magnitude;
    dynamic_token_info->is_token_2022_kind = (tlv_TUID_data->token_type == TOKEN_2022);
    dynamic_token_info->received = true;

    PRINTF("=== DYNAMIC TOKEN INFO ===\n");
    PRINTF("ticker               = %s\n", g_dynamic_token_info.ticker);
    PRINTF("token_2022           = %d\n", g_dynamic_token_info.is_token_2022_kind);
    PRINTF("magnitude            = %d\n", g_dynamic_token_info.magnitude);
    PRINTF("encoded_mint_address = %s\n", g_dynamic_token_info.encoded_mint_address);
    PRINTF("mint_address         = %.*H\n", PUBKEY_LENGTH, g_dynamic_token_info.mint_address);

    return 0;
}

dynamic_token_info_t g_dynamic_token_info;

void handle_provide_dynamic_descriptor(void) {
    explicit_bzero(&g_dynamic_token_info, sizeof(g_dynamic_token_info));

    tlv_dynamic_descriptor_out_t tlv_output = {0};

    // Convert G_command to buffer_t format. 0 copy
    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    if (tlv_use_case_parse_dynamic_descriptor_payload(&payload, &tlv_output) != 0) {
        PRINTF("tlv_use_case_parse_dynamic_descriptor_payload failed\n");
        THROW(ApduReplySolanaInvalidDynamicToken);
    }

    tlv_TUID_data_t tlv_TUID_data;
    PRINTF("tlv_output.TUID %.*H\n", tlv_output.TUID.size, tlv_output.TUID.ptr);
    if (!parse_dynamic_token_tuid(&tlv_output.TUID, &tlv_TUID_data, &tlv_TUID_data.received_tags)) {
        PRINTF("Failed to parse tuid tlv payload\n");
        THROW(ApduReplySolanaInvalidDynamicToken);
    }

    if (verify_struct_solana(&tlv_output, &tlv_TUID_data) != 0) {
        PRINTF("Failed to verify tlv payload\n");
        THROW(ApduReplySolanaInvalidDynamicToken);
    }

    if (save_dynamic_token_info(&tlv_output, &tlv_TUID_data, &g_dynamic_token_info) != 0) {
        PRINTF("Failed to save dynamic token info\n");
        THROW(ApduReplySolanaInvalidDynamicToken);
    }

    THROW(ApduReplySuccess);
}
