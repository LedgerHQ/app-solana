#include <os.h>
#include <string.h>

#include "handle_provide_instruction_substructure.h"
#include "io.h"
#include "apdu.h"
#include "globals.h"
#include "tlv_library.h"
#include "tlv_parser_cs_value.h"
#include "cs_instruction_template.h"
#include "cs_substructure.h"

enum substructure_type {
    SUBSTRUCTURE_TYPE_DISPLAY_FIELD   = 0x00,
    SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT = 0x01,
    SUBSTRUCTURE_TYPE_HIDE_RULE       = 0x02,
    SUBSTRUCTURE_TYPE_ACCOUNT_RESET   = 0x03,
};

// ---- PARAM_RAW parser -------------------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_RAW, ACCOUNT_PATH, and CONSTANT.
// CONSTANT source uses tag 0x02 to carry the IDL kind for format_leaf.

typedef struct param_raw_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t kind;
} param_raw_out_t;

static bool param_raw_handle_value(const tlv_data_t *data, param_raw_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_raw_handle_kind(const tlv_data_t *data, param_raw_out_t *out) {
    out->kind = data->value;
    return true;
}

static bool param_raw_handle_ignore(const tlv_data_t *data, param_raw_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_RAW_TAGS(X) \
    X(0x00, PARAM_RAW_TAG_VERSION, param_raw_handle_ignore, ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_RAW_TAG_VALUE,   param_raw_handle_value,  ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_RAW_TAG_KIND,    param_raw_handle_kind,   ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_RAW_TAGS, NULL, parse_param_raw)

// ---- PARAM_AMOUNT parser ----------------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_AMOUNT.

typedef struct param_amount_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t decimals;
} param_amount_out_t;

static bool param_amount_handle_value(const tlv_data_t *data, param_amount_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_amount_handle_decimals(const tlv_data_t *data, param_amount_out_t *out) {
    out->decimals = data->value;
    return true;
}

static bool param_amount_handle_ignore(const tlv_data_t *data, param_amount_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_AMOUNT_TAGS(X) \
    X(0x00, PARAM_AMOUNT_TAG_VERSION,  param_amount_handle_ignore,   ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_AMOUNT_TAG_VALUE,    param_amount_handle_value,    ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_AMOUNT_TAG_DECIMALS, param_amount_handle_decimals, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_AMOUNT_TAGS, NULL, parse_param_amount)

// ---- PARAM_TOKEN_AMOUNT parser -----------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_TOKEN_AMOUNT.

typedef struct param_token_amount_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t token;
    buffer_t decimals;
    buffer_t is_native;
} param_token_amount_out_t;

static bool param_token_amount_handle_value(const tlv_data_t *data,
                                            param_token_amount_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_token_amount_handle_token(const tlv_data_t *data,
                                            param_token_amount_out_t *out) {
    out->token = data->value;
    return true;
}

static bool param_token_amount_handle_decimals(const tlv_data_t *data,
                                               param_token_amount_out_t *out) {
    out->decimals = data->value;
    return true;
}

static bool param_token_amount_handle_is_native(const tlv_data_t *data,
                                                param_token_amount_out_t *out) {
    out->is_native = data->value;
    return true;
}

static bool param_token_amount_handle_ignore(const tlv_data_t *data,
                                             param_token_amount_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_TOKEN_AMOUNT_TAGS(X) \
    X(0x00, PARAM_TOKEN_AMOUNT_TAG_VERSION,   param_token_amount_handle_ignore,    ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_TOKEN_AMOUNT_TAG_VALUE,     param_token_amount_handle_value,     ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_TOKEN_AMOUNT_TAG_TOKEN,     param_token_amount_handle_token,     ENFORCE_UNIQUE_TAG) \
    X(0x03, PARAM_TOKEN_AMOUNT_TAG_DECIMALS,  param_token_amount_handle_decimals,  ENFORCE_UNIQUE_TAG) \
    X(0x04, PARAM_TOKEN_AMOUNT_TAG_IS_NATIVE, param_token_amount_handle_is_native, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_TOKEN_AMOUNT_TAGS, NULL, parse_param_token_amount)

// DISPLAY_FIELD parser. PARAM (tag 0x04) and SUBSTRUCT_TYPE (tag 0x01) are
// captured; the others are accepted and ignored.
typedef struct display_field_out_s {
    TLV_reception_t received_tags;
    uint8_t substruct_type;
    uint8_t param_type;
    char name[CS_MAX_DISPLAY_FIELD_NAME];
    buffer_t param;
} display_field_out_t;

static bool display_field_handle_substruct_type(const tlv_data_t *data,
                                               display_field_out_t *out) {
    if (data->value.size != 1) {
        return false;
    }
    out->substruct_type = data->value.ptr[0];
    return true;
}

static bool display_field_handle_param(const tlv_data_t *data, display_field_out_t *out) {
    out->param = data->value;
    return true;
}

static bool display_field_handle_name(const tlv_data_t *data, display_field_out_t *out) {
    size_t len = data->value.size;
    if (len >= sizeof(out->name)) {
        len = sizeof(out->name) - 1;
    }
    memcpy(out->name, data->value.ptr, len);
    out->name[len] = '\0';
    return true;
}

static bool display_field_handle_param_type(const tlv_data_t *data, display_field_out_t *out) {
    if (data->value.size != 1) {
        return false;
    }
    out->param_type = data->value.ptr[0];
    return true;
}

static bool display_field_handle_ignore(const tlv_data_t *data, display_field_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define DISPLAY_FIELD_TAGS(X) \
    X(0x00, DISPLAY_FIELD_TAG_VERSION,       display_field_handle_ignore,         ENFORCE_UNIQUE_TAG) \
    X(0x01, DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, display_field_handle_substruct_type, ENFORCE_UNIQUE_TAG) \
    X(0x02, DISPLAY_FIELD_TAG_NAME,          display_field_handle_name,           ENFORCE_UNIQUE_TAG) \
    X(0x03, DISPLAY_FIELD_TAG_PARAM_TYPE,    display_field_handle_param_type,     ENFORCE_UNIQUE_TAG) \
    X(0x04, DISPLAY_FIELD_TAG_PARAM,         display_field_handle_param,          ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(DISPLAY_FIELD_TAGS, NULL, parse_display_field)

// Parse the common DISPLAY_FIELD envelope (substruct_type, name, param_type, param buffer).
// Returns 0 on success, -1 on failure.
static int parse_display_field_envelope(uint8_t apdu_type,
                                        const uint8_t *tlv,
                                        size_t tlv_size,
                                        display_field_out_t *out) {
    memset(out, 0, sizeof(*out));
    buffer_t payload = {.ptr = (uint8_t *) tlv, .size = tlv_size};
    if (!parse_display_field(&payload, out, &out->received_tags)) {
        PRINTF("substructure: DISPLAY_FIELD parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(out->received_tags, DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE)) {
        PRINTF("substructure: DISPLAY_FIELD missing SUBSTRUCT_TYPE\n");
        return -1;
    }
    if (out->substruct_type != apdu_type) {
        PRINTF("substructure: SUBSTRUCT_TYPE=%d != APDU type=%d\n",
               out->substruct_type,
               apdu_type);
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(out->received_tags, DISPLAY_FIELD_TAG_PARAM)) {
        PRINTF("substructure: DISPLAY_FIELD missing PARAM\n");
        return -1;
    }
    return 0;
}

// Extract the VALUE (source + payload) from a parsed PARAM buffer.
static int extract_value(const buffer_t *value_buf, cs_value_t *out) {
    if (!cs_parse_value_from_buffer(value_buf->ptr, value_buf->size, out)) {
        PRINTF("substructure: VALUE parsing failed\n");
        return -1;
    }
    return 0;
}

// Register a PARAM_RAW display field (also handles ACCOUNT_PATH and CONSTANT sources).
static int register_param_raw(const display_field_out_t *display_field, const char *field_name) {
    param_raw_out_t param = {0};
    if (!parse_param_raw(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_RAW parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_RAW_TAG_VALUE)) {
        PRINTF("substructure: PARAM_RAW missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }

    if (value.source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
        if (cs_instruction_template_add_display_path(value.payload,
                                                     value.payload_size,
                                                     CS_PARAM_TYPE_RAW,
                                                     field_name) != 0) {
            return -1;
        }
        PRINTF("substructure: registered RAW argument path %.*H name=%s\n",
               value.payload_size,
               value.payload,
               field_name ? field_name : "(none)");
    } else if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        if (value.payload_size != 1) {
            PRINTF("substructure: ACCOUNT_PATH payload size %d != 1\n", value.payload_size);
            return -1;
        }
        if (cs_instruction_template_add_account_field(value.payload[0], field_name) != 0) {
            return -1;
        }
        PRINTF("substructure: registered account field index=%d name=%s\n",
               value.payload[0],
               field_name ? field_name : "(none)");
    } else if (value.source == CS_VALUE_SOURCE_CONSTANT) {
        uint8_t kind = 0;
        if (param.kind.ptr != NULL && param.kind.size == 1) {
            kind = param.kind.ptr[0];
        }
        if (cs_instruction_template_add_constant_field(value.payload,
                                                      value.payload_size,
                                                      kind,
                                                      field_name) != 0) {
            return -1;
        }
        PRINTF("substructure: registered constant field kind=%d size=%d name=%s\n",
               kind,
               value.payload_size,
               field_name ? field_name : "(none)");
    } else {
        PRINTF("substructure: PARAM_RAW source %d not supported\n", value.source);
        return -1;
    }
    return 0;
}

// Register a PARAM_ENUM display field (ARGUMENT_PATH only).
// The enum leaf is resolved by the walker to its selected variant's display name.
static int register_param_enum(const display_field_out_t *display_field, const char *field_name) {
    param_raw_out_t param = {0};
    if (!parse_param_raw(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_ENUM parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_RAW_TAG_VALUE)) {
        PRINTF("substructure: PARAM_ENUM missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_ENUM requires ARGUMENT_PATH source, got %d\n", value.source);
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload,
                                                 value.payload_size,
                                                 CS_PARAM_TYPE_ENUM,
                                                 field_name) != 0) {
        return -1;
    }
    PRINTF("substructure: registered ENUM path %.*H name=%s\n",
           value.payload_size,
           value.payload,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_AMOUNT display field (ARGUMENT_PATH only).
static int register_param_amount(const display_field_out_t *display_field,
                                 const char *field_name) {
    param_amount_out_t param = {0};
    if (!parse_param_amount(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_AMOUNT parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_AMOUNT_TAG_VALUE)) {
        PRINTF("substructure: PARAM_AMOUNT missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_AMOUNT requires ARGUMENT_PATH source, got %d\n",
               value.source);
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload,
                                                 value.payload_size,
                                                 CS_PARAM_TYPE_AMOUNT,
                                                 field_name) != 0) {
        return -1;
    }

    uint8_t decimals = 0;
    if (param.decimals.ptr != NULL && param.decimals.size == 1) {
        decimals = param.decimals.ptr[0];
    }
    if (cs_instruction_template_set_format_amount(decimals) != 0) {
        PRINTF("substructure: set_format_amount failed\n");
        return -1;
    }
    PRINTF("substructure: registered AMOUNT path %.*H decimals=%d name=%s\n",
           value.payload_size,
           value.payload,
           decimals,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_TOKEN_AMOUNT display field (ARGUMENT_PATH only).
static int register_param_token_amount(const display_field_out_t *display_field,
                                       const char *field_name) {
    param_token_amount_out_t param = {0};
    if (!parse_param_token_amount(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_TOKEN_AMOUNT parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_TOKEN_AMOUNT_TAG_VALUE)) {
        PRINTF("substructure: PARAM_TOKEN_AMOUNT missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_TOKEN_AMOUNT requires ARGUMENT_PATH source, got %d\n",
               value.source);
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload,
                                                 value.payload_size,
                                                 CS_PARAM_TYPE_TOKEN_AMOUNT,
                                                 field_name) != 0) {
        return -1;
    }

    bool is_native = (param.is_native.ptr != NULL && param.is_native.size == 1 &&
                      param.is_native.ptr[0] == 1);
    bool has_token = TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_TOKEN_AMOUNT_TAG_TOKEN);
    bool has_decimals =
        TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_TOKEN_AMOUNT_TAG_DECIMALS);

    // Native SOL carries its own built-in metadata; a mint reference or decimals
    // override alongside it is contradictory.
    if (is_native && (has_token || has_decimals)) {
        PRINTF("substructure: TOKEN_AMOUNT native cannot carry a TOKEN reference or DECIMALS\n");
        return -1;
    }

    cs_format_token_amount_t format = {0};
    if (is_native) {
        format.mint_source = CS_TOKEN_MINT_NATIVE;
    } else if (has_token) {
        cs_value_t token;
        if (extract_value(&param.token, &token) != 0) {
            return -1;
        }
        if (token.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
            if (token.payload_size != 1) {
                PRINTF("substructure: TOKEN ACCOUNT_PATH payload size %d != 1\n",
                       token.payload_size);
                return -1;
            }
            format.mint_source = CS_TOKEN_MINT_ACCOUNT_INDEX;
            format.ref.account_index = token.payload[0];
        } else if (token.source == CS_VALUE_SOURCE_CONSTANT) {
            if (token.payload_size != 32) {
                PRINTF("substructure: TOKEN CONSTANT payload size %d != 32\n", token.payload_size);
                return -1;
            }
            format.mint_source = CS_TOKEN_MINT_CONSTANT;
            memcpy(format.ref.mint, token.payload, 32);
        } else {
            PRINTF("substructure: TOKEN source %d unsupported\n", token.source);
            return -1;
        }
    } else {
        format.mint_source = CS_TOKEN_MINT_NONE;
    }

    // Optional DECIMALS override: replaces the mint's default magnitude. Only a
    // CONSTANT single byte is a usable override; anything else is refused.
    if (has_decimals) {
        cs_value_t decimals;
        if (extract_value(&param.decimals, &decimals) != 0) {
            return -1;
        }
        if (decimals.source != CS_VALUE_SOURCE_CONSTANT || decimals.payload_size != 1) {
            PRINTF("substructure: DECIMALS must be a 1-byte CONSTANT (source %d size %d)\n",
                   decimals.source,
                   decimals.payload_size);
            return -1;
        }
        format.has_decimals = true;
        format.decimals = decimals.payload[0];
    }

    if (cs_instruction_template_set_format_token_amount(&format) != 0) {
        PRINTF("substructure: set_format_token_amount failed\n");
        return -1;
    }

    PRINTF("substructure: registered TOKEN_AMOUNT path %.*H mint_source=%d name=%s\n",
           value.payload_size,
           value.payload,
           format.mint_source,
           field_name ? field_name : "(none)");
    return 0;
}

// Parse a DISPLAY_FIELD substructure and register it on the current template.
// Dispatches to the correct PARAM parser based on the declared param_type.
static int register_display_field(uint8_t apdu_type, const uint8_t *tlv, size_t tlv_size) {
    display_field_out_t display_field;
    if (parse_display_field_envelope(apdu_type, tlv, tlv_size, &display_field) != 0) {
        return -1;
    }

    const char *field_name = NULL;
    if (display_field.name[0] != '\0') {
        field_name = display_field.name;
    }

    switch (display_field.param_type) {
        case CS_PARAM_TYPE_RAW:
            return register_param_raw(&display_field, field_name);

        case CS_PARAM_TYPE_AMOUNT:
            return register_param_amount(&display_field, field_name);

        case CS_PARAM_TYPE_TOKEN_AMOUNT:
            return register_param_token_amount(&display_field, field_name);

        case CS_PARAM_TYPE_ENUM:
            return register_param_enum(&display_field, field_name);

        default:
            PRINTF("substructure: unsupported param_type %d\n", display_field.param_type);
            return -1;
    }
}

int handle_provide_instruction_substructure(void) {
    PRINTF("handle_provide_instruction_substructure\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return io_send_sw(state_err);
    }

    if (cs_instruction_template_current() == NULL) {
        PRINTF("substructure: no instruction template open\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (G_command.message_length < 1) {
        PRINTF("substructure: empty payload\n");
        return io_send_sw(ApduReplySolanaInvalidInstructionSubstructure);
    }

    uint8_t type = G_command.message[0];
    const uint8_t *tlv = G_command.message + 1;
    size_t tlv_size = (size_t) G_command.message_length - 1;

    // Accumulate the substructure TLV (type byte excluded) into the running hash.
    if (cs_substructure_update(tlv, tlv_size) != 0) {
        PRINTF("substructure: hash accumulation refused\n");
        return io_send_sw(ApduReplySolanaInvalidInstructionSubstructure);
    }

    // Only DISPLAY_FIELD is interpreted in this slice; the other substructure
    // types contribute to the hash but are not decoded.
    if (type == SUBSTRUCTURE_TYPE_DISPLAY_FIELD) {
        if (register_display_field(type, tlv, tlv_size) != 0) {
            PRINTF("substructure: register_display_field failed\n");
            return io_send_sw(ApduReplySolanaInvalidInstructionSubstructure);
        }
    }

    bool complete = false;
    if (cs_substructure_check_complete(&complete) != 0) {
        PRINTF("substructure: completeness check refused\n");
        return io_send_sw(ApduReplySolanaInvalidInstructionSubstructure);
    }
    if (complete) {
        if (cs_instruction_template_commit() != 0) {
            PRINTF("substructure: template commit refused\n");
            return io_send_sw(ApduReplySolanaInvalidInstructionSubstructure);
        }
        PRINTF("substructure: running hash matched, template committed\n");
    } else {
        PRINTF("substructure: hash not yet matched, awaiting more substructures\n");
    }

    return io_send_sw(ApduReplySuccess);
}
