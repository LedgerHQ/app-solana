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

// ---- PARAM_DATETIME parser --------------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_DATETIME.

typedef struct param_datetime_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t ticks_per_second;
} param_datetime_out_t;

static bool param_datetime_handle_value(const tlv_data_t *data, param_datetime_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_datetime_handle_ticks(const tlv_data_t *data, param_datetime_out_t *out) {
    out->ticks_per_second = data->value;
    return true;
}

static bool param_datetime_handle_ignore(const tlv_data_t *data, param_datetime_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_DATETIME_TAGS(X) \
    X(0x00, PARAM_DATETIME_TAG_VERSION, param_datetime_handle_ignore, ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_DATETIME_TAG_VALUE,   param_datetime_handle_value,  ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_DATETIME_TAG_TICKS,   param_datetime_handle_ticks,  ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_DATETIME_TAGS, NULL, parse_param_datetime)

// ---- PARAM_UNIT parser ------------------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_UNIT.

typedef struct param_unit_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t symbol;
    buffer_t decimals;
    buffer_t prefix;
} param_unit_out_t;

static bool param_unit_handle_value(const tlv_data_t *data, param_unit_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_unit_handle_symbol(const tlv_data_t *data, param_unit_out_t *out) {
    out->symbol = data->value;
    return true;
}

static bool param_unit_handle_decimals(const tlv_data_t *data, param_unit_out_t *out) {
    out->decimals = data->value;
    return true;
}

static bool param_unit_handle_prefix(const tlv_data_t *data, param_unit_out_t *out) {
    out->prefix = data->value;
    return true;
}

static bool param_unit_handle_ignore(const tlv_data_t *data, param_unit_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_UNIT_TAGS(X) \
    X(0x00, PARAM_UNIT_TAG_VERSION,  param_unit_handle_ignore,   ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_UNIT_TAG_VALUE,    param_unit_handle_value,    ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_UNIT_TAG_SYMBOL,   param_unit_handle_symbol,   ENFORCE_UNIQUE_TAG) \
    X(0x03, PARAM_UNIT_TAG_DECIMALS, param_unit_handle_decimals, ENFORCE_UNIQUE_TAG) \
    X(0x04, PARAM_UNIT_TAG_PREFIX,   param_unit_handle_prefix,   ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_UNIT_TAGS, NULL, parse_param_unit)

// ---- PARAM_STRING parser ----------------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_STRING.

typedef struct param_string_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t encoding;
    buffer_t slice_kind;
    buffer_t slice_start;
    buffer_t slice_end;
    buffer_t slice_size;
    buffer_t slice_reversed;
    buffer_t slice_applies_to;
} param_string_out_t;

static bool param_string_handle_value(const tlv_data_t *data, param_string_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_string_handle_encoding(const tlv_data_t *data, param_string_out_t *out) {
    out->encoding = data->value;
    return true;
}

static bool param_string_handle_slice_kind(const tlv_data_t *data, param_string_out_t *out) {
    out->slice_kind = data->value;
    return true;
}

static bool param_string_handle_slice_start(const tlv_data_t *data, param_string_out_t *out) {
    out->slice_start = data->value;
    return true;
}

static bool param_string_handle_slice_end(const tlv_data_t *data, param_string_out_t *out) {
    out->slice_end = data->value;
    return true;
}

static bool param_string_handle_slice_size(const tlv_data_t *data, param_string_out_t *out) {
    out->slice_size = data->value;
    return true;
}

static bool param_string_handle_slice_reversed(const tlv_data_t *data, param_string_out_t *out) {
    out->slice_reversed = data->value;
    return true;
}

static bool param_string_handle_slice_applies_to(const tlv_data_t *data, param_string_out_t *out) {
    out->slice_applies_to = data->value;
    return true;
}

static bool param_string_handle_ignore(const tlv_data_t *data, param_string_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_STRING_TAGS(X) \
    X(0x00, PARAM_STRING_TAG_VERSION,          param_string_handle_ignore,           ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_STRING_TAG_VALUE,            param_string_handle_value,            ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_STRING_TAG_ENCODING,         param_string_handle_encoding,         ENFORCE_UNIQUE_TAG) \
    X(0x03, PARAM_STRING_TAG_SLICE_KIND,       param_string_handle_slice_kind,       ENFORCE_UNIQUE_TAG) \
    X(0x04, PARAM_STRING_TAG_SLICE_START,      param_string_handle_slice_start,      ENFORCE_UNIQUE_TAG) \
    X(0x05, PARAM_STRING_TAG_SLICE_END,        param_string_handle_slice_end,        ENFORCE_UNIQUE_TAG) \
    X(0x06, PARAM_STRING_TAG_SLICE_SIZE,       param_string_handle_slice_size,       ENFORCE_UNIQUE_TAG) \
    X(0x07, PARAM_STRING_TAG_SLICE_REVERSED,   param_string_handle_slice_reversed,   ENFORCE_UNIQUE_TAG) \
    X(0x08, PARAM_STRING_TAG_SLICE_APPLIES_TO, param_string_handle_slice_applies_to, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_STRING_TAGS, NULL, parse_param_string)

// ---- PARAM_TRUSTED_NAME parser ----------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_TRUSTED_NAME.

typedef struct param_trusted_name_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t types;
} param_trusted_name_out_t;

static bool param_trusted_name_handle_value(const tlv_data_t *data,
                                            param_trusted_name_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_trusted_name_handle_types(const tlv_data_t *data,
                                            param_trusted_name_out_t *out) {
    out->types = data->value;
    return true;
}

static bool param_trusted_name_handle_ignore(const tlv_data_t *data,
                                             param_trusted_name_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// SOURCES is handled (the parser rejects unlisted tags) but ignored: only
// CRYPTO_ASSET_LIST names are ever cached.
// clang-format off
#define PARAM_TRUSTED_NAME_TAGS(X) \
    X(0x00, PARAM_TRUSTED_NAME_TAG_VERSION, param_trusted_name_handle_ignore, ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_TRUSTED_NAME_TAG_VALUE,   param_trusted_name_handle_value,  ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_TRUSTED_NAME_TAG_TYPES,   param_trusted_name_handle_types,  ENFORCE_UNIQUE_TAG) \
    X(0x03, PARAM_TRUSTED_NAME_TAG_SOURCES, param_trusted_name_handle_ignore, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_TRUSTED_NAME_TAGS, NULL, parse_param_trusted_name)

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

// Read a big-endian unsigned integer of up to `max_bytes` bytes from a buffer.
// An absent (NULL) buffer yields `fallback`. Returns false when the encoded
// width exceeds `max_bytes`.
static bool read_be_uint(const buffer_t *buf, size_t max_bytes, uint32_t fallback, uint32_t *out) {
    if (buf->ptr == NULL || buf->size == 0) {
        *out = fallback;
        return true;
    }
    if (buf->size > max_bytes) {
        PRINTF("substructure: integer width %d exceeds max %d\n", buf->size, max_bytes);
        return false;
    }
    uint32_t value = 0;
    for (size_t i = 0; i < buf->size; i++) {
        value = (value << 8) | buf->ptr[i];
    }
    *out = value;
    return true;
}

// Register a PARAM_DATETIME display field (ARGUMENT_PATH only).
static int register_param_datetime(const display_field_out_t *display_field,
                                   const char *field_name) {
    param_datetime_out_t param = {0};
    if (!parse_param_datetime(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_DATETIME parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_DATETIME_TAG_VALUE)) {
        PRINTF("substructure: PARAM_DATETIME missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_DATETIME requires ARGUMENT_PATH source, got %d\n",
               value.source);
        return -1;
    }

    uint32_t ticks_per_second = 1;
    if (!read_be_uint(&param.ticks_per_second, 4, 1, &ticks_per_second)) {
        PRINTF("substructure: PARAM_DATETIME bad TICKS_PER_SECOND\n");
        return -1;
    }
    if (ticks_per_second == 0) {
        PRINTF("substructure: PARAM_DATETIME TICKS_PER_SECOND must be non-zero\n");
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload,
                                                 value.payload_size,
                                                 CS_PARAM_TYPE_DATETIME,
                                                 field_name) != 0) {
        return -1;
    }
    if (cs_instruction_template_set_format_datetime(ticks_per_second) != 0) {
        PRINTF("substructure: set_format_datetime failed\n");
        return -1;
    }
    PRINTF("substructure: registered DATETIME path %.*H ticks=%d name=%s\n",
           value.payload_size,
           value.payload,
           ticks_per_second,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_UNIT display field (ARGUMENT_PATH only).
static int register_param_unit(const display_field_out_t *display_field, const char *field_name) {
    param_unit_out_t param = {0};
    if (!parse_param_unit(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_UNIT parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_UNIT_TAG_VALUE)) {
        PRINTF("substructure: PARAM_UNIT missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_UNIT requires ARGUMENT_PATH source, got %d\n", value.source);
        return -1;
    }

    cs_format_unit_t format = {0};
    if (param.symbol.ptr != NULL && param.symbol.size > 0) {
        if (param.symbol.size >= sizeof(format.symbol)) {
            PRINTF("substructure: PARAM_UNIT symbol too long (%d >= %d)\n",
                   param.symbol.size,
                   (int) sizeof(format.symbol));
            return -1;
        }
        memcpy(format.symbol, param.symbol.ptr, param.symbol.size);
        format.symbol[param.symbol.size] = '\0';
    }
    if (param.decimals.ptr != NULL) {
        if (param.decimals.size != 1) {
            PRINTF("substructure: PARAM_UNIT DECIMALS must be 1 byte (got %d)\n",
                   param.decimals.size);
            return -1;
        }
        format.decimals = param.decimals.ptr[0];
    }
    if (param.prefix.ptr != NULL) {
        if (param.prefix.size != 1) {
            PRINTF("substructure: PARAM_UNIT PREFIX must be 1 byte (got %d)\n", param.prefix.size);
            return -1;
        }
        format.prefix = (param.prefix.ptr[0] == 1);
    }

    if (cs_instruction_template_add_display_path(value.payload,
                                                 value.payload_size,
                                                 CS_PARAM_TYPE_UNIT,
                                                 field_name) != 0) {
        return -1;
    }
    if (cs_instruction_template_set_format_unit(&format) != 0) {
        PRINTF("substructure: set_format_unit failed\n");
        return -1;
    }
    PRINTF("substructure: registered UNIT path %.*H symbol=%s decimals=%d prefix=%d name=%s\n",
           value.payload_size,
           value.payload,
           format.symbol,
           format.decimals,
           format.prefix,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_STRING display field (ARGUMENT_PATH only).
static int register_param_string(const display_field_out_t *display_field,
                                 const char *field_name) {
    param_string_out_t param = {0};
    if (!parse_param_string(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_STRING parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_STRING_TAG_VALUE)) {
        PRINTF("substructure: PARAM_STRING missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_STRING requires ARGUMENT_PATH source, got %d\n", value.source);
        return -1;
    }

    cs_format_string_t format = {0};
    format.encoding = CS_STRING_ENCODING_UTF8;
    if (param.encoding.ptr != NULL) {
        if (param.encoding.size != 1) {
            PRINTF("substructure: PARAM_STRING ENCODING must be 1 byte (got %d)\n",
                   param.encoding.size);
            return -1;
        }
        format.encoding = param.encoding.ptr[0];
    }
    switch (format.encoding) {
        case CS_STRING_ENCODING_ASCII:
        case CS_STRING_ENCODING_UTF8:
        case CS_STRING_ENCODING_BASE58:
        case CS_STRING_ENCODING_BASE64:
        case CS_STRING_ENCODING_HEX:
            break;
        default:
            PRINTF("substructure: PARAM_STRING unknown encoding %d\n", format.encoding);
            return -1;
    }

    // Presence of SLICE_KIND enables slicing; the other slice tags are only
    // valid for the matching kind.
    format.has_slice = TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_STRING_TAG_SLICE_KIND);
    bool has_end = TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_STRING_TAG_SLICE_END);
    bool has_size = TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_STRING_TAG_SLICE_SIZE);
    bool has_reversed =
        TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_STRING_TAG_SLICE_REVERSED);
    bool has_start = TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_STRING_TAG_SLICE_START);

    if (!format.has_slice) {
        if (has_end || has_size || has_reversed || has_start) {
            PRINTF("substructure: PARAM_STRING slice tags present without SLICE_KIND\n");
            return -1;
        }
    } else {
        if (param.slice_kind.size != 1) {
            PRINTF("substructure: PARAM_STRING SLICE_KIND must be 1 byte (got %d)\n",
                   param.slice_kind.size);
            return -1;
        }
        format.slice_kind = param.slice_kind.ptr[0];

        uint32_t start = 0;
        if (!read_be_uint(&param.slice_start, 2, 0, &start)) {
            PRINTF("substructure: PARAM_STRING bad SLICE_START\n");
            return -1;
        }
        format.slice_start = (uint16_t) start;

        if (format.slice_kind == CS_SLICE_KIND_BOUNDED) {
            if (has_size || has_reversed) {
                PRINTF("substructure: PARAM_STRING BOUNDED cannot carry SLICE_SIZE/REVERSED\n");
                return -1;
            }
            uint32_t end = 0xFFFF;
            if (!read_be_uint(&param.slice_end, 2, 0xFFFF, &end)) {
                PRINTF("substructure: PARAM_STRING bad SLICE_END\n");
                return -1;
            }
            format.slice.bounded.end = (uint16_t) end;
        } else if (format.slice_kind == CS_SLICE_KIND_SIZED) {
            if (has_end) {
                PRINTF("substructure: PARAM_STRING SIZED cannot carry SLICE_END\n");
                return -1;
            }
            if (!has_size) {
                PRINTF("substructure: PARAM_STRING SIZED requires SLICE_SIZE\n");
                return -1;
            }
            uint32_t size = 0;
            if (!read_be_uint(&param.slice_size, 2, 0, &size)) {
                PRINTF("substructure: PARAM_STRING bad SLICE_SIZE\n");
                return -1;
            }
            format.slice.sized.size = (uint16_t) size;
            if (has_reversed) {
                if (param.slice_reversed.size != 1) {
                    PRINTF("substructure: PARAM_STRING SLICE_REVERSED must be 1 byte (got %d)\n",
                           param.slice_reversed.size);
                    return -1;
                }
                format.slice.sized.reversed = (param.slice_reversed.ptr[0] == 1);
            }
        } else {
            PRINTF("substructure: PARAM_STRING unknown SLICE_KIND %d\n", format.slice_kind);
            return -1;
        }
    }

    format.slice_applies_to = CS_SLICE_APPLIES_TO_FORMATTED;
    if (TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_STRING_TAG_SLICE_APPLIES_TO)) {
        if (param.slice_applies_to.size != 1) {
            PRINTF("substructure: PARAM_STRING SLICE_APPLIES_TO must be 1 byte (got %d)\n",
                   param.slice_applies_to.size);
            return -1;
        }
        format.slice_applies_to = param.slice_applies_to.ptr[0];
        if (format.slice_applies_to != CS_SLICE_APPLIES_TO_FORMATTED &&
            format.slice_applies_to != CS_SLICE_APPLIES_TO_SOURCE) {
            PRINTF("substructure: PARAM_STRING unknown SLICE_APPLIES_TO %d\n",
                   format.slice_applies_to);
            return -1;
        }
    }

    if (cs_instruction_template_add_display_path(value.payload,
                                                 value.payload_size,
                                                 CS_PARAM_TYPE_STRING,
                                                 field_name) != 0) {
        return -1;
    }
    if (cs_instruction_template_set_format_string(&format) != 0) {
        PRINTF("substructure: set_format_string failed\n");
        return -1;
    }
    PRINTF("substructure: registered STRING path %.*H encoding=%d has_slice=%d name=%s\n",
           value.payload_size,
           value.payload,
           format.encoding,
           format.has_slice,
           field_name ? field_name : "(none)");
    return 0;
}

// Fold an allow-list byte array into a bitmask (bit i = value i permitted).
// An empty array yields 0 (no constraint). Returns -1 on a value >= 8, which a
// uint8 mask cannot represent.
static int trusted_name_build_mask(const buffer_t *list, uint8_t *mask_out) {
    uint8_t mask = 0;
    for (uint16_t i = 0; i < list->size; i++) {
        uint8_t value = list->ptr[i];
        if (value >= 8) {
            PRINTF("substructure: PARAM_TRUSTED_NAME value %d out of representable range\n", value);
            return -1;
        }
        mask |= (uint8_t) (1 << value);
    }
    *mask_out = mask;
    return 0;
}

// Register a PARAM_TRUSTED_NAME display field (ARGUMENT_PATH only).
static int register_param_trusted_name(const display_field_out_t *display_field,
                                       const char *field_name) {
    param_trusted_name_out_t param = {0};
    if (!parse_param_trusted_name(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_TRUSTED_NAME parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_TRUSTED_NAME_TAG_VALUE)) {
        PRINTF("substructure: PARAM_TRUSTED_NAME missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_TRUSTED_NAME requires ARGUMENT_PATH source, got %d\n",
               value.source);
        return -1;
    }

    cs_format_trusted_name_t format = {0};
    if (trusted_name_build_mask(&param.types, &format.allowed_types_mask) != 0) {
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload,
                                                 value.payload_size,
                                                 CS_PARAM_TYPE_TRUSTED_NAME,
                                                 field_name) != 0) {
        return -1;
    }
    if (cs_instruction_template_set_format_trusted_name(&format) != 0) {
        PRINTF("substructure: set_format_trusted_name failed\n");
        return -1;
    }
    PRINTF("substructure: registered TRUSTED_NAME path %.*H types=0x%02x name=%s\n",
           value.payload_size,
           value.payload,
           format.allowed_types_mask,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_ACCOUNT or PARAM_DURATION display field. Both reuse the
// PARAM_RAW envelope (VERSION + VALUE) and carry no extra format parameters;
// only the resulting param_type differs. ARGUMENT_PATH source only.
static int register_param_plain_argument(const display_field_out_t *display_field,
                                         const char *field_name,
                                         uint8_t param_type) {
    param_raw_out_t param = {0};
    if (!parse_param_raw(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: plain PARAM (type %d) parsing failed\n", param_type);
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_RAW_TAG_VALUE)) {
        PRINTF("substructure: plain PARAM (type %d) missing VALUE\n", param_type);
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: param_type %d requires ARGUMENT_PATH source, got %d\n",
               param_type,
               value.source);
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload,
                                                 value.payload_size,
                                                 param_type,
                                                 field_name) != 0) {
        return -1;
    }
    PRINTF("substructure: registered param_type %d path %.*H name=%s\n",
           param_type,
           value.payload_size,
           value.payload,
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

        case CS_PARAM_TYPE_DATETIME:
            return register_param_datetime(&display_field, field_name);

        case CS_PARAM_TYPE_DURATION:
            return register_param_plain_argument(&display_field,
                                                 field_name,
                                                 CS_PARAM_TYPE_DURATION);

        case CS_PARAM_TYPE_UNIT:
            return register_param_unit(&display_field, field_name);

        case CS_PARAM_TYPE_ACCOUNT:
            return register_param_plain_argument(&display_field,
                                                 field_name,
                                                 CS_PARAM_TYPE_ACCOUNT);

        case CS_PARAM_TYPE_STRING:
            return register_param_string(&display_field, field_name);

        case CS_PARAM_TYPE_TRUSTED_NAME:
            return register_param_trusted_name(&display_field, field_name);

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
