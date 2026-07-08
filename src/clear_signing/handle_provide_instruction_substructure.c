#include <os.h>
#include <string.h>

#include "handle_provide_instruction_substructure.h"
#include "io.h"
#include "apdu.h"
#include "globals.h"
#include "tlv_library.h"
#include "tlv_parser_cs_value.h"
#include "cs_instruction_template.h"
#include "idl_kinds.h"
#include "cs_substructure.h"
#include "app_mem_utils.h"
#include "reply.h"

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

// ---- PARAM_ENUM parser ------------------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_ENUM. SKIP_INNER (0x02) collides in
// tag number with PARAM_RAW's KIND, so PARAM_ENUM needs its own tag set rather
// than borrowing the PARAM_RAW parser.

typedef struct param_enum_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t skip_inner;
} param_enum_out_t;

static bool param_enum_handle_value(const tlv_data_t *data, param_enum_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_enum_handle_skip_inner(const tlv_data_t *data, param_enum_out_t *out) {
    out->skip_inner = data->value;
    return true;
}

static bool param_enum_handle_ignore(const tlv_data_t *data, param_enum_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_ENUM_TAGS(X) \
    X(0x00, PARAM_ENUM_TAG_VERSION,    param_enum_handle_ignore,     ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_ENUM_TAG_VALUE,      param_enum_handle_value,      ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_ENUM_TAG_SKIP_INNER, param_enum_handle_skip_inner, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_ENUM_TAGS, NULL, parse_param_enum)

// ---- PARAM_AMOUNT parser ----------------------------------------------------
// Used for ARGUMENT_PATH with CS_PARAM_TYPE_AMOUNT.

typedef struct param_amount_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
    buffer_t decimals;
    buffer_t max_label;
} param_amount_out_t;

static bool param_amount_handle_value(const tlv_data_t *data, param_amount_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_amount_handle_decimals(const tlv_data_t *data, param_amount_out_t *out) {
    out->decimals = data->value;
    return true;
}

static bool param_amount_handle_max_label(const tlv_data_t *data, param_amount_out_t *out) {
    out->max_label = data->value;
    return true;
}

static bool param_amount_handle_ignore(const tlv_data_t *data, param_amount_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_AMOUNT_TAGS(X) \
    X(0x00, PARAM_AMOUNT_TAG_VERSION,   param_amount_handle_ignore,    ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_AMOUNT_TAG_VALUE,     param_amount_handle_value,     ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_AMOUNT_TAG_DECIMALS,  param_amount_handle_decimals,  ENFORCE_UNIQUE_TAG) \
    X(0x03, PARAM_AMOUNT_TAG_MAX_LABEL, param_amount_handle_max_label, ENFORCE_UNIQUE_TAG)
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
    buffer_t max_label;
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

static bool param_token_amount_handle_max_label(const tlv_data_t *data,
                                                param_token_amount_out_t *out) {
    out->max_label = data->value;
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
    X(0x00, PARAM_TOKEN_AMOUNT_TAG_VERSION,   param_token_amount_handle_ignore,     ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_TOKEN_AMOUNT_TAG_VALUE,     param_token_amount_handle_value,      ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_TOKEN_AMOUNT_TAG_TOKEN,     param_token_amount_handle_token,      ENFORCE_UNIQUE_TAG) \
    X(0x03, PARAM_TOKEN_AMOUNT_TAG_DECIMALS,  param_token_amount_handle_decimals,   ENFORCE_UNIQUE_TAG) \
    X(0x04, PARAM_TOKEN_AMOUNT_TAG_IS_NATIVE, param_token_amount_handle_is_native,  ENFORCE_UNIQUE_TAG) \
    X(0x05, PARAM_TOKEN_AMOUNT_TAG_MAX_LABEL, param_token_amount_handle_max_label,  ENFORCE_UNIQUE_TAG)
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
    buffer_t name;  // view into the message; materialized NUL-terminated at dispatch
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
    out->name = data->value;
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

// Register an ACCOUNT_PATH value as a plain account field. The payload is a
// single u8: the index into the instruction's accounts array. The pubkey there
// is always rendered as a short-form base58 address, so the declared param_type
// and any format parameters are irrelevant and intentionally ignored. Every
// PARAM parser routes an ACCOUNT_PATH source here so it is accepted uniformly.
// Returns 0 on success, -1 on a malformed payload.
static int register_account_path_value(const cs_value_t *value, const char *field_name) {
    if (value->payload.size != 1) {
        PRINTF("substructure: ACCOUNT_PATH payload size %d != 1\n", value->payload.size);
        return -1;
    }
    if (cs_instruction_template_add_account_field(value->payload.ptr[0], field_name) != 0) {
        return -1;
    }
    PRINTF("substructure: registered account field index=%d name=%s\n",
           value->payload.ptr[0],
           field_name ? field_name : "(none)");
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
        if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                     value.payload.size,
                                                     CS_PARAM_TYPE_RAW,
                                                     field_name) != 0) {
            return -1;
        }
        PRINTF("substructure: registered RAW argument path %.*H name=%s\n",
               value.payload.size,
               value.payload.ptr,
               field_name ? field_name : "(none)");
    } else if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        return register_account_path_value(&value, field_name);
    } else if (value.source == CS_VALUE_SOURCE_CONSTANT) {
        uint8_t kind = 0;
        if (param.kind.ptr != NULL && param.kind.size == 1) {
            kind = param.kind.ptr[0];
        }
        if (cs_instruction_template_add_constant_field(value.payload.ptr,
                                                      value.payload.size,
                                                      kind,
                                                      field_name) != 0) {
            return -1;
        }
        PRINTF("substructure: registered constant field kind=%d size=%d name=%s\n",
               kind,
               value.payload.size,
               field_name ? field_name : "(none)");
    } else {
        PRINTF("substructure: PARAM_RAW source %d not supported\n", value.source);
        return -1;
    }
    return 0;
}

// Register a PARAM_ENUM display field (ARGUMENT_PATH, or ACCOUNT_PATH rendered as an address).
// The enum leaf is resolved by the walker to its selected variant's display name.
static int register_param_enum(const display_field_out_t *display_field, const char *field_name) {
    param_enum_out_t param = {0};
    if (!parse_param_enum(&display_field->param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM_ENUM parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_ENUM_TAG_VALUE)) {
        PRINTF("substructure: PARAM_ENUM missing VALUE\n");
        return -1;
    }

    // SKIP_INNER is optional and must be a single 0/1 byte. The path-driven
    // renderer already shows the variant name alone and displays inner-payload
    // fields only when the descriptor emits explicit inner display fields, so the
    // flag drives no rendering state; it is validated and accepted here.
    if (param.skip_inner.ptr != NULL && (param.skip_inner.size != 1 || param.skip_inner.ptr[0] > 1)) {
        PRINTF("substructure: PARAM_ENUM SKIP_INNER must be a 0/1 byte (size %d)\n",
               param.skip_inner.size);
        return -1;
    }

    cs_value_t value;
    if (extract_value(&param.value, &value) != 0) {
        return -1;
    }
    if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        return register_account_path_value(&value, field_name);
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_ENUM requires ARGUMENT or ACCOUNT path, got %d\n",
               value.source);
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                 value.payload.size,
                                                 CS_PARAM_TYPE_ENUM,
                                                 field_name) != 0) {
        return -1;
    }
    PRINTF("substructure: registered ENUM path %.*H name=%s\n",
           value.payload.size,
           value.payload.ptr,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_AMOUNT display field (ARGUMENT_PATH, or ACCOUNT_PATH rendered as an address).
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
    if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        return register_account_path_value(&value, field_name);
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_AMOUNT requires ARGUMENT or ACCOUNT path, got %d\n",
               value.source);
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                 value.payload.size,
                                                 CS_PARAM_TYPE_AMOUNT,
                                                 field_name) != 0) {
        return -1;
    }

    uint8_t decimals = 0;
    if (param.decimals.ptr != NULL && param.decimals.size == 1) {
        decimals = param.decimals.ptr[0];
    }
    if (cs_instruction_template_set_format_amount(decimals,
                                                  param.max_label.ptr,
                                                  param.max_label.size) != 0) {
        PRINTF("substructure: set_format_amount failed\n");
        return -1;
    }
    PRINTF("substructure: registered AMOUNT path %.*H decimals=%d name=%s\n",
           value.payload.size,
           value.payload.ptr,
           decimals,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_TOKEN_AMOUNT display field (ARGUMENT_PATH, or ACCOUNT_PATH rendered as an address).
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
    if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        return register_account_path_value(&value, field_name);
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_TOKEN_AMOUNT requires ARGUMENT or ACCOUNT path, got %d\n",
               value.source);
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                 value.payload.size,
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
            if (token.payload.size != 1) {
                PRINTF("substructure: TOKEN ACCOUNT_PATH payload size %d != 1\n",
                       token.payload.size);
                return -1;
            }
            format.mint_source = CS_TOKEN_MINT_ACCOUNT_INDEX;
            format.ref.account_index = token.payload.ptr[0];
        } else if (token.source == CS_VALUE_SOURCE_CONSTANT) {
            if (token.payload.size != 32) {
                PRINTF("substructure: TOKEN CONSTANT payload size %d != 32\n", token.payload.size);
                return -1;
            }
            format.mint_source = CS_TOKEN_MINT_CONSTANT;
            memcpy(format.ref.mint, token.payload.ptr, 32);
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
        if (decimals.source != CS_VALUE_SOURCE_CONSTANT || decimals.payload.size != 1) {
            PRINTF("substructure: DECIMALS must be a 1-byte CONSTANT (source %d size %d)\n",
                   decimals.source,
                   decimals.payload.size);
            return -1;
        }
        format.has_decimals = true;
        format.decimals = decimals.payload.ptr[0];
    }

    if (cs_instruction_template_set_format_token_amount(&format,
                                                         param.max_label.ptr,
                                                         param.max_label.size) != 0) {
        PRINTF("substructure: set_format_token_amount failed\n");
        return -1;
    }

    PRINTF("substructure: registered TOKEN_AMOUNT path %.*H mint_source=%d name=%s\n",
           value.payload.size,
           value.payload.ptr,
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

// Register a PARAM_DATETIME display field (ARGUMENT_PATH, or ACCOUNT_PATH rendered as an address).
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
    if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        return register_account_path_value(&value, field_name);
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_DATETIME requires ARGUMENT or ACCOUNT path, got %d\n",
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

    if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                 value.payload.size,
                                                 CS_PARAM_TYPE_DATETIME,
                                                 field_name) != 0) {
        return -1;
    }
    if (cs_instruction_template_set_format_datetime(ticks_per_second) != 0) {
        PRINTF("substructure: set_format_datetime failed\n");
        return -1;
    }
    PRINTF("substructure: registered DATETIME path %.*H ticks=%d name=%s\n",
           value.payload.size,
           value.payload.ptr,
           ticks_per_second,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_UNIT display field (ARGUMENT_PATH, or ACCOUNT_PATH rendered as an address).
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
    if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        return register_account_path_value(&value, field_name);
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_UNIT requires ARGUMENT or ACCOUNT path, got %d\n",
               value.source);
        return -1;
    }

    uint8_t decimals = 0;
    bool prefix = false;
    if (param.decimals.ptr != NULL) {
        if (param.decimals.size != 1) {
            PRINTF("substructure: PARAM_UNIT DECIMALS must be 1 byte (got %d)\n",
                   param.decimals.size);
            return -1;
        }
        decimals = param.decimals.ptr[0];
    }
    if (param.prefix.ptr != NULL) {
        if (param.prefix.size != 1) {
            PRINTF("substructure: PARAM_UNIT PREFIX must be 1 byte (got %d)\n", param.prefix.size);
            return -1;
        }
        prefix = (param.prefix.ptr[0] == 1);
    }

    if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                 value.payload.size,
                                                 CS_PARAM_TYPE_UNIT,
                                                 field_name) != 0) {
        return -1;
    }
    if (cs_instruction_template_set_format_unit(param.symbol.ptr,
                                                param.symbol.size,
                                                decimals,
                                                prefix) != 0) {
        PRINTF("substructure: set_format_unit failed\n");
        return -1;
    }
    PRINTF("substructure: registered UNIT path %.*H symbol=%.*s decimals=%d prefix=%d name=%s\n",
           value.payload.size,
           value.payload.ptr,
           (int) param.symbol.size,
           param.symbol.ptr,
           decimals,
           prefix,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_STRING display field (ARGUMENT_PATH, or ACCOUNT_PATH rendered as an address).
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
    if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        return register_account_path_value(&value, field_name);
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: PARAM_STRING requires ARGUMENT or ACCOUNT path, got %d\n",
               value.source);
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

    if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                 value.payload.size,
                                                 CS_PARAM_TYPE_STRING,
                                                 field_name) != 0) {
        return -1;
    }
    if (cs_instruction_template_set_format_string(&format) != 0) {
        PRINTF("substructure: set_format_string failed\n");
        return -1;
    }
    PRINTF("substructure: registered STRING path %.*H encoding=%d has_slice=%d name=%s\n",
           value.payload.size,
           value.payload.ptr,
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

    if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                 value.payload.size,
                                                 CS_PARAM_TYPE_TRUSTED_NAME,
                                                 field_name) != 0) {
        return -1;
    }
    if (cs_instruction_template_set_format_trusted_name(&format) != 0) {
        PRINTF("substructure: set_format_trusted_name failed\n");
        return -1;
    }
    PRINTF("substructure: registered TRUSTED_NAME path %.*H types=0x%02x name=%s\n",
           value.payload.size,
           value.payload.ptr,
           format.allowed_types_mask,
           field_name ? field_name : "(none)");
    return 0;
}

// Register a PARAM_ACCOUNT, PARAM_DURATION or PARAM_TRUSTED_NAME display field.
// All reuse the PARAM_RAW envelope (VERSION + VALUE) and carry no extra format
// parameters; only the resulting param_type differs. Accepts an ARGUMENT_PATH
// value, or an ACCOUNT_PATH value rendered as a base58 address.
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
    if (value.source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        return register_account_path_value(&value, field_name);
    }
    if (value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: param_type %d requires ARGUMENT or ACCOUNT path, got %d\n",
               param_type,
               value.source);
        return -1;
    }

    if (cs_instruction_template_add_display_path(value.payload.ptr,
                                                 value.payload.size,
                                                 param_type,
                                                 field_name) != 0) {
        return -1;
    }
    PRINTF("substructure: registered param_type %d path %.*H name=%s\n",
           param_type,
           value.payload.size,
           value.payload.ptr,
           field_name ? field_name : "(none)");
    return 0;
}

// Dispatch a parsed DISPLAY_FIELD to the correct PARAM parser based on the
// declared param_type. `field_name` is the NUL-terminated label (or NULL).
static int dispatch_display_field(const display_field_out_t *display_field,
                                  const char *field_name) {
    switch (display_field->param_type) {
        case CS_PARAM_TYPE_RAW:
            return register_param_raw(display_field, field_name);

        case CS_PARAM_TYPE_AMOUNT:
            return register_param_amount(display_field, field_name);

        case CS_PARAM_TYPE_TOKEN_AMOUNT:
            return register_param_token_amount(display_field, field_name);

        case CS_PARAM_TYPE_ENUM:
            return register_param_enum(display_field, field_name);

        case CS_PARAM_TYPE_DATETIME:
            return register_param_datetime(display_field, field_name);

        case CS_PARAM_TYPE_DURATION:
            return register_param_plain_argument(display_field,
                                                 field_name,
                                                 CS_PARAM_TYPE_DURATION);

        case CS_PARAM_TYPE_UNIT:
            return register_param_unit(display_field, field_name);

        case CS_PARAM_TYPE_ACCOUNT:
            return register_param_plain_argument(display_field,
                                                 field_name,
                                                 CS_PARAM_TYPE_ACCOUNT);

        case CS_PARAM_TYPE_STRING:
            return register_param_string(display_field, field_name);

        case CS_PARAM_TYPE_TRUSTED_NAME:
            return register_param_trusted_name(display_field, field_name);

        default:
            PRINTF("substructure: unsupported param_type %d\n", display_field->param_type);
            return -1;
    }
}

// Parse a DISPLAY_FIELD substructure and register it, materializing the optional
// NUL-terminated label from its message view for the duration of registration.
static int register_display_field(uint8_t apdu_type, const uint8_t *tlv, size_t tlv_size) {
    display_field_out_t display_field = {0};
    if (parse_display_field_envelope(apdu_type, tlv, tlv_size, &display_field) != 0) {
        return -1;
    }

    char *field_name = NULL;
    if (display_field.name.size > 0) {
        if (!APP_MEM_CALLOC((void **) &field_name, display_field.name.size + 1)) {
            PRINTF("substructure: field name allocation failed\n");
            return -1;
        }
        memcpy(field_name, display_field.name.ptr, display_field.name.size);
    }

    int result = dispatch_display_field(&display_field, field_name);

    if (field_name != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &field_name);
    }
    return result;
}

// ---- Merge-engine substructures: VALUE_FLOW_PORT / HIDE_RULE / ACCOUNT_RESET --
// These are decoded and forwarded into the instruction template so the merge
// engine can perform value-flow matching and hiding. Embedded VALUE / AMOUNT_VALUE
// / TOKEN_VALUE / RESET_SCOPE are parsed with their own nested parsers; the built
// structs carry borrowed views that the template's add_* setters deep-copy.

// Copy a parsed VALUE into a borrowed cs_stored_value_t (no allocation).
static void borrow_value(cs_stored_value_t *dst, const cs_value_t *value) {
    dst->source = value->source;
    dst->payload = (uint8_t *) value->payload.ptr;
    dst->payload_size = value->payload.size;
}

// ---- AMOUNT_VALUE nested parser ---------------------------------------------

typedef struct amount_value_out_s {
    TLV_reception_t received_tags;
    uint8_t kind;
    buffer_t value;
} amount_value_out_t;

static bool amount_value_handle_kind(const tlv_data_t *data, amount_value_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->kind);
}

static bool amount_value_handle_value(const tlv_data_t *data, amount_value_out_t *out) {
    out->value = data->value;
    return true;
}

// clang-format off
#define AMOUNT_VALUE_TAGS(X) \
    X(0x01, AMOUNT_VALUE_TAG_KIND,  amount_value_handle_kind,  ENFORCE_UNIQUE_TAG) \
    X(0x02, AMOUNT_VALUE_TAG_VALUE, amount_value_handle_value, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(AMOUNT_VALUE_TAGS, NULL, parse_amount_value)

// Whether a NUMERIC amount can actually yield a number, which not every VALUE can.
static bool numeric_amount_source_is_valid(const cs_value_t *value) {
    // A path into the instruction data takes its width from the IDL type pool, so nothing
    // here can judge it; the walk checks the leaf it lands on instead.
    if (value->source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
        return true;
    }
    // That leaves a literal. An ACCOUNT_PATH would give an address, which is no amount, so
    // a descriptor asking for one is malformed and refused now rather than stored.
    if (value->source != CS_VALUE_SOURCE_CONSTANT) {
        PRINTF("substructure: amount source %d resolves to no number\n", value->source);
        return false;
    }
    // A literal carries no kind, so its byte count has to be a width a number can occupy.
    // The kind itself is of no use here and is worked out again at finalize.
    uint8_t leaf_kind = 0;
    if (idl_unsigned_kind_for_width(value->payload.size, &leaf_kind) != 0) {
        PRINTF("substructure: constant amount size %d is not an integer width\n",
               (int) value->payload.size);
        return false;
    }
    return true;
}

// Parse an AMOUNT_VALUE buffer into a borrowed cs_amount_value_t. Returns 0, -1.
static int parse_amount_value_into(const buffer_t *buf, cs_amount_value_t *out) {
    amount_value_out_t parsed = {0};
    if (!parse_amount_value(buf, &parsed, &parsed.received_tags)) {
        PRINTF("substructure: AMOUNT_VALUE parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, AMOUNT_VALUE_TAG_KIND)) {
        PRINTF("substructure: AMOUNT_VALUE missing KIND\n");
        return -1;
    }
    bool has_value = TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, AMOUNT_VALUE_TAG_VALUE);
    if (parsed.kind == CS_AMOUNT_KIND_NUMERIC) {
        if (!has_value) {
            PRINTF("substructure: AMOUNT_VALUE NUMERIC requires VALUE\n");
            return -1;
        }
    } else if (parsed.kind == CS_AMOUNT_KIND_BALANCE) {
        if (has_value) {
            PRINTF("substructure: AMOUNT_VALUE BALANCE cannot carry VALUE\n");
            return -1;
        }
    } else {
        PRINTF("substructure: AMOUNT_VALUE unknown KIND %d\n", parsed.kind);
        return -1;
    }
    out->kind = parsed.kind;
    out->has_value = has_value;
    if (has_value) {
        cs_value_t value;
        if (extract_value(&parsed.value, &value) != 0) {
            return -1;
        }
        if (!numeric_amount_source_is_valid(&value)) {
            return -1;
        }
        borrow_value(&out->value, &value);
    }
    return 0;
}

// ---- TOKEN_VALUE nested parser ----------------------------------------------

typedef struct token_value_out_s {
    TLV_reception_t received_tags;
    uint8_t kind;
    buffer_t value;
    uint8_t account;
    uint8_t fallback_account;
} token_value_out_t;

static bool token_value_handle_kind(const tlv_data_t *data, token_value_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->kind);
}

static bool token_value_handle_value(const tlv_data_t *data, token_value_out_t *out) {
    out->value = data->value;
    return true;
}

static bool token_value_handle_account(const tlv_data_t *data, token_value_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->account);
}

static bool token_value_handle_fallback(const tlv_data_t *data, token_value_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->fallback_account);
}

// clang-format off
#define TOKEN_VALUE_TAGS(X) \
    X(0x01, TOKEN_VALUE_TAG_KIND,     token_value_handle_kind,     ENFORCE_UNIQUE_TAG) \
    X(0x02, TOKEN_VALUE_TAG_VALUE,    token_value_handle_value,    ENFORCE_UNIQUE_TAG) \
    X(0x03, TOKEN_VALUE_TAG_ACCOUNT,  token_value_handle_account,  ENFORCE_UNIQUE_TAG) \
    X(0x04, TOKEN_VALUE_TAG_FALLBACK, token_value_handle_fallback, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(TOKEN_VALUE_TAGS, NULL, parse_token_value)

// Parse a TOKEN_VALUE buffer into a borrowed cs_token_value_t. Returns 0, -1.
static int parse_token_value_into(const buffer_t *buf, cs_token_value_t *out) {
    token_value_out_t parsed = {0};
    if (!parse_token_value(buf, &parsed, &parsed.received_tags)) {
        PRINTF("substructure: TOKEN_VALUE parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, TOKEN_VALUE_TAG_KIND)) {
        PRINTF("substructure: TOKEN_VALUE missing KIND\n");
        return -1;
    }
    bool has_value = TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, TOKEN_VALUE_TAG_VALUE);
    bool has_account = TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, TOKEN_VALUE_TAG_ACCOUNT);
    bool has_fallback = TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, TOKEN_VALUE_TAG_FALLBACK);
    switch (parsed.kind) {
        case CS_TOKEN_KIND_DIRECT:
            if (!has_value) {
                PRINTF("substructure: TOKEN_VALUE DIRECT requires VALUE\n");
                return -1;
            }
            if (has_account) {
                PRINTF("substructure: TOKEN_VALUE DIRECT cannot carry ACCOUNT\n");
                return -1;
            }
            break;
        case CS_TOKEN_KIND_RESOLVE:
            if (has_value) {
                PRINTF("substructure: TOKEN_VALUE RESOLVE cannot carry VALUE\n");
                return -1;
            }
            break;
        case CS_TOKEN_KIND_NULL:
        case CS_TOKEN_KIND_NATIVE:
            if (has_value || has_account) {
                PRINTF("substructure: TOKEN_VALUE NULL/NATIVE cannot carry VALUE/ACCOUNT\n");
                return -1;
            }
            break;
        default:
            PRINTF("substructure: TOKEN_VALUE unknown KIND %d\n", parsed.kind);
            return -1;
    }
    out->kind = parsed.kind;
    out->has_value = has_value;
    if (has_value) {
        cs_value_t value;
        if (extract_value(&parsed.value, &value) != 0) {
            return -1;
        }
        borrow_value(&out->value, &value);
    }
    // ACCOUNT / FALLBACK_ACCOUNT are only meaningful for RESOLVE.
    if (parsed.kind == CS_TOKEN_KIND_RESOLVE) {
        out->has_account = has_account;
        out->account_index = parsed.account;
        out->has_fallback_account = has_fallback;
        out->fallback_account_index = parsed.fallback_account;
    }
    return 0;
}

// ---- RESET_SCOPE nested parser ----------------------------------------------

typedef struct reset_scope_out_s {
    TLV_reception_t received_tags;
    buffer_t program_id;
    cs_reset_discriminator_t *discriminators;  // heap scratch; borrowed data pointers
    size_t discriminator_count;
} reset_scope_out_t;

static bool reset_scope_handle_program_id(const tlv_data_t *data, reset_scope_out_t *out) {
    return get_buffer_from_tlv_data(data, &out->program_id, 32, 32);
}

static bool reset_scope_handle_discriminator(const tlv_data_t *data, reset_scope_out_t *out) {
    if (data->value.size > 8) {
        PRINTF("substructure: SCOPE_DISCRIMINATOR too long (%d)\n", data->value.size);
        return false;
    }
    cs_reset_discriminator_t *grown =
        APP_MEM_REALLOC(out->discriminators, (out->discriminator_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("substructure: SCOPE_DISCRIMINATOR list growth failed\n");
        return false;
    }
    out->discriminators = grown;
    out->discriminators[out->discriminator_count].data = (uint8_t *) data->value.ptr;
    out->discriminators[out->discriminator_count].size = (uint8_t) data->value.size;
    out->discriminator_count++;
    return true;
}

// clang-format off
#define RESET_SCOPE_TAGS(X) \
    X(0x01, RESET_SCOPE_TAG_PROGRAM_ID,    reset_scope_handle_program_id,    ENFORCE_UNIQUE_TAG) \
    X(0x02, RESET_SCOPE_TAG_DISCRIMINATOR, reset_scope_handle_discriminator, ALLOW_MULTIPLE_TAG)
// clang-format on

DEFINE_TLV_PARSER(RESET_SCOPE_TAGS, NULL, parse_reset_scope)

// ---- VALUE_FLOW_PORT parser -------------------------------------------------

typedef struct value_flow_port_out_s {
    TLV_reception_t received_tags;
    uint8_t substruct_type;
    uint8_t direction;
    uint8_t *account_candidates;  // heap scratch, ordered
    size_t candidate_count;
    uint8_t value_kind;
    buffer_t amount_value;
    buffer_t token_value;
    buffer_t active_when;
    uint8_t optional_account_strategy;
} value_flow_port_out_t;

static bool vfp_handle_substruct_type(const tlv_data_t *data, value_flow_port_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->substruct_type);
}

static bool vfp_handle_direction(const tlv_data_t *data, value_flow_port_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->direction);
}

static bool vfp_handle_account_index(const tlv_data_t *data, value_flow_port_out_t *out) {
    uint8_t index;
    if (!get_uint8_t_from_tlv_data(data, &index)) {
        return false;
    }
    uint8_t *grown = APP_MEM_REALLOC(out->account_candidates, out->candidate_count + 1);
    if (grown == NULL) {
        PRINTF("substructure: VALUE_FLOW_PORT candidate list growth failed\n");
        return false;
    }
    out->account_candidates = grown;
    out->account_candidates[out->candidate_count] = index;
    out->candidate_count++;
    return true;
}

static bool vfp_handle_value_kind(const tlv_data_t *data, value_flow_port_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->value_kind);
}

static bool vfp_handle_amount_value(const tlv_data_t *data, value_flow_port_out_t *out) {
    out->amount_value = data->value;
    return true;
}

static bool vfp_handle_token_value(const tlv_data_t *data, value_flow_port_out_t *out) {
    out->token_value = data->value;
    return true;
}

static bool vfp_handle_active_when(const tlv_data_t *data, value_flow_port_out_t *out) {
    out->active_when = data->value;
    return true;
}

static bool vfp_handle_strategy(const tlv_data_t *data, value_flow_port_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->optional_account_strategy);
}

// clang-format off
#define VALUE_FLOW_PORT_TAGS(X) \
    X(0x00, VFP_TAG_VERSION,        NULL,                    ENFORCE_UNIQUE_TAG) \
    X(0x01, VFP_TAG_SUBSTRUCT_TYPE, vfp_handle_substruct_type, ENFORCE_UNIQUE_TAG) \
    X(0x02, VFP_TAG_DIRECTION,      vfp_handle_direction,    ENFORCE_UNIQUE_TAG) \
    X(0x03, VFP_TAG_ACCOUNT_INDEX,  vfp_handle_account_index, ALLOW_MULTIPLE_TAG) \
    X(0x04, VFP_TAG_VALUE_KIND,     vfp_handle_value_kind,   ENFORCE_UNIQUE_TAG) \
    X(0x05, VFP_TAG_AMOUNT_VALUE,   vfp_handle_amount_value, ENFORCE_UNIQUE_TAG) \
    X(0x06, VFP_TAG_TOKEN_VALUE,    vfp_handle_token_value,  ENFORCE_UNIQUE_TAG) \
    X(0x07, VFP_TAG_ACTIVE_WHEN,    vfp_handle_active_when,  ENFORCE_UNIQUE_TAG) \
    X(0x08, VFP_TAG_STRATEGY,       vfp_handle_strategy,     ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(VALUE_FLOW_PORT_TAGS, NULL, parse_value_flow_port)

// Parse a VALUE_FLOW_PORT, build a borrowed port, and add it to the template.
// The candidate-list scratch in *parsed is freed by the caller. Returns 0, -1.
static int value_flow_port_build_and_add(uint8_t apdu_type,
                                         const uint8_t *tlv,
                                         size_t tlv_size,
                                         value_flow_port_out_t *parsed) {
    buffer_t payload = {.ptr = (uint8_t *) tlv, .size = tlv_size};
    if (!parse_value_flow_port(&payload, parsed, &parsed->received_tags)) {
        PRINTF("substructure: VALUE_FLOW_PORT parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(parsed->received_tags,
                                 VFP_TAG_SUBSTRUCT_TYPE,
                                 VFP_TAG_DIRECTION,
                                 VFP_TAG_ACCOUNT_INDEX,
                                 VFP_TAG_VALUE_KIND,
                                 VFP_TAG_AMOUNT_VALUE)) {
        PRINTF("substructure: VALUE_FLOW_PORT missing required tags\n");
        return -1;
    }
    if (parsed->substruct_type != apdu_type) {
        PRINTF("substructure: VALUE_FLOW_PORT SUBSTRUCT_TYPE=%d != APDU type=%d\n",
               parsed->substruct_type,
               apdu_type);
        return -1;
    }
    if (parsed->direction != CS_PORT_DIRECTION_INPUT &&
        parsed->direction != CS_PORT_DIRECTION_OUTPUT) {
        PRINTF("substructure: VALUE_FLOW_PORT unknown DIRECTION %d\n", parsed->direction);
        return -1;
    }
    if (parsed->value_kind != CS_PORT_VALUE_KIND_NATIVE &&
        parsed->value_kind != CS_PORT_VALUE_KIND_SPL_TOKEN) {
        PRINTF("substructure: VALUE_FLOW_PORT unknown VALUE_KIND %d\n", parsed->value_kind);
        return -1;
    }

    cs_value_flow_port_t port = {0};
    port.direction = parsed->direction;
    port.account_candidates = parsed->account_candidates;
    port.candidate_count = parsed->candidate_count;
    port.value_kind = parsed->value_kind;
    if (parse_amount_value_into(&parsed->amount_value, &port.amount) != 0) {
        return -1;
    }
    if (TLV_CHECK_RECEIVED_TAGS(parsed->received_tags, VFP_TAG_TOKEN_VALUE)) {
        port.has_token = true;
        if (parse_token_value_into(&parsed->token_value, &port.token) != 0) {
            return -1;
        }
    }
    if (TLV_CHECK_RECEIVED_TAGS(parsed->received_tags, VFP_TAG_ACTIVE_WHEN)) {
        port.active_when = (uint8_t *) parsed->active_when.ptr;
        port.active_when_size = parsed->active_when.size;
    }
    port.optional_account_strategy = CS_OPTIONAL_ACCOUNT_STRATEGY_PROGRAM_ID;
    if (TLV_CHECK_RECEIVED_TAGS(parsed->received_tags, VFP_TAG_STRATEGY)) {
        if (parsed->optional_account_strategy != CS_OPTIONAL_ACCOUNT_STRATEGY_PROGRAM_ID &&
            parsed->optional_account_strategy != CS_OPTIONAL_ACCOUNT_STRATEGY_OMITTED) {
            PRINTF("substructure: VALUE_FLOW_PORT unknown OPTIONAL_ACCOUNT_STRATEGY %d\n",
                   parsed->optional_account_strategy);
            return -1;
        }
        port.optional_account_strategy = parsed->optional_account_strategy;
    }

    if (cs_instruction_template_add_port(&port) != 0) {
        PRINTF("substructure: add_port failed\n");
        return -1;
    }
    PRINTF("substructure: registered VALUE_FLOW_PORT direction=%d candidates=%d\n",
           port.direction,
           (int) port.candidate_count);
    return 0;
}

static int register_value_flow_port(uint8_t apdu_type, const uint8_t *tlv, size_t tlv_size) {
    value_flow_port_out_t parsed = {0};
    int rc = value_flow_port_build_and_add(apdu_type, tlv, tlv_size, &parsed);
    if (parsed.account_candidates != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &parsed.account_candidates);
    }
    return rc;
}

// ---- HIDE_RULE parser -------------------------------------------------------

typedef struct hide_rule_out_s {
    TLV_reception_t received_tags;
    uint8_t substruct_type;
    uint8_t rule_set_index;
    buffer_t target;
    uint8_t condition;
} hide_rule_out_t;

static bool hide_rule_handle_substruct_type(const tlv_data_t *data, hide_rule_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->substruct_type);
}

static bool hide_rule_handle_rule_set_index(const tlv_data_t *data, hide_rule_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->rule_set_index);
}

static bool hide_rule_handle_target(const tlv_data_t *data, hide_rule_out_t *out) {
    out->target = data->value;
    return true;
}

static bool hide_rule_handle_condition(const tlv_data_t *data, hide_rule_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->condition);
}

// clang-format off
#define HIDE_RULE_TAGS(X) \
    X(0x00, HIDE_RULE_TAG_VERSION,        NULL,                          ENFORCE_UNIQUE_TAG) \
    X(0x01, HIDE_RULE_TAG_SUBSTRUCT_TYPE, hide_rule_handle_substruct_type, ENFORCE_UNIQUE_TAG) \
    X(0x02, HIDE_RULE_TAG_RULE_SET_INDEX, hide_rule_handle_rule_set_index, ENFORCE_UNIQUE_TAG) \
    X(0x03, HIDE_RULE_TAG_TARGET,         hide_rule_handle_target,       ENFORCE_UNIQUE_TAG) \
    X(0x04, HIDE_RULE_TAG_CONDITION,      hide_rule_handle_condition,    ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(HIDE_RULE_TAGS, NULL, parse_hide_rule)

static int register_hide_rule(uint8_t apdu_type, const uint8_t *tlv, size_t tlv_size) {
    hide_rule_out_t parsed = {0};
    buffer_t payload = {.ptr = (uint8_t *) tlv, .size = tlv_size};
    if (!parse_hide_rule(&payload, &parsed, &parsed.received_tags)) {
        PRINTF("substructure: HIDE_RULE parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(parsed.received_tags,
                                 HIDE_RULE_TAG_SUBSTRUCT_TYPE,
                                 HIDE_RULE_TAG_RULE_SET_INDEX,
                                 HIDE_RULE_TAG_TARGET,
                                 HIDE_RULE_TAG_CONDITION)) {
        PRINTF("substructure: HIDE_RULE missing required tags\n");
        return -1;
    }
    if (parsed.substruct_type != apdu_type) {
        PRINTF("substructure: HIDE_RULE SUBSTRUCT_TYPE=%d != APDU type=%d\n",
               parsed.substruct_type,
               apdu_type);
        return -1;
    }
    if (parsed.condition > CS_HIDE_CONDITION_ACCOUNT_EFFECTS_DISPLAYED_ELSEWHERE) {
        PRINTF("substructure: HIDE_RULE unknown CONDITION %d\n", parsed.condition);
        return -1;
    }

    cs_value_t target;
    if (extract_value(&parsed.target, &target) != 0) {
        return -1;
    }
    cs_hide_rule_t rule = {0};
    rule.rule_set_index = parsed.rule_set_index;
    rule.condition = parsed.condition;
    borrow_value(&rule.target, &target);
    if (cs_instruction_template_add_hide_rule(&rule) != 0) {
        PRINTF("substructure: add_hide_rule failed\n");
        return -1;
    }
    PRINTF("substructure: registered HIDE_RULE set=%d condition=%d\n",
           rule.rule_set_index,
           rule.condition);
    return 0;
}

// ---- ACCOUNT_RESET parser ---------------------------------------------------

typedef struct account_reset_out_s {
    TLV_reception_t received_tags;
    uint8_t substruct_type;
    uint8_t account_index;
    uint8_t require_pre_balance_zero;
    buffer_t reset_value;
    buffer_t reset_scope;
} account_reset_out_t;

static bool account_reset_handle_substruct_type(const tlv_data_t *data, account_reset_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->substruct_type);
}

static bool account_reset_handle_account_index(const tlv_data_t *data, account_reset_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->account_index);
}

static bool account_reset_handle_require_zero(const tlv_data_t *data, account_reset_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->require_pre_balance_zero);
}

static bool account_reset_handle_reset_value(const tlv_data_t *data, account_reset_out_t *out) {
    out->reset_value = data->value;
    return true;
}

static bool account_reset_handle_reset_scope(const tlv_data_t *data, account_reset_out_t *out) {
    out->reset_scope = data->value;
    return true;
}

// clang-format off
#define ACCOUNT_RESET_TAGS(X) \
    X(0x00, AR_TAG_VERSION,         NULL,                              ENFORCE_UNIQUE_TAG) \
    X(0x01, AR_TAG_SUBSTRUCT_TYPE,  account_reset_handle_substruct_type, ENFORCE_UNIQUE_TAG) \
    X(0x02, AR_TAG_ACCOUNT_INDEX,   account_reset_handle_account_index, ENFORCE_UNIQUE_TAG) \
    X(0x03, AR_TAG_REQUIRE_ZERO,    account_reset_handle_require_zero,  ENFORCE_UNIQUE_TAG) \
    X(0x04, AR_TAG_RESET_VALUE,     account_reset_handle_reset_value,   ENFORCE_UNIQUE_TAG) \
    X(0x05, AR_TAG_RESET_SCOPE,     account_reset_handle_reset_scope,   ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(ACCOUNT_RESET_TAGS, NULL, parse_account_reset)

// Parse an ACCOUNT_RESET, build a borrowed reset, and add it to the template.
// The RESET_SCOPE discriminator scratch in *scope_scratch is freed by the caller.
static int account_reset_build_and_add(uint8_t apdu_type,
                                       const uint8_t *tlv,
                                       size_t tlv_size,
                                       reset_scope_out_t *scope_scratch) {
    account_reset_out_t parsed = {0};
    buffer_t payload = {.ptr = (uint8_t *) tlv, .size = tlv_size};
    if (!parse_account_reset(&payload, &parsed, &parsed.received_tags)) {
        PRINTF("substructure: ACCOUNT_RESET parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(parsed.received_tags,
                                 AR_TAG_SUBSTRUCT_TYPE,
                                 AR_TAG_ACCOUNT_INDEX)) {
        PRINTF("substructure: ACCOUNT_RESET missing required tags\n");
        return -1;
    }
    if (parsed.substruct_type != apdu_type) {
        PRINTF("substructure: ACCOUNT_RESET SUBSTRUCT_TYPE=%d != APDU type=%d\n",
               parsed.substruct_type,
               apdu_type);
        return -1;
    }

    cs_account_reset_t reset = {0};
    reset.account_index = parsed.account_index;
    if (TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, AR_TAG_REQUIRE_ZERO)) {
        reset.require_pre_balance_zero = (parsed.require_pre_balance_zero != 0);
    }
    if (TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, AR_TAG_RESET_VALUE)) {
        reset.has_reset_value = true;
        if (parse_amount_value_into(&parsed.reset_value, &reset.reset_value) != 0) {
            return -1;
        }
        if (reset.reset_value.kind == CS_AMOUNT_KIND_BALANCE) {
            PRINTF("substructure: ACCOUNT_RESET RESET_VALUE cannot be BALANCE\n");
            return -1;
        }
    }
    if (TLV_CHECK_RECEIVED_TAGS(parsed.received_tags, AR_TAG_RESET_SCOPE)) {
        if (!parse_reset_scope(&parsed.reset_scope, scope_scratch, &scope_scratch->received_tags)) {
            PRINTF("substructure: RESET_SCOPE parsing failed\n");
            return -1;
        }
        if (!TLV_CHECK_RECEIVED_TAGS(scope_scratch->received_tags, RESET_SCOPE_TAG_PROGRAM_ID)) {
            PRINTF("substructure: RESET_SCOPE missing SCOPE_PROGRAM_ID\n");
            return -1;
        }
        reset.has_scope = true;
        reset.scope.has_program_id = true;
        memcpy(reset.scope.scope_program_id, scope_scratch->program_id.ptr, 32);
        reset.scope.discriminators = scope_scratch->discriminators;
        reset.scope.discriminator_count = scope_scratch->discriminator_count;
    }

    if (cs_instruction_template_add_account_reset(&reset) != 0) {
        PRINTF("substructure: add_account_reset failed\n");
        return -1;
    }
    PRINTF("substructure: registered ACCOUNT_RESET account=%d require_zero=%d\n",
           reset.account_index,
           reset.require_pre_balance_zero);
    return 0;
}

static int register_account_reset(uint8_t apdu_type, const uint8_t *tlv, size_t tlv_size) {
    reset_scope_out_t scope_scratch = {0};
    int rc = account_reset_build_and_add(apdu_type, tlv, tlv_size, &scope_scratch);
    if (scope_scratch.discriminators != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &scope_scratch.discriminators);
    }
    return rc;
}

int handle_provide_instruction_substructure(void) {
    PRINTF("handle_provide_instruction_substructure\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return reply_sw(state_err);
    }

    if (cs_instruction_template_current() == NULL) {
        PRINTF("substructure: no instruction template open\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (G_command.message_length < 1) {
        PRINTF("substructure: empty payload\n");
        return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
    }

    uint8_t type = G_command.message[0];
    const uint8_t *tlv = G_command.message + 1;
    size_t tlv_size = (size_t) G_command.message_length - 1;

    // Accumulate the substructure TLV (type byte excluded) into the running hash.
    if (cs_substructure_update(tlv, tlv_size) != 0) {
        PRINTF("substructure: hash accumulation refused\n");
        return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
    }

    // Every substructure type is decoded and forwarded into the template. The
    // hash was already accumulated above, so an unknown type is refused here.
    if (type == SUBSTRUCTURE_TYPE_DISPLAY_FIELD) {
        if (register_display_field(type, tlv, tlv_size) != 0) {
            PRINTF("substructure: register_display_field failed\n");
            return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
        }
    } else if (type == SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT) {
        if (register_value_flow_port(type, tlv, tlv_size) != 0) {
            PRINTF("substructure: register_value_flow_port failed\n");
            return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
        }
    } else if (type == SUBSTRUCTURE_TYPE_HIDE_RULE) {
        if (register_hide_rule(type, tlv, tlv_size) != 0) {
            PRINTF("substructure: register_hide_rule failed\n");
            return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
        }
    } else if (type == SUBSTRUCTURE_TYPE_ACCOUNT_RESET) {
        if (register_account_reset(type, tlv, tlv_size) != 0) {
            PRINTF("substructure: register_account_reset failed\n");
            return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
        }
    } else {
        PRINTF("substructure: unknown substructure type %d\n", type);
        return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
    }

    bool complete = false;
    if (cs_substructure_check_complete(&complete) != 0) {
        PRINTF("substructure: completeness check refused\n");
        return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
    }
    if (complete) {
        if (cs_instruction_template_commit() != 0) {
            PRINTF("substructure: template commit refused\n");
            return reply_sw(ApduReplySolanaInvalidInstructionSubstructure);
        }
        PRINTF("substructure: running hash matched, template committed\n");
    } else {
        PRINTF("substructure: hash not yet matched, awaiting more substructures\n");
    }

    return reply_sw(ApduReplySuccess);
}
