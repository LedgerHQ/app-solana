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

#define SUBSTRUCTURE_TYPE_DISPLAY_FIELD   0x00
#define SUBSTRUCTURE_TYPE_VALUE_FLOW_PORT 0x01
#define SUBSTRUCTURE_TYPE_HIDE_RULE       0x02
#define SUBSTRUCTURE_TYPE_ACCOUNT_RESET   0x03

// PARAM_* parser. VALUE always sits at tag 0x01; the type-specific tags
// (0x00, 0x02..0x06 across the PARAM_* variants) are accepted and ignored so a
// single parser handles every formatter type.
typedef struct param_out_s {
    TLV_reception_t received_tags;
    buffer_t value;
} param_out_t;

static bool param_handle_value(const tlv_data_t *data, param_out_t *out) {
    out->value = data->value;
    return true;
}

static bool param_handle_ignore(const tlv_data_t *data, param_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define PARAM_TAGS(X) \
    X(0x00, PARAM_TAG_VERSION, param_handle_ignore, ENFORCE_UNIQUE_TAG) \
    X(0x01, PARAM_TAG_VALUE,   param_handle_value,  ENFORCE_UNIQUE_TAG) \
    X(0x02, PARAM_TAG_OPT_2,   param_handle_ignore, ALLOW_MULTIPLE_TAG) \
    X(0x03, PARAM_TAG_OPT_3,   param_handle_ignore, ALLOW_MULTIPLE_TAG) \
    X(0x04, PARAM_TAG_OPT_4,   param_handle_ignore, ALLOW_MULTIPLE_TAG) \
    X(0x05, PARAM_TAG_OPT_5,   param_handle_ignore, ALLOW_MULTIPLE_TAG) \
    X(0x06, PARAM_TAG_OPT_6,   param_handle_ignore, ALLOW_MULTIPLE_TAG)
// clang-format on

DEFINE_TLV_PARSER(PARAM_TAGS, NULL, parse_param)

// DISPLAY_FIELD parser. PARAM (tag 0x04) and SUBSTRUCT_TYPE (tag 0x01) are
// captured; the others are accepted and ignored.
typedef struct display_field_out_s {
    TLV_reception_t received_tags;
    uint8_t substruct_type;
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

static bool display_field_handle_ignore(const tlv_data_t *data, display_field_out_t *out) {
    UNUSED(data);
    UNUSED(out);
    return true;
}

// clang-format off
#define DISPLAY_FIELD_TAGS(X) \
    X(0x00, DISPLAY_FIELD_TAG_VERSION,       display_field_handle_ignore,        ENFORCE_UNIQUE_TAG) \
    X(0x01, DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE, display_field_handle_substruct_type, ENFORCE_UNIQUE_TAG) \
    X(0x02, DISPLAY_FIELD_TAG_NAME,          display_field_handle_ignore,        ENFORCE_UNIQUE_TAG) \
    X(0x03, DISPLAY_FIELD_TAG_PARAM_TYPE,    display_field_handle_ignore,        ENFORCE_UNIQUE_TAG) \
    X(0x04, DISPLAY_FIELD_TAG_PARAM,         display_field_handle_param,         ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(DISPLAY_FIELD_TAGS, NULL, parse_display_field)

// Extract the ARGUMENT_PATH of a DISPLAY_FIELD (if any) and record it on the
// current template so PROMPT UI DISPLAY can match walker leaves against it.
static int register_display_field(uint8_t apdu_type, const uint8_t *tlv, size_t tlv_size) {
    display_field_out_t display_field = {0};
    buffer_t display_field_payload = {.ptr = (uint8_t *) tlv, .size = tlv_size};
    if (!parse_display_field(&display_field_payload,
                             &display_field,
                             &display_field.received_tags)) {
        PRINTF("substructure: DISPLAY_FIELD parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(display_field.received_tags, DISPLAY_FIELD_TAG_SUBSTRUCT_TYPE)) {
        PRINTF("substructure: DISPLAY_FIELD missing SUBSTRUCT_TYPE\n");
        return -1;
    }
    if (display_field.substruct_type != apdu_type) {
        PRINTF("substructure: SUBSTRUCT_TYPE=%d != APDU type=%d\n",
               display_field.substruct_type,
               apdu_type);
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(display_field.received_tags, DISPLAY_FIELD_TAG_PARAM)) {
        PRINTF("substructure: DISPLAY_FIELD missing PARAM\n");
        return -1;
    }

    param_out_t param = {0};
    if (!parse_param(&display_field.param, &param, &param.received_tags)) {
        PRINTF("substructure: PARAM parsing failed\n");
        return -1;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(param.received_tags, PARAM_TAG_VALUE)) {
        PRINTF("substructure: PARAM missing VALUE\n");
        return -1;
    }

    cs_value_t value;
    if (!cs_parse_value_from_buffer(param.value.ptr, param.value.size, &value)) {
        PRINTF("substructure: VALUE parsing failed\n");
        return -1;
    }

    // Only ARGUMENT_PATH-sourced fields carry a walker path to match against.
    if (value.source != VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("substructure: DISPLAY_FIELD source %d carries no argument path\n", value.source);
        return 0;
    }

    if (cs_instruction_template_add_display_path(value.payload, value.payload_size) != 0) {
        return -1;
    }
    PRINTF("substructure: registered display path %.*H\n", value.payload_size, value.payload);
    return 0;
}

int handle_provide_instruction_substructure(void) {
    PRINTF("handle_provide_instruction_substructure\n");

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
