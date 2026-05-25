#pragma once

// VALUE sub-TLV parser for clear signing descriptors
//
// VALUE is used inside INSTRUCTION_INFO (OWNER_ASSOC_OWNER), DISPLAY_FIELD PARAMs,
// HIDE_RULE (TARGET), etc. Each .c file that includes this header gets its own
// static inline copy of the parser via DEFINE_TLV_PARSER.

#include "tlv_library.h"

#define VALUE_SOURCE_ARGUMENT_PATH 0x00
#define VALUE_SOURCE_ACCOUNT_PATH  0x01
#define VALUE_SOURCE_CONSTANT      0x02

#define CS_VALUE_MAX_PAYLOAD_LENGTH 64

typedef struct cs_value_s {
    TLV_reception_t received_tags;
    uint8_t source;
    uint8_t payload[CS_VALUE_MAX_PAYLOAD_LENGTH];
    size_t payload_size;
} cs_value_t;

static bool cs_value_handle_source(const tlv_data_t *data, cs_value_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->source);
}

static bool cs_value_handle_payload(const tlv_data_t *data, cs_value_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, 0, CS_VALUE_MAX_PAYLOAD_LENGTH)) {
        return false;
    }
    out->payload_size = temp.size;
    if (temp.size > 0) {
        memcpy(out->payload, temp.ptr, temp.size);
    }
    return true;
}

// clang-format off
#define CS_VALUE_TAGS(X) \
    X(0x01, CS_VALUE_TAG_SOURCE,  cs_value_handle_source,  ENFORCE_UNIQUE_TAG) \
    X(0x02, CS_VALUE_TAG_PAYLOAD, cs_value_handle_payload, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(CS_VALUE_TAGS, NULL, cs_parse_value)

// Parse a VALUE sub-TLV from a raw buffer
static inline bool cs_parse_value_from_buffer(const uint8_t *buf,
                                              size_t buf_size,
                                              cs_value_t *out) {
    explicit_bzero(out, sizeof(cs_value_t));
    buffer_t sub_payload = {.ptr = (uint8_t *) buf, .size = buf_size};
    if (!cs_parse_value(&sub_payload, out, &out->received_tags)) {
        return false;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(out->received_tags, CS_VALUE_TAG_SOURCE)) {
        return false;
    }
    return true;
}
