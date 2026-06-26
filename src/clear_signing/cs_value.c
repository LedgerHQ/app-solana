#include <string.h>

#include "cs_value.h"
#include "tlv_library.h"

// Internal wrapper coupling the output value with TLV parse state.
typedef struct cs_value_parse_ctx_s {
    cs_value_t value;
    TLV_reception_t received_tags;
} cs_value_parse_ctx_t;

static bool cs_value_handle_source(const tlv_data_t *data, cs_value_parse_ctx_t *ctx) {
    return get_uint8_t_from_tlv_data(data, &ctx->value.source);
}

static bool cs_value_handle_payload(const tlv_data_t *data, cs_value_parse_ctx_t *ctx) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, 0, CS_VALUE_MAX_PAYLOAD_LENGTH)) {
        return false;
    }
    ctx->value.payload_size = temp.size;
    if (temp.size > 0) {
        memcpy(ctx->value.payload, temp.ptr, temp.size);
    }
    return true;
}

// clang-format off
#define CS_VALUE_TAGS(X) \
    X(0x01, CS_VALUE_TAG_SOURCE,  cs_value_handle_source,  ENFORCE_UNIQUE_TAG) \
    X(0x02, CS_VALUE_TAG_PAYLOAD, cs_value_handle_payload, ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(CS_VALUE_TAGS, NULL, cs_parse_value)

bool cs_parse_value_from_buffer(const uint8_t *buf, size_t buf_size, cs_value_t *out) {
    cs_value_parse_ctx_t ctx;
    explicit_bzero(&ctx, sizeof(ctx));
    buffer_t sub_payload = {.ptr = (uint8_t *) buf, .size = buf_size};
    if (!cs_parse_value(&sub_payload, &ctx, &ctx.received_tags)) {
        return false;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(ctx.received_tags, CS_VALUE_TAG_SOURCE)) {
        return false;
    }
    memcpy(out, &ctx.value, sizeof(cs_value_t));
    return true;
}
