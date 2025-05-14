#include <cx.h>
#include <os.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "tlv_library.h"

#define DER_LONG_FORM_FLAG        0x80  // 8th bit set
#define DER_FIRST_BYTE_VALUE_MASK 0x7f

bool get_uint32_t_from_tlv_data(const tlv_data_t *data, uint32_t *value) {
    uint8_t size_diff;
    uint8_t buffer[sizeof(uint32_t)];

    if (data->length > sizeof(buffer)) {
        PRINTF("Unexpectedly long value (%u bytes) for tag 0x%x\n", data->length, data->tag);
        return false;
    }
    size_diff = sizeof(buffer) - data->length;
    memset(buffer, 0, size_diff);
    memcpy(buffer + size_diff, data->value, data->length);
    *value = U4BE(buffer, 0);
    return true;
}

bool get_uint16_t_from_tlv_data(const tlv_data_t *data, uint16_t *value) {
    uint32_t tmp_value;
    if (!get_uint32_t_from_tlv_data(data, &tmp_value) || (tmp_value > UINT16_MAX)) {
        return false;
    }
    *value = (uint16_t) tmp_value;
    return true;
}

bool get_uint8_t_from_tlv_data(const tlv_data_t *data, uint8_t *value) {
    uint32_t tmp_value;
    if (!get_uint32_t_from_tlv_data(data, &tmp_value) || (tmp_value > UINT8_MAX)) {
        return false;
    }
    *value = (uint8_t) tmp_value;
    return true;
}

bool get_buffer_from_tlv_data(const tlv_data_t *data,
                              buffer_t *out,
                              uint16_t min_size,
                              uint16_t max_size) {
    if (min_size != 0 && data->length < min_size) {
        PRINTF("Expected at least %d bytes, found %d\n", min_size, data->length);
        return false;
    }
    if (max_size != 0 && data->length > max_size) {
        PRINTF("Expected at most %d bytes, found %d\n", max_size, data->length);
        return false;
    }
    out->size = data->length;
    out->ptr = data->value;
    return true;
}

bool get_string_from_tlv_data(const tlv_data_t *data,
                              char *out,
                              uint16_t min_length,
                              uint16_t out_size) {
    // Reject TLV strings with embedded null bytes
    size_t actual_length = strnlen((const char *) data->value, data->length);
    if (actual_length != data->length) {
        PRINTF("Embedded null byte at offset %u\n", (unsigned) actual_length);
        return false;
    }

    if (min_length != 0 && data->length < min_length) {
        PRINTF("Expected at least %u bytes, found %u\n", min_length, data->length);
        return false;
    }
    // The input is not '\0' terminated
    if (out_size != 0 && data->length + 1 > out_size) {
        PRINTF("Expected at most %u bytes, found %u (+1)\n", out_size, data->length);
        return false;
    }

    memcpy(out, data->value, data->length);
    out[data->length] = '\0';

    return true;
}

/** Parse DER-encoded value
 *
 * Parses a DER-encoded value (up to 4 bytes long)
 * https://en.wikipedia.org/wiki/X.690
 *
 * @param[in] payload the TLV payload
 * @param[in,out] offset the payload offset
 * @param[out] value the parsed value
 * @return whether it was successful
 */
static bool get_der_value_as_uint32(const buffer_t *payload, size_t *offset, uint32_t *value) {
    bool ret = false;
    uint8_t byte_length;
    uint8_t buf[sizeof(*value)];

    if (value != NULL) {
        if (payload->ptr[*offset] & DER_LONG_FORM_FLAG) {  // long form
            byte_length = payload->ptr[*offset] & DER_FIRST_BYTE_VALUE_MASK;
            *offset += 1;
            if ((*offset + byte_length) > payload->size) {
                PRINTF("TLV payload too small for DER encoded value\n");
            } else {
                if (byte_length > sizeof(buf) || byte_length == 0) {
                    PRINTF("Unexpectedly long DER-encoded value (%u bytes)\n", byte_length);
                } else {
                    memset(buf, 0, (sizeof(buf) - byte_length));
                    memcpy(buf + (sizeof(buf) - byte_length), &payload->ptr[*offset], byte_length);
                    *value = U4BE(buf, 0);
                    *offset += byte_length;
                    ret = true;
                }
            }
        } else {  // short form
            *value = payload->ptr[*offset];
            *offset += 1;
            ret = true;
        }
    }
    return ret;
}

/** Parse DER-encoded value and fits it in uint16_t or fails
 */
static bool get_der_value_as_uint16(const buffer_t *payload, size_t *offset, uint16_t *value) {
    uint32_t tmp_value;
    if (!get_der_value_as_uint32(payload, offset, &tmp_value) || (tmp_value > UINT16_MAX)) {
        return false;
    }

    *value = (uint16_t) tmp_value;
    return true;
}

/** Parse DER-encoded value and fits it in uint8_t or fails
 */
__attribute__((unused)) static bool get_der_value_as_uint8(const buffer_t *payload,
                                                           size_t *offset,
                                                           uint8_t *value) {
    uint32_t tmp_value;
    if (!get_der_value_as_uint32(payload, offset, &tmp_value) || (tmp_value > UINT8_MAX)) {
        return false;
    }

    *value = (uint8_t) tmp_value;
    return true;
}

static bool set_tag(TLV_reception_t *received_tags_flags, TLV_tag_t tag) {
    TLV_flag_t flag = received_tags_flags->tag_to_flag_function(tag);
    if (received_tags_flags->flags & flag) {
        return false;
    }
    received_tags_flags->flags |= flag;
    return true;
}

bool tlv_check_received_tags(TLV_reception_t received, const TLV_tag_t *tags, size_t tag_count) {
    for (size_t i = 0; i < tag_count; i++) {
        TLV_flag_t flag = received.tag_to_flag_function(tags[i]);
        if (flag == 0) {
            PRINTF("No flag found for tag 0x%x\n", tags[i]);
            return false;
        }
        if ((received.flags & flag) != flag) {
            PRINTF("Tag 0x%x no received\n", tags[i]);
            return false;
        }
    }
    return true;
}

static const _internal_tlv_handler_t *find_handler(const _internal_tlv_handler_t *handlers,
                                                   uint8_t handlers_count,
                                                   TLV_tag_t tag) {
    // check if a handler exists for this tag
    for (uint8_t idx = 0; idx < handlers_count; ++idx) {
        if (handlers[idx].tag == tag) {
            return &handlers[idx];
        }
    }
    return NULL;
}

typedef enum tlv_step_e {
    TLV_TAG,
    TLV_LENGTH,
    TLV_VALUE,
} tlv_step_t;

bool _parse_tlv_internal(const _internal_tlv_handler_t *handlers,
                         uint8_t handlers_count,
                         tag_to_flag_function_t *tag_to_flag_function,
                         const buffer_t *payload,
                         void *tlv_out,
                         TLV_reception_t *received_tags_flags) {
    tlv_step_t step = TLV_TAG;
    tlv_data_t data;
    size_t offset = 0;
    size_t tag_start_offset;
    const _internal_tlv_handler_t *handler;

    explicit_bzero(received_tags_flags, sizeof(*received_tags_flags));
    received_tags_flags->tag_to_flag_function = tag_to_flag_function;

    // handle TLV payload
    while (offset < payload->size || (step == TLV_VALUE && data.length == 0)) {
        switch (step) {
            case TLV_TAG:
                tag_start_offset = offset;
                if (!get_der_value_as_uint32(payload, &offset, &data.tag)) {
                    return false;
                }
                handler = find_handler(handlers, handlers_count, data.tag);
                if (handler == NULL) {
                    PRINTF("No handler found for tag 0x%x\n", data.tag);
                    return false;
                }
                if (!set_tag(received_tags_flags, data.tag)) {
                    if (handler->is_unique) {
                        PRINTF("Tag = %d was already received and is flagged unique\n", data.tag);
                        return false;
                    }
                }
                step = TLV_LENGTH;
                break;

            case TLV_LENGTH:
                if (!get_der_value_as_uint16(payload, &offset, &data.length)) {
                    return false;
                }
                step = TLV_VALUE;
                break;

            case TLV_VALUE:
                if ((offset + data.length) > payload->size) {
                    PRINTF("Error: value would go beyond the TLV payload!\n");
                    return false;
                }
                if (data.length > 0) {
                    data.value = &payload->ptr[offset];
                    PRINTF("Handling tag 0x%02x length %d value '%.*H'\n",
                           data.tag,
                           data.length,
                           data.length,
                           data.value);
                } else {
                    data.value = NULL;
                    PRINTF("Handling tag 0x%02x length %d\n", data.tag, data.length);
                }
                offset += data.length;

                // Calculate raw TLV start/end to give to the handler
                data.raw = &payload->ptr[tag_start_offset];
                data.raw_size = offset - tag_start_offset;

                // Call this tag's handler if there is one
                tlv_handler_cb_t *fptr = PIC(handler->func);
                if (fptr != NULL && !(*fptr)(&data, tlv_out)) {
                    PRINTF("Handler error while handling tag 0x%x\n", handler->tag);
                    return false;
                }

                step = TLV_TAG;
                break;

            default:
                return false;
        }
    }
    if (step != TLV_TAG) {
        PRINTF("Error: unexpected end step %d\n", step);
        return false;
    }
    if (offset != payload->size) {
        PRINTF("Error: unexpected data at the end of the TLV payload!\n");
        return false;
    }

    return true;
}
