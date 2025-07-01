#include <cx.h>
#include <os.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "tlv_library.h"

#define DER_LONG_FORM_FLAG        0x80  // 8th bit set
#define DER_FIRST_BYTE_VALUE_MASK 0x7f

#define U8BE(buf, off) (((uint64_t) U4BE(buf, off) << 32) | (uint64_t) U4BE(buf, off + 4))

bool get_uint64_t_from_tlv_data(const tlv_data_t *data, uint64_t *value) {
    if (data->value.size == 0 || data->value.size > sizeof(uint64_t)) {
        PRINTF("Invalid length (%u bytes) for tag 0x%x (expected 1-%zu bytes)\n",
               data->value.size,
               data->tag,
               sizeof(uint64_t));
        return false;
    }

    // Pad with zeros before calling U8BE()
    uint8_t buffer[sizeof(uint64_t)] = {0};
    memcpy(buffer + (sizeof(buffer) - data->value.size), data->value.ptr, data->value.size);

    *value = U8BE(buffer, 0);
    return true;
}

bool get_uint32_t_from_tlv_data(const tlv_data_t *data, uint32_t *value) {
    uint64_t tmp_value;
    if (!get_uint64_t_from_tlv_data(data, &tmp_value) || tmp_value > UINT32_MAX) {
        return false;
    }
    *value = (uint32_t) tmp_value;
    return true;
}

bool get_uint16_t_from_tlv_data(const tlv_data_t *data, uint16_t *value) {
    uint64_t tmp_value;
    if (!get_uint64_t_from_tlv_data(data, &tmp_value) || (tmp_value > UINT16_MAX)) {
        return false;
    }
    *value = (uint16_t) tmp_value;
    return true;
}

bool get_uint8_t_from_tlv_data(const tlv_data_t *data, uint8_t *value) {
    uint64_t tmp_value;
    if (!get_uint64_t_from_tlv_data(data, &tmp_value) || (tmp_value > UINT8_MAX)) {
        return false;
    }
    *value = (uint8_t) tmp_value;
    return true;
}

bool get_buffer_from_tlv_data(const tlv_data_t *data,
                              buffer_t *out,
                              uint16_t min_size,
                              uint16_t max_size) {
    if (min_size != 0 && data->value.size < min_size) {
        PRINTF("Expected at least %d bytes, found %d\n", min_size, data->value.size);
        return false;
    }
    if (max_size != 0 && data->value.size > max_size) {
        PRINTF("Expected at most %d bytes, found %d\n", max_size, data->value.size);
        return false;
    }
    out->size = data->value.size;
    out->ptr = data->value.ptr;
    return true;
}

bool get_string_from_tlv_data(const tlv_data_t *data,
                              char *out,
                              uint16_t min_length,
                              uint16_t out_size) {
    // Reject TLV strings with embedded null bytes
    size_t actual_length = strnlen((const char *) data->value.ptr, data->value.size);
    if (actual_length != data->value.size) {
        PRINTF("Embedded null byte at offset %u\n", (unsigned) actual_length);
        return false;
    }

    if (min_length != 0 && data->value.size < min_length) {
        PRINTF("Expected at least %u bytes, found %u\n", min_length, data->value.size);
        return false;
    }
    // The input is not '\0' terminated
    if (out_size != 0 && data->value.size + 1 > out_size) {
        PRINTF("Expected at most %u bytes, found %u (+1)\n", out_size, data->value.size);
        return false;
    }

    memcpy(out, data->value.ptr, data->value.size);
    out[data->value.size] = '\0';

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
                         tlv_handler_cb_t *common_handler,
                         tag_to_flag_function_t *tag_to_flag_function,
                         const buffer_t *payload,
                         void *tlv_out,
                         TLV_reception_t *received_tags_flags) {
    tlv_step_t step = TLV_TAG;
    tlv_data_t data;
    size_t offset = 0;
    size_t tag_start_offset;
    const _internal_tlv_handler_t *handler;
    tlv_handler_cb_t *fptr;
    uint16_t size;

    explicit_bzero(received_tags_flags, sizeof(*received_tags_flags));
    received_tags_flags->tag_to_flag_function = PIC(tag_to_flag_function);

    PRINTF("Parsing TLV payload %.*H\n", payload->size, payload->ptr);

    // handle TLV payload
    while (offset < payload->size || (step == TLV_VALUE && data.value.size == 0)) {
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
                step = TLV_LENGTH;
                break;

            case TLV_LENGTH:
                if (!get_der_value_as_uint16(payload, &offset, &size)) {
                    return false;
                }
                data.value.size = size;
                step = TLV_VALUE;
                break;

            case TLV_VALUE:
                if ((offset + data.value.size) > payload->size) {
                    PRINTF("Error: can't read %d + %d, only %d\n",
                           offset,
                           data.value.size,
                           payload->size);
                    return false;
                }
                if (data.value.size > 0) {
                    data.value.ptr = &payload->ptr[offset];
                    PRINTF("Handling tag 0x%02x length %d value '%.*H'\n",
                           data.tag,
                           data.value.size,
                           data.value.size,
                           data.value.ptr);
                } else {
                    data.value.ptr = NULL;
                    PRINTF("Handling tag 0x%02x length %d\n", data.tag, data.value.size);
                }
                offset += data.value.size;

                // Calculate raw TLV start/end to give to the handler
                data.raw.ptr = &payload->ptr[tag_start_offset];
                data.raw.size = offset - tag_start_offset;

                // Call the common handler if there is one
                fptr = PIC(common_handler);
                if (fptr != NULL && !(*fptr)(&data, tlv_out)) {
                    PRINTF("Common handler error while handling tag 0x%x\n", handler->tag);
                    return false;
                }

                // Call this tag's handler if there is one
                fptr = PIC(handler->func);
                if (fptr != NULL && !(*fptr)(&data, tlv_out)) {
                    PRINTF("Handler error while handling tag 0x%x\n", handler->tag);
                    return false;
                }

                // Flag reception after handler callback in case the handler wants to check it
                if (!set_tag(received_tags_flags, data.tag)) {
                    if (handler->is_unique) {
                        PRINTF("Tag = %d was already received and is flagged unique\n", data.tag);
                        return false;
                    }
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
