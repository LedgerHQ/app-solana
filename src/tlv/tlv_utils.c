#include "tlv_utils.h"

#define DER_LONG_FORM_FLAG        0x80  // 8th bit set
#define DER_FIRST_BYTE_VALUE_MASK 0x7f

bool get_uint32_from_tlv_data(const tlv_data_t *data, uint32_t *value) {
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
    if (!get_uint32_from_tlv_data(data, &tmp_value) || (tmp_value > UINT16_MAX)) {
        return false;
    }
    *value = (uint16_t) tmp_value;
    return true;
}

bool get_uint8_t_from_tlv_data(const tlv_data_t *data, uint8_t *value) {
    uint32_t tmp_value;
    if (!get_uint32_from_tlv_data(data, &tmp_value) || (tmp_value > UINT8_MAX)) {
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
        PRINTF("Expected at least %d bytes, found %D\n", min_size, data->length);
        return false;
    }
    if (max_size != 0 && data->length > max_size) {
        PRINTF("Expected at most %d bytes, found %D\n", max_size, data->length);
        return false;
    }
    out->size = data->length;
    out->ptr = data->value;
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

static bool get_der_value_as_uint16(const buffer_t *payload, size_t *offset, uint16_t *value) {
    uint32_t tmp_value;
    if (!get_der_value_as_uint32(payload, offset, &tmp_value) || (tmp_value > UINT16_MAX)) {
        return false;
    }

    *value = (uint16_t) tmp_value;
    return true;
}

static bool get_der_value_as_uint8(const buffer_t *payload, size_t *offset, uint8_t *value) {
    uint32_t tmp_value;
    if (!get_der_value_as_uint32(payload, offset, &tmp_value) || (tmp_value > UINT8_MAX)) {
        return false;
    }

    *value = (uint8_t) tmp_value;
    return true;
}

// clang-format off
// Use _Generic keyword to perform a compile-time switch / case depending on value actual type
#define GET_DER_VALUE_AS_UINTX(payload, offset, value) \
    _Generic((value),                                  \
        uint8_t  *: get_der_value_as_uint8,            \
        uint16_t *: get_der_value_as_uint16,           \
        uint32_t *: get_der_value_as_uint32            \
    )(payload, offset, value)
// clang-format on

// Some Xmacro dark magic to assign to each tag_FLAG its flag value
// Used by the function below that maps TAGS to FLAGS
typedef enum tlv_rcv_bit_e {
#define X(name, value) name##_FLAG = (1 << __COUNTER__),
    TLV_TAGS
#undef X
} tlv_rcv_bit_t;

// Some Xmacro dark magic to get the flag value from the tag
// 0(n) complexity but we don't care
uint32_t get_tag_flag(tlv_tag_t tag) {
    switch (tag) {
#define X(name, value) \
    case name:         \
        return name##_FLAG;
        TLV_TAGS
#undef X
        default:
            return (uint32_t) -1;
    }
}

/**
 * Calls the proper handler for the given TLV data
 *
 * Checks if there is a proper handler function for the given TLV tag and then calls it
 *
 * @param[in] handlers list of tag / handler function pairs
 * @param[in] data the TLV data
 * @param[in/out] received_tags_flags the tags flagged as received
 * @param[out] tlv_out the parsed tlv
 * @return whether it was successful
 */
static bool handle_tlv_data(const tlv_handler_t *handlers,
                            uint8_t handlers_count,
                            const tlv_data_t *data,
                            uint32_t *received_tags_flags,
                            tlv_out_t *tlv_out) {
    // check if a handler exists for this tag
    for (uint8_t idx = 0; idx < handlers_count; ++idx) {
        if (handlers[idx].tag == data->tag) {
            // Refuse if this tag was already received
            if (*received_tags_flags & get_tag_flag(handlers[idx].tag)) {
                PRINTF("Tag 0x%x already received, rejecting duplicate\n", handlers[idx].tag);
                return false;
            }

            // Mark this tag as received
            *received_tags_flags |= get_tag_flag(handlers[idx].tag);

            // Call the handler function
            tlv_handler_cb_t *fptr = PIC(handlers[idx].func);
            if (fptr != NULL && !(*fptr)(data, tlv_out)) {
                PRINTF("Error while handling tag 0x%x\n", handlers[idx].tag);
                return false;
            }

            // Success
            return true;
        }
    }

    PRINTF("No handler found for tag 0x%x\n", data->tag);
    return false;
}

typedef enum tlv_step_e {
    TLV_TAG,
    TLV_LENGTH,
    TLV_VALUE,
} tlv_step_t;

bool parse_tlv(const tlv_handler_t *handlers,
               uint8_t handlers_count,
               const buffer_t *payload,
               tlv_out_t *tlv_out,
               tlv_tag_t signature_tag,
               uint8_t hash[INT256_LENGTH],
               uint32_t *received_tags_flags) {
    tlv_step_t step = TLV_TAG;
    tlv_data_t data;
    size_t offset = 0;
    size_t tag_start_offset;
    cx_sha256_t hash_ctx;

    cx_sha256_init(&hash_ctx);

    // handle TLV payload
    while (offset < payload->size) {
        switch (step) {
            case TLV_TAG:
                tag_start_offset = offset;
                if (!GET_DER_VALUE_AS_UINTX(payload, &offset, &data.tag)) {
                    return false;
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
                data.value = &payload->ptr[offset];
                PRINTF("Handling tag 0x%02x length %d value '%.*H'\n",
                       data.tag,
                       data.length,
                       data.length,
                       data.value);
                if (!handle_tlv_data(handlers,
                                     handlers_count,
                                     &data,
                                     received_tags_flags,
                                     tlv_out)) {
                    PRINTF("Handler reported an error\n");
                    return false;
                }
                offset += data.length;
                // Feed this TLV into the hash (except the signature itself)
                if (data.tag != signature_tag) {
                    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &hash_ctx,
                                               0,
                                               &payload->ptr[tag_start_offset],
                                               (offset - tag_start_offset),
                                               NULL,
                                               0));
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

    // If the user requested the hash of the TLV, forward it to him
    if (hash != NULL) {
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &hash_ctx, CX_LAST, NULL, 0, hash, INT256_LENGTH));
    }

    return true;
}

bool received_required_tags(uint32_t rcv_flags, const tlv_tag_t *tags, size_t tag_count) {
    uint32_t required_flags = 0;
    for (size_t i = 0; i < tag_count; i++) {
        required_flags |= get_tag_flag(tags[i]);
    }
    return ((rcv_flags & required_flags) == required_flags);
}
