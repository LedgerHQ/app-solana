#pragma once

#include "tlv_library.h"
#include "buffer.h"

#define MAX_TICKER_SIZE 32

typedef struct tlv_dynamic_descriptor_out_s {
    uint8_t version;
    uint32_t coin_type;
    uint8_t magnitude;
    buffer_t TUID;
    // 0 copy is inconvenient for strings because they are not '\0' terminated in the TLV reception
    // format
    char ticker[MAX_TICKER_SIZE + 1];
} tlv_dynamic_descriptor_out_t;

int tlv_use_case_parse_dynamic_descriptor_payload(const buffer_t *payload,
                                                  tlv_dynamic_descriptor_out_t *tlv_output);
