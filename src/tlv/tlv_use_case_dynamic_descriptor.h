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

typedef enum tlv_dynamic_descriptor_status_e {
    TLV_DYNAMIC_DESCRIPTOR_SUCCESS = 0,
    TLV_DYNAMIC_DESCRIPTOR_PARSING_ERROR = 1,
    TLV_DYNAMIC_DESCRIPTOR_MISSING_STRUCTURE_TAG = 2,
    TLV_DYNAMIC_DESCRIPTOR_WRONG_TYPE = 3,
    TLV_DYNAMIC_DESCRIPTOR_MISSING_TAG = 4,
    TLV_DYNAMIC_DESCRIPTOR_WRONG_APPLICATION_NAME = 5,
    TLV_DYNAMIC_DESCRIPTOR_UNKNOWN_VERSION = 6,
    // Combined with check_signature_with_pki_status_t
    TLV_DYNAMIC_DESCRIPTOR_SIGNATURE_ERROR = 0x80,
} tlv_dynamic_descriptor_status_t;

tlv_dynamic_descriptor_status_t tlv_use_case_dynamic_descriptor(const buffer_t *payload,
                                                                tlv_dynamic_descriptor_out_t *out);
