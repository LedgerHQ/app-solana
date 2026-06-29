#pragma once

// VALUE sub-TLV parser for clear signing descriptors.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sol/cs_value_source.h"

#define CS_VALUE_MAX_PAYLOAD_LENGTH 64

typedef struct cs_value_s {
    uint8_t source;
    uint8_t payload[CS_VALUE_MAX_PAYLOAD_LENGTH];
    size_t payload_size;
} cs_value_t;

// Parse a VALUE sub-TLV from a raw buffer. Returns true on success.
bool cs_parse_value_from_buffer(const uint8_t *buf, size_t buf_size, cs_value_t *out);
