#pragma once

// VALUE sub-TLV parser for clear signing descriptors.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "buffer.h"
#include "sol/cs_value_source.h"

// payload is a zero-copy view into the source TLV buffer; it stays valid only as
// long as the buffer passed to cs_parse_value_from_buffer is alive.
typedef struct cs_value_s {
    uint8_t source;
    buffer_t payload;
} cs_value_t;

// Parse a VALUE sub-TLV from a raw buffer. Returns true on success.
bool cs_parse_value_from_buffer(const uint8_t *buf, size_t buf_size, cs_value_t *out);
