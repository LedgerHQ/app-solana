#pragma once

// Clear-signing VALUE sub-TLV source types — spec/device/tlv_structs.md §VALUE.
// Determines where a display field's value comes from at resolution time.

// Even if this is a TLV related value, it is forwarded to the walker in libsol therefor is defined
// in libsol

enum cs_value_source {
    CS_VALUE_SOURCE_ARGUMENT_PATH = 0x00,
    CS_VALUE_SOURCE_ACCOUNT_PATH  = 0x01,
    CS_VALUE_SOURCE_CONSTANT      = 0x02,
};
