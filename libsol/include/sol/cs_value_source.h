#pragma once

// Clear-signing VALUE sub-TLV source types — spec/device/tlv_structs.md §VALUE.
// Determines where a display field's value comes from at resolution time.

#define CS_VALUE_SOURCE_ARGUMENT_PATH 0x00
#define CS_VALUE_SOURCE_ACCOUNT_PATH  0x01
#define CS_VALUE_SOURCE_CONSTANT      0x02
