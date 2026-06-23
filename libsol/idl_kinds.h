#pragma once

// IDL type-pool kind codes, as carried verbatim in the leading byte of every
// IDL_TYPE_POOL entry (and inline *_kind markers) shipped inside an
// INSTRUCTION_INFO TLV. Mirrors spec/device/idl_descriptor.md "Type-pool
// kinds". These values are also surfaced on `idl_leaf_t.kind` so the consumer
// knows how to interpret a leaf's raw value bytes.
//
// Convention reminders (enforced by the walker, not this header):
//   - multi-byte descriptor metadata (sizes, counts) is big-endian;
//   - numeric leaves in the instruction data are little-endian.

#include <stdint.h>

// --- Numeric primitives ------------------------------------------------------
#define IDL_KIND_U8         0x01
#define IDL_KIND_U16        0x02
#define IDL_KIND_U32        0x03
#define IDL_KIND_U64        0x04
#define IDL_KIND_U128       0x05
#define IDL_KIND_I8         0x06
#define IDL_KIND_I16        0x07
#define IDL_KIND_I32        0x08
#define IDL_KIND_I64        0x09
#define IDL_KIND_I128       0x0A
#define IDL_KIND_F32        0x0B
#define IDL_KIND_F64        0x0C
#define IDL_KIND_SHORT_U16  0x0D
#define IDL_KIND_BOOL_U8    0x0E
#define IDL_KIND_BOOL_U16   0x0F
#define IDL_KIND_BOOL_U32   0x10

// --- Fixed / variable byte leaves --------------------------------------------
#define IDL_KIND_PUBKEY_32       0x11
#define IDL_KIND_BYTES_FIXED     0x12
#define IDL_KIND_STRING_FIXED    0x13
#define IDL_KIND_STRING_PREFIXED 0x14
#define IDL_KIND_BYTES_REMAINDER 0x15

// --- Aggregates / composites -------------------------------------------------
#define IDL_KIND_STRUCT          0x20
#define IDL_KIND_TUPLE           0x21
#define IDL_KIND_OPTION_DYNAMIC  0x22
#define IDL_KIND_OPTION_FIXED    0x23
#define IDL_KIND_OPTION_ZEROABLE 0x24
#define IDL_KIND_ARRAY_FIXED     0x25
#define IDL_KIND_ARRAY_PREFIXED  0x26
#define IDL_KIND_ARRAY_REMAINDER 0x27
#define IDL_KIND_ENUM            0x28
#define IDL_KIND_HIDDEN_PREFIX   0x29
#define IDL_KIND_HIDDEN_SUFFIX   0x2A
#define IDL_KIND_OPTION_REMAINDER 0x2B

// --- String encodings (STRING_FIXED / STRING_PREFIXED `encoding` arg) --------
#define IDL_ENCODING_UTF8   0x00
#define IDL_ENCODING_BASE16 0x01
