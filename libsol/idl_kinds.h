#pragma once

// IDL type-pool kind codes, as carried verbatim in the leading byte of every
// IDL_TYPE_POOL entry (and inline *_kind markers) shipped inside an
// INSTRUCTION_INFO TLV. Mirrors spec/device/idl_descriptor.md "Type-pool
// kinds". These values are also surfaced on `idl_resolved_leaf_t.kind` so the
// consumer knows how to interpret a leaf's raw value bytes.
//
// Convention reminders (enforced by the walker, not this header):
//   - multi-byte descriptor metadata (sizes, counts) is big-endian;
//   - numeric leaves in the instruction data are little-endian.

#include <stdint.h>

// --- Numeric primitives ------------------------------------------------------
enum idl_kind {
    IDL_KIND_U8 = 0x01,
    IDL_KIND_U16 = 0x02,
    IDL_KIND_U32 = 0x03,
    IDL_KIND_U64 = 0x04,
    IDL_KIND_U128 = 0x05,
    IDL_KIND_I8 = 0x06,
    IDL_KIND_I16 = 0x07,
    IDL_KIND_I32 = 0x08,
    IDL_KIND_I64 = 0x09,
    IDL_KIND_I128 = 0x0A,
    IDL_KIND_F32 = 0x0B,
    IDL_KIND_F64 = 0x0C,
    IDL_KIND_SHORT_U16 = 0x0D,
    IDL_KIND_BOOL_U8 = 0x0E,
    IDL_KIND_BOOL_U16 = 0x0F,
    IDL_KIND_BOOL_U32 = 0x10,

    // --- Fixed / variable byte leaves ----------------------------------------
    IDL_KIND_PUBKEY_32 = 0x11,
    IDL_KIND_BYTES_FIXED = 0x12,
    IDL_KIND_STRING_FIXED = 0x13,
    IDL_KIND_STRING_PREFIXED = 0x14,
    IDL_KIND_BYTES_REMAINDER = 0x15,

    // --- Aggregates / composites ---------------------------------------------
    IDL_KIND_STRUCT = 0x20,
    IDL_KIND_TUPLE = 0x21,
    IDL_KIND_OPTION_DYNAMIC = 0x22,
    IDL_KIND_OPTION_FIXED = 0x23,
    IDL_KIND_OPTION_ZEROABLE = 0x24,
    IDL_KIND_ARRAY_FIXED = 0x25,
    IDL_KIND_ARRAY_PREFIXED = 0x26,
    IDL_KIND_ARRAY_REMAINDER = 0x27,
    IDL_KIND_ENUM = 0x28,
    IDL_KIND_HIDDEN_PREFIX = 0x29,
    IDL_KIND_HIDDEN_SUFFIX = 0x2A,
    IDL_KIND_OPTION_REMAINDER = 0x2B,
};

// --- String encodings (STRING_FIXED / STRING_PREFIXED `encoding` arg) --------
enum idl_encoding {
    IDL_ENCODING_UTF8 = 0x00,
    IDL_ENCODING_BASE16 = 0x01,
};

// --- Amount kinds ------------------------------------------------------------
//
// An amount is read as an unsigned little-endian integer of at most 64 bits. These two
// lookups are the single place that decides which kinds qualify and how wide each one
// is, so a decoder, a descriptor validator and a width inference cannot disagree.

#include <stddef.h>

// Byte width of an unsigned-integer IDL kind. Returns 0, -1 when the kind is not one.
int idl_unsigned_kind_width(uint8_t kind, size_t *out_width);

// The unsigned-integer IDL kind occupying a given byte width, for a number carried
// without a kind of its own. Returns 0, -1 when no kind has that width.
int idl_unsigned_kind_for_width(size_t width, uint8_t *out_kind);
