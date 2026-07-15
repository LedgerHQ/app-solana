#pragma once

// Instruction template table for clear signing.
//
// Owns the signed INSTRUCTION_INFO templates streamed by PROVIDE INSTRUCTION
// INFO (0x06) / SUBSTRUCTURE (0x10) and consumed at PROMPT UI DISPLAY (0x0B).
//
// A template is assembled in two phases. PROVIDE INSTRUCTION INFO opens a single
// in-flight builder and fills its committed fields (program_id, discriminator,
// IDL pool). PROVIDE INSTRUCTION SUBSTRUCTURE then streams the substructures,
// folding them into the substructure hash accumulator and appending display
// paths to the builder. Only once the accumulated hash matches the descriptor's
// committed target is the builder copied into the committed array. Templates in
// that array are therefore always whole and walker-ready; an in-flight builder
// that never completes is never visible to PROMPT UI DISPLAY.
//
// The table lives on the heap (allocated on first open, released on reset) and
// is session-scoped, mirroring cs_transaction_t.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sol/cs_value_source.h"

// Param types (spec/device/tlv_structs.md FieldParamType enum).
// Determines how the renderer formats the resolved value.
enum cs_param_type {
    CS_PARAM_TYPE_RAW = 0x00,
    CS_PARAM_TYPE_AMOUNT = 0x01,
    CS_PARAM_TYPE_TOKEN_AMOUNT = 0x02,
    CS_PARAM_TYPE_DATETIME = 0x03,
    CS_PARAM_TYPE_DURATION = 0x04,
    CS_PARAM_TYPE_UNIT = 0x05,
    CS_PARAM_TYPE_ENUM = 0x06,
    CS_PARAM_TYPE_TRUSTED_NAME = 0x07,
    CS_PARAM_TYPE_ACCOUNT = 0x08,
    CS_PARAM_TYPE_STRING = 0x09,
};

// Format-specific parameters for PARAM_AMOUNT.
typedef struct cs_format_amount_s {
    uint8_t decimals;
} cs_format_amount_t;

// Format-specific parameters for PARAM_DATETIME. The resolved integer leaf is
// divided by `ticks_per_second` to obtain Unix epoch seconds before formatting.
typedef struct cs_format_datetime_s {
    uint32_t ticks_per_second;
} cs_format_datetime_t;

// Format-specific parameters for PARAM_UNIT. The resolved integer leaf is scaled
// by `decimals` and rendered with `symbol` placed before (`prefix`) or after it.
#define CS_MAX_UNIT_SYMBOL 12
typedef struct cs_format_unit_s {
    char symbol[CS_MAX_UNIT_SYMBOL];
    uint8_t decimals;
    bool prefix;
} cs_format_unit_t;

// Text encoding applied to a PARAM_STRING leaf before display.
enum cs_string_encoding {
    CS_STRING_ENCODING_ASCII = 0x00,
    CS_STRING_ENCODING_UTF8 = 0x01,
    CS_STRING_ENCODING_BASE58 = 0x02,
    CS_STRING_ENCODING_BASE64 = 0x03,
    CS_STRING_ENCODING_HEX = 0x04,
};

// How a PARAM_STRING slice window is expressed.
enum cs_slice_kind {
    CS_SLICE_KIND_BOUNDED = 0x00,  // [start, end)
    CS_SLICE_KIND_SIZED = 0x01,    // `size` units from start, or from the tail when reversed
};

// Whether a PARAM_STRING slice operates on the raw source bytes or on the
// post-encoding formatted string.
enum cs_slice_applies_to {
    CS_SLICE_APPLIES_TO_FORMATTED = 0x00,
    CS_SLICE_APPLIES_TO_SOURCE = 0x01,
};

// Format-specific parameters for PARAM_STRING. `slice_kind` selects the active
// `slice` arm; `slice_start` is shared by BOUNDED and forward SIZED.
typedef struct cs_format_string_s {
    uint8_t encoding;  // enum cs_string_encoding
    bool has_slice;
    uint8_t slice_kind;        // enum cs_slice_kind
    uint8_t slice_applies_to;  // enum cs_slice_applies_to
    uint16_t slice_start;
    union {
        struct {
            uint16_t end;  // exclusive
        } bounded;         // CS_SLICE_KIND_BOUNDED
        struct {
            uint16_t size;
            bool reversed;  // take the trailing window
        } sized;            // CS_SLICE_KIND_SIZED
    } slice;
} cs_format_string_t;

// Where a TOKEN_AMOUNT's ticker/decimals metadata comes from. Exactly one
// applies, so contradictory combinations (native carrying a mint reference, a
// stale payload behind an absent reference) are unrepresentable. ARGUMENT_PATH
// is intentionally absent: a token reference read from instruction data is
// refused at ingest and never stored.
enum cs_token_mint_source {
    CS_TOKEN_MINT_NATIVE = 0,     // built-in "SOL" / SOL_DECIMALS, no lookup
    CS_TOKEN_MINT_NONE,           // no reference: rendered without a ticker
    CS_TOKEN_MINT_ACCOUNT_INDEX,  // mint is the pubkey at an accounts-array index
    CS_TOKEN_MINT_CONSTANT,       // mint embedded as a 32-byte pubkey
};

// Format-specific parameters for PARAM_TOKEN_AMOUNT.
//
// `mint_source` selects which `ref` arm (if any) identifies the mint whose
// ticker/decimals describe this amount; the mint is resolved at finalize time.
// The DECIMALS override is orthogonal: when `has_decimals` is set it replaces
// the resolved magnitude while the ticker still comes from TOKEN_INFO.
typedef struct cs_format_token_amount_s {
    uint8_t mint_source;  // enum cs_token_mint_source
    union {
        uint8_t account_index;  // CS_TOKEN_MINT_ACCOUNT_INDEX
        uint8_t mint[32];       // CS_TOKEN_MINT_CONSTANT
    } ref;
    bool has_decimals;
    uint8_t decimals;
} cs_format_token_amount_t;

// PARAM_TRUSTED_NAME: the TYPES allow-list as a bitmask (bit i = TrustedNameType
// i permitted; all values are <= 6). Zero means no constraint. No source mask:
// only CRYPTO_ASSET_LIST names are ever cached.
typedef struct cs_format_trusted_name_s {
    uint8_t allowed_types_mask;
} cs_format_trusted_name_t;

// Fixed capacities. Inputs exceeding these fail closed rather than truncate.
#define CS_MAX_INSTRUCTION_TEMPLATES 4
#define CS_MAX_IDL_TYPE_POOL_SIZE    512
#define CS_MAX_DISCRIMINATOR_SIZE    8
#define CS_MAX_DISPLAY_FIELDS        8
#define CS_MAX_ARGUMENT_PATH_SIZE    16
#define CS_MAX_CONSTANT_SIZE         32
#define CS_MAX_OPERATION_TYPE_SIZE   32
#define CS_MAX_PROGRAM_NAME_SIZE     32
#define CS_MAX_DISPLAY_FIELD_NAME    32

// One displayed field. Three source types are supported:
//   - ARGUMENT_PATH (source == 0x00): the field value is extracted from the
//     instruction data via the IDL walker using `argument.path`/`argument.path_size`.
//     Only ARGUMENT_PATH fields carry a `param_type` (how to format the value)
//     and optional format parameters (decimals, token mint source, etc.).
//   - ACCOUNT_PATH  (source == 0x01): the field value is the pubkey at
//     `account.index` in the instruction's accounts array. Always rendered as
//     a short-form base58 address.
//   - CONSTANT      (source == 0x02): the field value is embedded directly in
//     the descriptor. `constant.data`/`constant.data_size` hold the raw bytes
//     and `constant.kind` the IDL kind for formatting via format_leaf.
// All share the same array so streaming order equals display order.
typedef struct cs_display_field_s {
    uint8_t source;
    char name[CS_MAX_DISPLAY_FIELD_NAME];
    union {
        struct {
            uint8_t path[CS_MAX_ARGUMENT_PATH_SIZE];
            uint8_t path_size;
            uint8_t param_type;
            union {
                cs_format_amount_t amount;
                cs_format_token_amount_t token_amount;
                cs_format_datetime_t datetime;
                cs_format_unit_t unit;
                cs_format_string_t string;
                cs_format_trusted_name_t trusted_name;
            } format;
        } argument;
        struct {
            uint8_t index;
        } account;
        struct {
            uint8_t data[CS_MAX_CONSTANT_SIZE];
            uint8_t data_size;
            uint8_t kind;
        } constant;
    };
} cs_display_field_t;

// One complete instruction template, keyed by (program_id, discriminator).
// Only ever exposed once fully assembled, so every field is valid.
typedef struct cs_instruction_template_s {
    uint8_t program_id[32];
    uint8_t discriminator[CS_MAX_DISCRIMINATOR_SIZE];
    uint8_t discriminator_size;
    char operation_type[CS_MAX_OPERATION_TYPE_SIZE];
    char program_name[CS_MAX_PROGRAM_NAME_SIZE];
    uint8_t idl_type_pool[CS_MAX_IDL_TYPE_POOL_SIZE];
    size_t idl_type_pool_size;
    uint8_t idl_root_type;
    cs_display_field_t display_fields[CS_MAX_DISPLAY_FIELDS];
    uint8_t display_field_count;
    uint8_t mint_assoc_account;
    uint8_t mint_assoc_mint;
    bool has_mint_assoc;
} cs_instruction_template_t;

// Open a fresh in-flight builder committed to `target_hash` (the SHA-256 the
// signed INSTRUCTION_INFO descriptor expects over its substructures) and start
// the matching substructure hash accumulation. Returns the zeroed builder for
// the caller to fill, or NULL when the committed array is already full or the
// table cannot be allocated. Discards any previous unfinished builder.
cs_instruction_template_t *cs_instruction_template_open(const uint8_t target_hash[32]);

// The in-flight builder being assembled, or NULL when none is open.
cs_instruction_template_t *cs_instruction_template_current(void);

// Append one argument path to the in-flight builder's display-field list.
// `name` is the human-readable field label (may be NULL or empty).
// Returns 0 on success, -1 when no builder is open, the path is too long, or
// the slot is full.
int cs_instruction_template_add_display_path(const uint8_t *path,
                                             size_t path_size,
                                             uint8_t param_type,
                                             const char *name);

// Append one account-path field to the in-flight builder's display-field list.
// `account_index` is the index into the instruction's accounts array.
// `name` is the human-readable field label (may be NULL or empty).
// Always rendered as a short-form base58 address; no param_type needed.
// Returns 0 on success, -1 when no builder is open or the slot is full.
int cs_instruction_template_add_account_field(uint8_t account_index, const char *name);

// Append a CONSTANT display field. The value is embedded directly from the
// descriptor payload. `kind` is the IDL kind code for formatting at render time.
// Always rendered via format_leaf using the IDL kind; no param_type needed.
// Returns 0 on success, -1 when no builder is open or the slot is full.
int cs_instruction_template_add_constant_field(const uint8_t *data,
                                               size_t data_size,
                                               uint8_t kind,
                                               const char *name);

// Set AMOUNT format parameters on the last added display field.
// Must be called immediately after adding a field with param_type == AMOUNT.
int cs_instruction_template_set_format_amount(uint8_t decimals);

// Set TOKEN_AMOUNT format parameters on the last added display field. The
// caller builds a fully-validated `format` (mint source, optional embedded mint
// or account index, optional decimals override) and hands it over atomically.
// Must be called immediately after adding a field with param_type == TOKEN_AMOUNT.
// Returns 0 on success, -1 when no matching field is open.
int cs_instruction_template_set_format_token_amount(const cs_format_token_amount_t *format);

// Set DATETIME format parameters on the last added display field.
// Must be called immediately after adding a field with param_type == DATETIME.
// Returns 0 on success, -1 when no matching field is open.
int cs_instruction_template_set_format_datetime(uint32_t ticks_per_second);

// Set UNIT format parameters on the last added display field.
// Must be called immediately after adding a field with param_type == UNIT.
// Returns 0 on success, -1 when no matching field is open.
int cs_instruction_template_set_format_unit(const cs_format_unit_t *format);

// Set STRING format parameters on the last added display field.
// Must be called immediately after adding a field with param_type == STRING.
// Returns 0 on success, -1 when no matching field is open.
int cs_instruction_template_set_format_string(const cs_format_string_t *format);

// Set TRUSTED_NAME format parameters (type/source allow-list masks) on the last
// added display field. Must be called immediately after adding a field with
// param_type == TRUSTED_NAME. Returns 0 on success, -1 when no matching field.
int cs_instruction_template_set_format_trusted_name(const cs_format_trusted_name_t *format);

// Set mint association indices on the in-flight builder. Both indices refer to
// the instruction's accounts array: `account_idx` is the token account,
// `mint_idx` is the mint account whose pubkey identifies the token.
// Returns 0 on success, -1 when no builder is open.
int cs_instruction_template_set_mint_assoc(uint8_t account_idx, uint8_t mint_idx);

// Promote the in-flight builder into the committed array. Must be called only
// once the substructure accumulation has matched the committed target. Returns 0
// on success, -1 when no builder is open or the array is full.
int cs_instruction_template_commit(void);

// Number of committed (whole, walker-ready) templates.
uint8_t cs_instruction_template_committed_count(void);

// True while a builder is open but not yet committed.
bool cs_instruction_template_pending(void);

// Find the committed template whose program_id matches and whose discriminator
// is a prefix of `data`. Returns NULL when none matches.
const cs_instruction_template_t *cs_instruction_template_find(const uint8_t program_id[32],
                                                              const uint8_t *data,
                                                              size_t data_size);

// Release the table and the substructure accumulator, returning to the empty
// state. Safe when no table is allocated.
void cs_instruction_template_table_reset(void);
