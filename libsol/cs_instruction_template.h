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

// Format-specific parameters for PARAM_AMOUNT. `max_label` is rendered in place
// of the number when the raw integer equals its IDL type's maximum value.
typedef struct cs_format_amount_s {
    uint8_t decimals;
    char *max_label;  // heap, NUL-terminated; owned by this template, NULL when absent
} cs_format_amount_t;

// Format-specific parameters for PARAM_DATETIME. The resolved integer leaf is
// divided by `ticks_per_second` to obtain Unix epoch seconds before formatting.
typedef struct cs_format_datetime_s {
    uint32_t ticks_per_second;
} cs_format_datetime_t;

// Format-specific parameters for PARAM_UNIT. The resolved integer leaf is scaled
// by `decimals` and rendered with `symbol` placed before (`prefix`) or after it.
typedef struct cs_format_unit_s {
    char *symbol;  // heap, NUL-terminated; owned by this template, NULL when absent
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
    char *max_label;  // heap, NUL-terminated; owned by this template, NULL when absent
} cs_format_token_amount_t;

// PARAM_TRUSTED_NAME: the TYPES allow-list as a bitmask (bit i = TrustedNameType
// i permitted; all values are <= 6). Zero means no constraint. No source mask:
// only CRYPTO_ASSET_LIST names are ever cached.
typedef struct cs_format_trusted_name_s {
    uint8_t allowed_types_mask;
} cs_format_trusted_name_t;

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
    char *name;  // heap, NUL-terminated; owned by this template, NULL when unlabeled
    union {
        struct {
            uint8_t *path;  // heap, sized to path_size; owned by this template
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
            uint8_t *data;  // heap, sized to data_size; owned by this template
            uint8_t data_size;
            uint8_t kind;
        } constant;
    };
} cs_display_field_t;

// =============================================================================
// Merge-engine substructures (VALUE_FLOW_PORT / HIDE_RULE / ACCOUNT_RESET) and
// the OWNER_ASSOC pair. These carry the descriptor form: account indices,
// embedded VALUE descriptors and raw predicate/scope bytes. The finalize walk
// resolves them into concrete pubkeys/amounts/mints for the merge engine.
// =============================================================================

enum cs_port_direction {
    CS_PORT_DIRECTION_INPUT = 0x00,
    CS_PORT_DIRECTION_OUTPUT = 0x01,
};

enum cs_port_value_kind {
    CS_PORT_VALUE_KIND_NATIVE = 0x00,
    CS_PORT_VALUE_KIND_SPL_TOKEN = 0x01,
};

enum cs_amount_kind {
    CS_AMOUNT_KIND_NUMERIC = 0x00,
    CS_AMOUNT_KIND_BALANCE = 0x01,
};

enum cs_token_kind {
    CS_TOKEN_KIND_DIRECT = 0x00,
    CS_TOKEN_KIND_RESOLVE = 0x01,
    CS_TOKEN_KIND_NULL = 0x02,
    CS_TOKEN_KIND_NATIVE = 0x03,
};

enum cs_optional_account_strategy {
    CS_OPTIONAL_ACCOUNT_STRATEGY_PROGRAM_ID = 0x00,
    CS_OPTIONAL_ACCOUNT_STRATEGY_OMITTED = 0x01,
};

enum cs_active_when_predicate {
    CS_ACTIVE_WHEN_CREATED_IN_TRANSACTION = 0x00,
    CS_ACTIVE_WHEN_IS_SIGNER = 0x01,
    CS_ACTIVE_WHEN_ACCOUNT_USED_ELSEWHERE = 0x02,
    CS_ACTIVE_WHEN_MINT_PREDICATE = 0x03,
    CS_ACTIVE_WHEN_IS_ANOTHER_SIGNER = 0x04,
};

enum cs_hide_condition {
    CS_HIDE_CONDITION_CREATED_IN_TRANSACTION = 0x00,
    CS_HIDE_CONDITION_IS_SIGNER = 0x01,
    CS_HIDE_CONDITION_ACCOUNT_USED_ELSEWHERE = 0x02,
    CS_HIDE_CONDITION_IS_ANOTHER_SIGNER = 0x03,
    CS_HIDE_CONDITION_ACCOUNT_EFFECTS_DISPLAYED_ELSEWHERE = 0x04,
};

// An owned deep copy of a parsed VALUE sub-TLV. `source` is enum cs_value_source;
// `payload` is heap, sized to payload_size, owned by the enclosing template.
typedef struct cs_stored_value_s {
    uint8_t source;
    uint8_t *payload;
    size_t payload_size;
} cs_stored_value_t;

// AMOUNT_VALUE carried by a port or an account reset. NUMERIC wraps a VALUE;
// BALANCE is symbolic and carries no value.
typedef struct cs_amount_value_s {
    uint8_t kind;  // enum cs_amount_kind
    bool has_value;
    cs_stored_value_t value;
} cs_amount_value_t;

// TOKEN_VALUE carried by a port. `kind` selects the resolution path: DIRECT uses
// `value`, RESOLVE optionally uses `account_index` / `fallback_account_index`,
// NULL and NATIVE carry nothing.
typedef struct cs_token_value_s {
    uint8_t kind;  // enum cs_token_kind
    bool has_value;
    cs_stored_value_t value;
    bool has_account;
    uint8_t account_index;
    bool has_fallback_account;
    uint8_t fallback_account_index;
} cs_token_value_t;

// One VALUE_FLOW_PORT: a leg of value movement. `account_candidates` is an
// ordered list resolved to the first-provided candidate at finalize;
// `active_when` holds the raw packed predicate bytes evaluated by the merge engine.
typedef struct cs_value_flow_port_s {
    uint8_t direction;           // enum cs_port_direction
    uint8_t *account_candidates;  // heap, sized to candidate_count
    size_t candidate_count;
    uint8_t value_kind;  // enum cs_port_value_kind
    cs_amount_value_t amount;
    bool has_token;
    cs_token_value_t token;
    uint8_t *active_when;  // heap, raw packed predicate bytes; NULL when absent
    size_t active_when_size;
    uint8_t optional_account_strategy;  // enum cs_optional_account_strategy
} cs_value_flow_port_t;

// One HIDE_RULE. Rules sharing rule_set_index are ANDed; different indices ORed.
typedef struct cs_hide_rule_s {
    uint8_t rule_set_index;
    cs_stored_value_t target;  // pubkey-resolving VALUE
    uint8_t condition;         // enum cs_hide_condition
} cs_hide_rule_t;

// One SCOPE_DISCRIMINATOR prefix (0..8 bytes) inside a RESET_SCOPE.
typedef struct cs_reset_discriminator_s {
    uint8_t *data;  // heap, sized to size
    uint8_t size;
} cs_reset_discriminator_t;

// RESET_SCOPE: restricts which downstream consumers may rely on a reset. The
// discriminator prefixes carry OR semantics.
typedef struct cs_reset_scope_s {
    bool has_program_id;
    uint8_t scope_program_id[32];
    cs_reset_discriminator_t *discriminators;  // heap, sized to discriminator_count
    size_t discriminator_count;
} cs_reset_scope_t;

// One ACCOUNT_RESET: a known post-instruction balance for an account.
typedef struct cs_account_reset_s {
    uint8_t account_index;
    bool require_pre_balance_zero;
    bool has_reset_value;
    cs_amount_value_t reset_value;  // BALANCE kind rejected at ingest
    bool has_scope;
    cs_reset_scope_t scope;
} cs_account_reset_t;

// One complete instruction template, keyed by (program_id, discriminator).
// Only ever exposed once fully assembled, so every field is valid.
typedef struct cs_instruction_template_s {
    uint8_t program_id[32];
    uint8_t *discriminator;  // heap, sized to discriminator_size; owned by this template
    uint8_t discriminator_size;
    char *operation_type;    // heap, NUL-terminated; owned by this template
    char *program_name;      // heap, NUL-terminated; owned by this template, NULL when absent
    uint8_t *idl_type_pool;  // heap, sized to idl_type_pool_size; owned by this template
    size_t idl_type_pool_size;
    uint8_t idl_root_type;
    cs_display_field_t *display_fields;  // heap, sized to display_field_count; owned by this template
    size_t display_field_count;
    uint8_t mint_assoc_account;
    uint8_t mint_assoc_mint;
    bool has_mint_assoc;
    cs_value_flow_port_t *ports;  // heap, sized to port_count; owned by this template
    size_t port_count;
    cs_hide_rule_t *hide_rules;  // heap, sized to hide_rule_count; owned by this template
    size_t hide_rule_count;
    cs_account_reset_t *account_resets;  // heap, sized to account_reset_count; owned
    size_t account_reset_count;
    bool has_owner_assoc;
    uint8_t owner_assoc_account;
    cs_stored_value_t owner_assoc_owner;  // pubkey-resolving VALUE, owned
} cs_instruction_template_t;

// Open a fresh in-flight builder committed to `target_hash` (the SHA-256 the
// signed INSTRUCTION_INFO descriptor expects over its substructures) and start
// the matching substructure hash accumulation. Returns the zeroed builder for
// the caller to fill, or NULL when the table or builder cannot be allocated.
// Discards any previous unfinished builder.
cs_instruction_template_t *cs_instruction_template_open(const uint8_t target_hash[32]);

// The in-flight builder being assembled, or NULL when none is open.
cs_instruction_template_t *cs_instruction_template_current(void);

// Append an argument-path display field. `name` is NULL (unlabeled) or non-empty.
// Returns 0, or -1 on no builder / bad path / allocation failure.
int cs_instruction_template_add_display_path(const uint8_t *path,
                                             size_t path_size,
                                             uint8_t param_type,
                                             const char *name);

// Append an account-path display field (rendered as a short base58 address).
// `name` is NULL (unlabeled) or non-empty. Returns 0, -1 on error.
int cs_instruction_template_add_account_field(uint8_t account_index, const char *name);

// Append a CONSTANT display field carrying `data` and its IDL `kind` for format_leaf.
// `name` is NULL (unlabeled) or non-empty. Returns 0, -1 on error.
int cs_instruction_template_add_constant_field(const uint8_t *data,
                                               size_t data_size,
                                               uint8_t kind,
                                               const char *name);

// Store the operation type / program name (str_size bytes, empty rejected). The
// caller skips the call for an absent optional value. Returns 0, -1 on error.
int cs_instruction_template_set_operation_type(const char *str, size_t str_size);
int cs_instruction_template_set_program_name(const char *str, size_t str_size);

// Store the discriminator; empty matches any instruction for the program id.
// Returns 0, -1 on error.
int cs_instruction_template_set_discriminator(const uint8_t *data, size_t size);

// Set AMOUNT format parameters on the last added display field. `max_label`
// (max_label_size bytes, absent when the size is 0) is copied into a heap buffer
// owned by the template. Must be called immediately after adding a field with
// param_type == AMOUNT. Returns 0, -1 on no matching field or allocation failure.
int cs_instruction_template_set_format_amount(uint8_t decimals,
                                             const uint8_t *max_label,
                                             size_t max_label_size);

// Set TOKEN_AMOUNT format parameters on the last added display field. The
// caller builds a fully-validated `format` (mint source, optional embedded mint
// or account index, optional decimals override) and hands it over atomically;
// its `max_label` field is ignored in favour of the `max_label` argument
// (max_label_size bytes, absent when the size is 0), which is copied into a heap
// buffer owned by the template. Must be called immediately after adding a field
// with param_type == TOKEN_AMOUNT. Returns 0, -1 on no matching field or
// allocation failure.
int cs_instruction_template_set_format_token_amount(const cs_format_token_amount_t *format,
                                                    const uint8_t *max_label,
                                                    size_t max_label_size);

// Set DATETIME format parameters on the last added display field.
// Must be called immediately after adding a field with param_type == DATETIME.
// Returns 0 on success, -1 when no matching field is open.
int cs_instruction_template_set_format_datetime(uint32_t ticks_per_second);

// Set UNIT format parameters on the last added display field. `symbol` (symbol_size
// bytes, may be empty) is copied into a heap buffer owned by the template.
// Must be called immediately after adding a field with param_type == UNIT.
// Returns 0 on success, -1 when no matching field is open or the allocation fails.
int cs_instruction_template_set_format_unit(const uint8_t *symbol,
                                            size_t symbol_size,
                                            uint8_t decimals,
                                            bool prefix);

// Set STRING format parameters on the last added display field.
// Must be called immediately after adding a field with param_type == STRING.
// Returns 0 on success, -1 when no matching field is open.
int cs_instruction_template_set_format_string(const cs_format_string_t *format);

// Set TRUSTED_NAME format parameters (type/source allow-list masks) on the last
// added display field. Must be called immediately after adding a field with
// param_type == TRUSTED_NAME. Returns 0 on success, -1 when no matching field.
int cs_instruction_template_set_format_trusted_name(const cs_format_trusted_name_t *format);

// Copy the IDL type pool into a right-sized heap buffer owned by the in-flight
// builder. `size` is the exact byte length streamed by the descriptor.
// Returns 0 on success, -1 when no builder is open or the allocation fails.
int cs_instruction_template_set_idl_type_pool(const uint8_t *data, size_t size);

// Set mint association indices on the in-flight builder. Both indices refer to
// the instruction's accounts array: `account_idx` is the token account,
// `mint_idx` is the mint account whose pubkey identifies the token.
// Returns 0 on success, -1 when no builder is open.
int cs_instruction_template_set_mint_assoc(uint8_t account_idx, uint8_t mint_idx);

// Append a VALUE_FLOW_PORT / HIDE_RULE / ACCOUNT_RESET to the in-flight builder.
// The passed struct carries borrowed pointers (views into the APDU message); the
// setter deep-copies every buffer into template-owned heap. Returns 0, -1 on no
// builder / allocation failure.
int cs_instruction_template_add_port(const cs_value_flow_port_t *port);
int cs_instruction_template_add_hide_rule(const cs_hide_rule_t *rule);
int cs_instruction_template_add_account_reset(const cs_account_reset_t *reset);

// Store the OWNER_ASSOC pair on the in-flight builder: the bound token account
// index and the owner as a pubkey-resolving VALUE (source + borrowed payload,
// deep-copied). Returns 0, -1 on no builder / allocation failure.
int cs_instruction_template_set_owner_assoc(uint8_t account_idx,
                                            uint8_t owner_source,
                                            const uint8_t *owner_payload,
                                            size_t owner_payload_size);

// Promote the in-flight builder into the committed array. Must be called only
// once the substructure accumulation has matched the committed target. Returns 0
// on success, -1 when no builder is open or the array cannot be grown.
int cs_instruction_template_commit(void);

// Number of committed (whole, walker-ready) templates.
size_t cs_instruction_template_committed_count(void);

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
