#include <string.h>
#include <stdio.h>

#include "cs_display_renderer.h"
#include "cs_instruction_template.h"
#include "app_mem_utils.h"
#include "idl_kinds.h"
#include "sol/printer.h"
#include "sol/pubkey.h"
#include "sol/string_utils.h"
#include "print_float.h"
#include "util.h"
#include "os_print.h"
#include "dynamic_token_info.h"
#include "cs_trusted_name_cache.h"
#include "system_instruction.h"
#include "stake_instruction.h"
#include "vote_instruction.h"
#include "spl_token_instruction.h"
#include "spl_token2022_instruction.h"
#include "spl_associated_token_account_instruction.h"
#include "compute_budget_instruction.h"

#define CS_FIELD_CAP_STEP       8
#define CS_INSTRUCTION_CAP_STEP 4

typedef struct cs_display_renderer_table_s {
    cs_display_instruction_t *instructions;
    size_t instruction_count;
    size_t instruction_capacity;
    cs_display_transaction_fields_t transaction_fields;
} cs_display_renderer_table_t;

static cs_display_renderer_table_t G_cs_display_renderer;

// Widths of the fixed-shape renderings, each derived from the type being printed rather
// than chosen: a u64 in decimal, the widest number any leaf prints (a signed 128-bit
// integer, which also bounds every narrower integer and both float forms), the
// "True"/"False" and "<empty>" literals, and the "YYYY-MM-DDThh:mm:ss+00:00" datetime form.
#define CS_UINT64_TEXT_SIZE   (20 + 1)
#define CS_NUMBER_TEXT_SIZE   (1 + 39 + 1)
#define CS_BOOL_TEXT_SIZE     (sizeof("False"))
#define CS_EMPTY_TEXT_SIZE    (sizeof("<empty>"))
#define CS_DATETIME_TEXT_SIZE (sizeof("YYYY-MM-DDThh:mm:ss+00:00"))
// H:MM:SS where the hour count is a u64 of seconds divided by 3600.
#define CS_DURATION_TEXT_SIZE (CS_UINT64_TEXT_SIZE + sizeof(":MM:SS"))

// Bytes print_token_amount can write for `decimals` scaling, before any symbol: the widest
// u64, a decimal point, and the zero padding a large scale forces.
#define CS_SCALED_AMOUNT_TEXT_SIZE(decimals) (CS_UINT64_TEXT_SIZE + 1 + (size_t) (decimals) + 1)

// Larger of two capacities, so a formatter that can take either of two shapes gets a buffer
// fitting both.
static size_t larger_capacity(size_t left, size_t right) {
    if (left > right) {
        return left;
    }
    return right;
}

// Bytes base58 needs for `byte_count` raw bytes: log(256)/log(58) is under 1.38, so 138/100
// bounds the digit count, plus the NUL.
static size_t base58_capacity(size_t byte_count) {
    return (byte_count * 138) / 100 + 2;
}

// Bytes the trusted name cached for a 32-byte address needs, or 0 when the address has no
// cached name or the leaf is not an address.
static size_t trusted_name_capacity(const idl_resolved_leaf_t *leaf) {
    if (leaf->value == NULL || leaf->value_size < PUBKEY_SIZE) {
        return 0;
    }
    const cs_trusted_name_t *entry = cs_trusted_name_cache_find(leaf->value);
    if (entry == NULL) {
        return 0;
    }
    return strlen(entry->name) + 1;
}

// Bytes `encoding` needs to render `in_len` raw bytes.
static size_t encoded_capacity(uint8_t encoding, size_t in_len) {
    switch (encoding) {
        case CS_STRING_ENCODING_ASCII:
        case CS_STRING_ENCODING_UTF8:
            return in_len + 1;

        case CS_STRING_ENCODING_BASE58:
            return base58_capacity(in_len);

        case CS_STRING_ENCODING_BASE64:
            return 4 * ((in_len + 2) / 3) + 1;

        case CS_STRING_ENCODING_HEX:
            return 2 * in_len + 1;

        default:
            PRINTF("encoded_capacity: unsupported encoding %d\n", encoding);
            return 0;
    }
}

// Bytes format_leaf needs for this leaf, judged from its kind and byte count.
static size_t leaf_render_capacity(const idl_resolved_leaf_t *leaf) {
    if (leaf->value == NULL || leaf->value_size == 0) {
        return CS_EMPTY_TEXT_SIZE;
    }
    switch (leaf->kind) {
        case IDL_KIND_U8:
        case IDL_KIND_U16:
        case IDL_KIND_U32:
        case IDL_KIND_U64:
        case IDL_KIND_SHORT_U16:
        case IDL_KIND_I8:
        case IDL_KIND_I16:
        case IDL_KIND_I32:
        case IDL_KIND_I64:
        case IDL_KIND_F32:
        case IDL_KIND_F64:
        case IDL_KIND_U128:
        case IDL_KIND_I128:
            return CS_NUMBER_TEXT_SIZE;

        case IDL_KIND_BOOL_U8:
        case IDL_KIND_BOOL_U16:
        case IDL_KIND_BOOL_U32:
            return CS_BOOL_TEXT_SIZE;

        case IDL_KIND_BYTES_FIXED:
        case IDL_KIND_BYTES_REMAINDER:
            return 2 * leaf->value_size + 1;

        case IDL_KIND_PUBKEY_32:
            return base58_capacity(PUBKEY_SIZE);

        case IDL_KIND_STRING_FIXED:
        case IDL_KIND_STRING_PREFIXED:
        case IDL_KIND_ENUM:
            return leaf->value_size + 1;

        default:
            PRINTF("leaf_render_capacity: unsupported kind %d\n", leaf->kind);
            return 0;
    }
}

// Bytes a scaled amount plus its optional symbol and MAX_LABEL sentinel need.
static size_t amount_render_capacity(uint8_t decimals, const char *symbol, const char *max_label) {
    size_t needed = CS_SCALED_AMOUNT_TEXT_SIZE(decimals);
    if (symbol != NULL) {
        // print_token_amount separates the number and the symbol with one space.
        needed += 1 + strlen(symbol);
    }
    if (max_label != NULL) {
        needed = larger_capacity(needed, strlen(max_label) + 1);
    }
    return needed;
}

// Bytes a PARAM_STRING needs. Without a slice the whole encoding is shown; a slice can only
// select part of it, so the unsliced size bounds both.
static size_t string_render_capacity(const cs_format_string_t *string,
                                     const idl_resolved_leaf_t *leaf) {
    return encoded_capacity(string->encoding, leaf->value_size);
}

// Grow a rendered field array by one step.
static int ensure_field_capacity(cs_rendered_field_t **fields, size_t count, size_t *capacity) {
    if (count < *capacity) {
        return 0;
    }
    if (*capacity == 0) {
        cs_rendered_field_t *initial = NULL;
        if (!APP_MEM_CALLOC((void **) &initial, CS_FIELD_CAP_STEP * sizeof(*initial))) {
            PRINTF("ensure_field_capacity: allocation failed\n");
            return -1;
        }
        *fields = initial;
        *capacity = CS_FIELD_CAP_STEP;
    } else {
        size_t new_capacity = *capacity + CS_FIELD_CAP_STEP;
        cs_rendered_field_t *grown = APP_MEM_REALLOC(*fields, new_capacity * sizeof(*grown));
        if (grown == NULL) {
            PRINTF("ensure_field_capacity: growth failed\n");
            return -1;
        }
        *fields = grown;
        *capacity = new_capacity;
    }
    return 0;
}

// Ensure the instruction array can hold one more entry.
static int ensure_instruction_capacity(void) {
    if (G_cs_display_renderer.instruction_count < G_cs_display_renderer.instruction_capacity) {
        return 0;
    }
    if (G_cs_display_renderer.instruction_capacity == 0) {
        cs_display_instruction_t *initial = NULL;
        if (!APP_MEM_CALLOC((void **) &initial, CS_INSTRUCTION_CAP_STEP * sizeof(*initial))) {
            PRINTF("ensure_instruction_capacity: allocation failed\n");
            return -1;
        }
        G_cs_display_renderer.instructions = initial;
        G_cs_display_renderer.instruction_capacity = CS_INSTRUCTION_CAP_STEP;
    } else {
        size_t new_capacity = G_cs_display_renderer.instruction_capacity + CS_INSTRUCTION_CAP_STEP;
        cs_display_instruction_t *grown = APP_MEM_REALLOC(G_cs_display_renderer.instructions,
                                                          new_capacity * sizeof(*grown));
        if (grown == NULL) {
            PRINTF("ensure_instruction_capacity: growth failed\n");
            return -1;
        }
        G_cs_display_renderer.instructions = grown;
        G_cs_display_renderer.instruction_capacity = new_capacity;
    }
    return 0;
}

// Allocate and return a new instruction entry in the table.
static cs_display_instruction_t *append_instruction(void) {
    if (ensure_instruction_capacity() != 0) {
        return NULL;
    }
    // A reserved capacity implies a live table; refuse rather than index a null base.
    if (G_cs_display_renderer.instructions == NULL) {
        PRINTF("append_instruction: instruction table missing after reservation\n");
        return NULL;
    }
    cs_display_instruction_t
        *instruction = &G_cs_display_renderer.instructions[G_cs_display_renderer.instruction_count];
    explicit_bzero(instruction, sizeof(*instruction));
    G_cs_display_renderer.instruction_count++;
    PRINTF("append_instruction: index=%u\n",
           (unsigned) (G_cs_display_renderer.instruction_count - 1));
    return instruction;
}

// Append a rendered field to an instruction's field list.
static cs_rendered_field_t *append_instruction_field(cs_display_instruction_t *instruction) {
    if (ensure_field_capacity(&instruction->fields,
                              instruction->field_count,
                              &instruction->field_capacity) != 0) {
        return NULL;
    }
    cs_rendered_field_t *field = &instruction->fields[instruction->field_count];
    explicit_bzero(field, sizeof(*field));
    instruction->field_count++;
    return field;
}

// Append a rendered field to the transaction-level field list.
static cs_rendered_field_t *append_transaction_field(void) {
    cs_display_transaction_fields_t *txn = &G_cs_display_renderer.transaction_fields;
    if (ensure_field_capacity(&txn->fields, txn->field_count, &txn->field_capacity) != 0) {
        return NULL;
    }
    cs_rendered_field_t *field = &txn->fields[txn->field_count];
    explicit_bzero(field, sizeof(*field));
    txn->field_count++;
    return field;
}

// Free a single rendered field's strings.
static void free_rendered_field(cs_rendered_field_t *field) {
    APP_MEM_FREE_AND_NULL((void **) &field->title);
    APP_MEM_FREE_AND_NULL((void **) &field->value);
}

// Free a rendered field array and its strings.
static void free_rendered_fields(cs_rendered_field_t **fields, size_t count) {
    if (*fields == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free_rendered_field(&(*fields)[i]);
    }
    APP_MEM_FREE_AND_NULL((void **) fields);
}

void cs_display_renderer_reset(void) {
    PRINTF("cs_display_renderer_reset\n");
    for (size_t i = 0; i < G_cs_display_renderer.instruction_count; i++) {
        cs_display_instruction_t *instruction = &G_cs_display_renderer.instructions[i];
        APP_MEM_FREE_AND_NULL((void **) &instruction->intent);
        APP_MEM_FREE_AND_NULL((void **) &instruction->program);
        free_rendered_fields(&instruction->fields, instruction->field_count);
    }
    if (G_cs_display_renderer.instructions != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &G_cs_display_renderer.instructions);
    }
    G_cs_display_renderer.instruction_count = 0;
    G_cs_display_renderer.instruction_capacity = 0;

    free_rendered_fields(&G_cs_display_renderer.transaction_fields.fields,
                         G_cs_display_renderer.transaction_fields.field_count);
    G_cs_display_renderer.transaction_fields.field_count = 0;
    G_cs_display_renderer.transaction_fields.field_capacity = 0;
}

// Shrink a formatted working buffer to its string length and return the fitted
// buffer. On failure the working buffer is freed and NULL returned.
static char *shrink_render_buffer(char *buffer) {
    size_t fitted_size = strlen(buffer) + 1;
    char *fitted = APP_MEM_REALLOC(buffer, fitted_size);
    if (fitted == NULL) {
        PRINTF("shrink_render_buffer: shrink to %u bytes failed\n", (unsigned) fitted_size);
        APP_MEM_FREE_AND_NULL((void **) &buffer);
        return NULL;
    }
    PRINTF("shrink_render_buffer: %u bytes: %s\n", (unsigned) fitted_size, fitted);
    return fitted;
}

// Copy a NUL-terminated string into a freshly sized heap buffer.
static char *duplicate_string(const char *source) {
    size_t size = strlen(source) + 1;
    char *copy = NULL;
    if (!APP_MEM_CALLOC((void **) &copy, size)) {
        PRINTF("duplicate_string: allocation of %u bytes failed\n", (unsigned) size);
        return NULL;
    }
    memcpy(copy, source, size);
    return copy;
}

// Read a little-endian signed integer from leaf bytes, sign-extended to i64.
// Returns 0 on success, -1 on unsupported kind or truncation.
static int read_leaf_i64(const idl_resolved_leaf_t *leaf, int64_t *out) {
    size_t width = 0;

    switch (leaf->kind) {
        case IDL_KIND_I8:
            width = 1;
            break;
        case IDL_KIND_I16:
            width = 2;
            break;
        case IDL_KIND_I32:
            width = 4;
            break;
        case IDL_KIND_I64:
            width = 8;
            break;
        default:
            PRINTF("read_leaf_i64: unsupported kind=%d\n", leaf->kind);
            return -1;
    }

    if (leaf->value_size < width) {
        PRINTF("read_leaf_i64: value truncated (size=%u < width=%u)\n",
               (unsigned) leaf->value_size,
               (unsigned) width);
        return -1;
    }

    uint64_t raw = 0;
    for (size_t i = 0; i < width; i++) {
        raw |= (uint64_t) leaf->value[i] << (8 * i);
    }
    // Sign-extend from the width's top bit for kinds narrower than 64 bits.
    if (width < 8 && (raw & ((uint64_t) 1 << (width * 8 - 1))) != 0) {
        raw |= ~(((uint64_t) 1 << (width * 8)) - 1);
    }
    *out = (int64_t) raw;
    return 0;
}

// Format a single resolved leaf into the value buffer based on its kind.
// Returns 0 on success, -1 on failure.
static int format_leaf(const idl_resolved_leaf_t *leaf, char *value_out, size_t value_out_size) {
    if (leaf->value == NULL || leaf->value_size == 0) {
        strlcpy(value_out, "<empty>", value_out_size);
        return 0;
    }

    switch (leaf->kind) {
        case IDL_KIND_U8:
            if (leaf->value_size < 1) {
                PRINTF("format_leaf: u8 truncated\n");
                return -1;
            }
            print_u64(leaf->value[0], value_out, value_out_size);
            return 0;

        case IDL_KIND_U16:
            if (leaf->value_size < 2) {
                PRINTF("format_leaf: u16 truncated\n");
                return -1;
            }
            print_u64((uint64_t) (leaf->value[0] | (leaf->value[1] << 8)),
                      value_out,
                      value_out_size);
            return 0;

        case IDL_KIND_U32:
            if (leaf->value_size < 4) {
                PRINTF("format_leaf: u32 truncated\n");
                return -1;
            }
            // Each byte is cast to u64 before shifting: without it value[3]<<24 sets bit 31 of an
            // int, and the u64 cast then sign-extends into bits 32-63 for values >= 0x80000000.
            print_u64((uint64_t) leaf->value[0] | ((uint64_t) leaf->value[1] << 8) |
                          ((uint64_t) leaf->value[2] << 16) | ((uint64_t) leaf->value[3] << 24),
                      value_out,
                      value_out_size);
            return 0;

        case IDL_KIND_U64:
            if (leaf->value_size < 8) {
                PRINTF("format_leaf: u64 truncated\n");
                return -1;
            }
            print_u64((uint64_t) leaf->value[0] | ((uint64_t) leaf->value[1] << 8) |
                          ((uint64_t) leaf->value[2] << 16) | ((uint64_t) leaf->value[3] << 24) |
                          ((uint64_t) leaf->value[4] << 32) | ((uint64_t) leaf->value[5] << 40) |
                          ((uint64_t) leaf->value[6] << 48) | ((uint64_t) leaf->value[7] << 56),
                      value_out,
                      value_out_size);
            return 0;

        case IDL_KIND_U128:
            if (leaf->value_size < 16) {
                PRINTF("format_leaf: u128 truncated\n");
                return -1;
            }
            if (print_u128(leaf->value, value_out, value_out_size) != 0) {
                PRINTF("format_leaf: print_u128 failed\n");
                return -1;
            }
            return 0;

        case IDL_KIND_I8:
        case IDL_KIND_I16:
        case IDL_KIND_I32:
        case IDL_KIND_I64: {
            int64_t signed_value;
            if (read_leaf_i64(leaf, &signed_value) != 0) {
                PRINTF("format_leaf: signed read failed\n");
                return -1;
            }
            if (print_i64(signed_value, value_out, value_out_size) != 0) {
                PRINTF("format_leaf: print_i64 failed\n");
                return -1;
            }
            return 0;
        }

        case IDL_KIND_I128:
            if (leaf->value_size < 16) {
                PRINTF("format_leaf: i128 truncated\n");
                return -1;
            }
            if (print_i128(leaf->value, value_out, value_out_size) != 0) {
                PRINTF("format_leaf: print_i128 failed\n");
                return -1;
            }
            return 0;

        case IDL_KIND_SHORT_U16: {
            // The leaf carries the raw compact-u16 varint bytes; re-decode them.
            uint64_t decoded = 0;
            for (size_t i = 0; i < leaf->value_size && i < 3; i++) {
                decoded |= (uint64_t) (leaf->value[i] & 0x7F) << (7 * i);
                if ((leaf->value[i] & 0x80) == 0) {
                    break;
                }
            }
            if (print_u64(decoded, value_out, value_out_size) != 0) {
                PRINTF("format_leaf: short_u16 print_u64 failed\n");
                return -1;
            }
            return 0;
        }

        case IDL_KIND_BOOL_U8:
        case IDL_KIND_BOOL_U16:
        case IDL_KIND_BOOL_U32: {
            size_t width;
            if (leaf->kind == IDL_KIND_BOOL_U8) {
                width = 1;
            } else if (leaf->kind == IDL_KIND_BOOL_U16) {
                width = 2;
            } else {
                width = 4;
            }
            if (leaf->value_size < width) {
                PRINTF("format_leaf: bool truncated\n");
                return -1;
            }
            bool is_true = false;
            for (size_t i = 0; i < width; i++) {
                if (leaf->value[i] != 0) {
                    is_true = true;
                    break;
                }
            }
            if (is_true) {
                strlcpy(value_out, "True", value_out_size);
            } else {
                strlcpy(value_out, "False", value_out_size);
            }
            return 0;
        }

        case IDL_KIND_F32:
            if (leaf->value_size < 4) {
                PRINTF("format_leaf: f32 truncated\n");
                return -1;
            }
            if (print_f32(leaf->value, value_out, value_out_size) != 0) {
                PRINTF("format_leaf: print_f32 failed\n");
                return -1;
            }
            return 0;

        case IDL_KIND_F64:
            if (leaf->value_size < 8) {
                PRINTF("format_leaf: f64 truncated\n");
                return -1;
            }
            if (print_f64(leaf->value, value_out, value_out_size) != 0) {
                PRINTF("format_leaf: print_f64 failed\n");
                return -1;
            }
            return 0;

        case IDL_KIND_BYTES_FIXED:
        case IDL_KIND_BYTES_REMAINDER:
            if (encode_hex(leaf->value, leaf->value_size, value_out, value_out_size) < 0) {
                PRINTF("format_leaf: bytes hex encode failed\n");
                return -1;
            }
            return 0;

        case IDL_KIND_PUBKEY_32:
            if (leaf->value_size < PUBKEY_SIZE) {
                PRINTF("format_leaf: pubkey truncated\n");
                return -1;
            }
            if (encode_base58(leaf->value, PUBKEY_SIZE, value_out, value_out_size) < 0) {
                PRINTF("format_leaf: base58 encode failed\n");
                return -1;
            }
            return 0;

        case IDL_KIND_STRING_FIXED:
        case IDL_KIND_STRING_PREFIXED:
        case IDL_KIND_ENUM: {
            // ENUM leaves carry the selected variant's display name (a string).
            // Refuse rather than truncate: a shortened value would misrepresent
            // what the user is signing.
            if (leaf->value_size >= value_out_size) {
                PRINTF(
                    "format_leaf: string value (%u) does not fit buffer "
                    "(%u)\n",
                    (unsigned) leaf->value_size,
                    (unsigned) value_out_size);
                return -1;
            }
            memcpy(value_out, leaf->value, leaf->value_size);
            value_out[leaf->value_size] = '\0';
            return 0;
        }

        default:
            PRINTF("format_leaf: unsupported kind %d\n", leaf->kind);
            return -1;
    }
}

// Read a little-endian unsigned integer from leaf bytes into a u64.
// Returns 0 on success, -1 on unsupported kind.
static int read_leaf_u64(const idl_resolved_leaf_t *leaf, uint64_t *out) {
    size_t width = 0;
    if (idl_unsigned_kind_width(leaf->kind, &width) != 0) {
        PRINTF("read_leaf_u64: unsupported kind=%d\n", leaf->kind);
        return -1;
    }

    if (leaf->value_size < width) {
        PRINTF("read_leaf_u64: value truncated (size=%u < width=%u)\n",
               (unsigned) leaf->value_size,
               (unsigned) width);
        return -1;
    }

    *out = 0;
    for (size_t i = 0; i < width; i++) {
        *out |= (uint64_t) leaf->value[i] << (8 * i);
    }
    return 0;
}

// True when `value` equals the maximum of the leaf's unsigned IDL number type.
static bool leaf_at_unsigned_max(uint8_t kind, uint64_t value) {
    switch (kind) {
        case IDL_KIND_U8:
            return value == UINT8_MAX;
        case IDL_KIND_U16:
            return value == UINT16_MAX;
        case IDL_KIND_U32:
            return value == UINT32_MAX;
        case IDL_KIND_U64:
            return value == UINT64_MAX;
        default:
            return false;
    }
}

// Render a MAX_LABEL sentinel.
static int render_max_label(const char *max_label, char *value_out, size_t value_out_size) {
    if (strlen(max_label) >= value_out_size) {
        PRINTF("render_max_label: label does not fit buffer (%u)\n", (unsigned) value_out_size);
        return -1;
    }
    strlcpy(value_out, max_label, value_out_size);
    return 0;
}

// PARAM_AMOUNT: numeric value with fixed decimal scaling, or the MAX_LABEL
// sentinel when the raw integer is at its IDL type's maximum.
static int format_amount(const idl_resolved_leaf_t *leaf,
                         const cs_format_amount_t *fmt,
                         char *value_out,
                         size_t value_out_size) {
    uint64_t amount;
    if (read_leaf_u64(leaf, &amount) != 0) {
        PRINTF("format_amount: unsupported leaf kind %d\n", leaf->kind);
        return -1;
    }

    int status;
    if (fmt->max_label != NULL && leaf_at_unsigned_max(leaf->kind, amount)) {
        status = render_max_label(fmt->max_label, value_out, value_out_size);
    } else {
        status = print_token_amount(amount, NULL, fmt->decimals, value_out, value_out_size);
        if (status != 0) {
            PRINTF("format_amount: print_token_amount failed\n");
            status = -1;
        }
    }
    return status;
}

// Resolve the ticker and decimal scaling a PARAM_TOKEN_AMOUNT displays with, per spec
// "Token amount metadata resolution": the mint's TOKEN_INFO supplies both, an explicit
// DECIMALS overrides the magnitude, and an unresolved mint degrades to a bare amount.
// Sizing and formatting both call this, so the buffer always matches what is written.
// Returns 0 on success, -1 when the descriptor names a mint the walk never resolved.
static int resolve_token_display(const cs_format_token_amount_t *fmt,
                                 const uint8_t *mint_pubkey,
                                 const char **symbol_out,
                                 uint8_t *magnitude_out) {
    switch (fmt->mint_source) {
        case CS_TOKEN_MINT_NATIVE:
            PRINTF("resolve_token_display: native SOL\n");
            *symbol_out = "SOL";
            *magnitude_out = SOL_DECIMALS;
            return 0;

        case CS_TOKEN_MINT_NONE:
            *symbol_out = NULL;
            *magnitude_out = 0;
            if (fmt->has_decimals) {
                *magnitude_out = fmt->decimals;
            }
            PRINTF("resolve_token_display: no mint, bare render decimals=%d\n", *magnitude_out);
            return 0;

        case CS_TOKEN_MINT_ACCOUNT_INDEX:
        case CS_TOKEN_MINT_CONSTANT: {
            // finalize resolves referenced mints; a NULL here is an upstream bug.
            if (mint_pubkey == NULL) {
                PRINTF("resolve_token_display: mint_source %d has no resolved mint\n",
                       fmt->mint_source);
                return -1;
            }
            // A descriptor names the mint, never the token program that will move it, so the
            // lookup keys on the mint alone and Token-2022 metadata resolves.
            const char *symbol = get_token_symbol_by_mint(mint_pubkey);
            int magnitude = get_token_magnitude_by_mint(mint_pubkey);
            PRINTF("resolve_token_display: registry symbol=%s magnitude=%d\n",
                   symbol == NULL ? "(none)" : symbol,
                   magnitude);
            if (fmt->has_decimals) {
                magnitude = fmt->decimals;
                PRINTF("resolve_token_display: decimals overridden to %d\n", magnitude);
            }
            if (magnitude < 0) {
                // No metadata for this mint: the spec degrades the display rather than the
                // amount, so the raw integer is shown against an unnamed ticker.
                PRINTF("resolve_token_display: mint unknown, ticker=???\n");
                symbol = "???";
                magnitude = 0;
            }
            *symbol_out = symbol;
            *magnitude_out = (uint8_t) magnitude;
            return 0;
        }

        default:
            PRINTF("resolve_token_display: unknown mint_source %d\n", fmt->mint_source);
            return -1;
    }
}

// PARAM_TOKEN_AMOUNT: renders a raw amount with the ticker and decimal scaling
// implied by the descriptor's mint_source.
static int format_token_amount(const idl_resolved_leaf_t *leaf,
                               const cs_format_token_amount_t *fmt,
                               const uint8_t *mint_pubkey,
                               char *value_out,
                               size_t value_out_size) {
    uint64_t amount;
    if (read_leaf_u64(leaf, &amount) != 0) {
        PRINTF("format_token_amount: unsupported leaf kind %d\n", leaf->kind);
        return -1;
    }

    int status;
    if (fmt->max_label != NULL && leaf_at_unsigned_max(leaf->kind, amount)) {
        status = render_max_label(fmt->max_label, value_out, value_out_size);
    } else {
        const char *symbol;
        uint8_t magnitude;
        if (resolve_token_display(fmt, mint_pubkey, &symbol, &magnitude) != 0) {
            return -1;
        }
        status = print_token_amount(amount, symbol, magnitude, value_out, value_out_size);
        if (status != 0) {
            PRINTF("format_token_amount: print_token_amount failed\n");
            status = -1;
        }
    }
    return status;
}

// Write the cached name for a 32-byte address leaf when its type satisfies the
// allow-list mask (zero = no constraint).
static bool resolve_trusted_name(const idl_resolved_leaf_t *leaf,
                                 uint8_t allowed_types_mask,
                                 char *value_out,
                                 size_t value_out_size) {
    if (leaf->value_size < PUBKEY_SIZE) {
        return false;
    }
    const cs_trusted_name_t *entry = cs_trusted_name_cache_find(leaf->value);
    if (entry == NULL) {
        return false;
    }
    bool type_allowed = (allowed_types_mask == 0) ||
                        (entry->type < 8 &&
                         (allowed_types_mask & (uint8_t) (1 << entry->type)) != 0);
    if (type_allowed) {
        // A shortened name would name a different thing than the address resolves to, so a
        // name that does not fit is left unrendered and the address is shown instead.
        if (strlen(entry->name) >= value_out_size) {
            PRINTF("resolve_trusted_name: name does not fit buffer (%u)\n",
                   (unsigned) value_out_size);
            return false;
        }
        strlcpy(value_out, entry->name, value_out_size);
        PRINTF("resolve_trusted_name: resolved name=%s\n", value_out);
        return true;
    }
    return false;
}

// ACCOUNT_PATH: full base58 address.
static int format_account(const idl_resolved_leaf_t *leaf, char *value_out, size_t value_out_size) {
    if (leaf->value_size < PUBKEY_SIZE) {
        PRINTF("format_account: value too short (%u < 32)\n", (unsigned) leaf->value_size);
        return -1;
    }
    if (encode_base58(leaf->value, PUBKEY_SIZE, value_out, value_out_size) < 0) {
        PRINTF("format_account: base58 encode failed\n");
        return -1;
    }
    return 0;
}

// PARAM_ACCOUNT: an argument resolving to a 32-byte address, rendered as a
// base58 short form.
static int format_account_short(const idl_resolved_leaf_t *leaf,
                                char *value_out,
                                size_t value_out_size) {
    char full[BASE58_PUBKEY_LENGTH];

    if (leaf->value_size < PUBKEY_SIZE) {
        PRINTF("format_account_short: value too short (%u < 32)\n", (unsigned) leaf->value_size);
        return -1;
    }
    if (encode_base58(leaf->value, PUBKEY_SIZE, full, sizeof(full)) < 0) {
        PRINTF("format_account_short: base58 encode failed\n");
        return -1;
    }
    if (value_out_size < BASE58_PUBKEY_SHORT) {
        PRINTF("format_account_short: output buffer too small (%u < %u)\n",
               (unsigned) value_out_size,
               (unsigned) BASE58_PUBKEY_SHORT);
        return -1;
    }
    if (print_summary(full, value_out, BASE58_PUBKEY_SHORT, SUMMARY_LENGTH, SUMMARY_LENGTH) != 0) {
        PRINTF("format_account_short: print_summary failed\n");
        return -1;
    }
    PRINTF("format_account_short: rendered value=%s\n", value_out);
    return 0;
}

// PARAM_TRUSTED_NAME: show the cached name for the address leaf, or its short
// base58 form when no permitted name exists.
static int format_trusted_name(const idl_resolved_leaf_t *leaf,
                               const cs_format_trusted_name_t *format,
                               char *value_out,
                               size_t value_out_size) {
    if (leaf->value_size < PUBKEY_SIZE) {
        PRINTF("format_trusted_name: value too short (%u < 32)\n", (unsigned) leaf->value_size);
        return -1;
    }

    if (resolve_trusted_name(leaf, format->allowed_types_mask, value_out, value_out_size)) {
        return 0;
    } else {
        PRINTF(
            "format_trusted_name: no permitted name, rendering short "
            "address\n");
        return format_account_short(leaf, value_out, value_out_size);
    }
}

// ACCOUNT_PATH: cached trusted name, else the full base58 address.
static int format_account_named(const idl_resolved_leaf_t *leaf,
                                char *value_out,
                                size_t value_out_size) {
    if (resolve_trusted_name(leaf, 0, value_out, value_out_size)) {
        return 0;
    } else {
        return format_account(leaf, value_out, value_out_size);
    }
}

// PARAM_ACCOUNT: cached trusted name, else the short base58 address.
static int format_account_short_named(const idl_resolved_leaf_t *leaf,
                                      char *value_out,
                                      size_t value_out_size) {
    if (resolve_trusted_name(leaf, 0, value_out, value_out_size)) {
        return 0;
    } else {
        return format_account_short(leaf, value_out, value_out_size);
    }
}

// True for the signed integer leaf kinds.
static bool is_signed_int_kind(uint8_t kind) {
    return kind == IDL_KIND_I8 || kind == IDL_KIND_I16 || kind == IDL_KIND_I32 ||
           kind == IDL_KIND_I64;
}

// PARAM_DURATION: a numeric value of seconds rendered as "H:MM:SS".
static int format_duration(const idl_resolved_leaf_t *leaf,
                           char *value_out,
                           size_t value_out_size) {
    uint64_t total_seconds;
    uint64_t hours;
    uint32_t minutes;
    uint32_t seconds;
    char hours_str[21];
    int written;

    if (is_signed_int_kind(leaf->kind)) {
        int64_t signed_seconds;
        if (read_leaf_i64(leaf, &signed_seconds) != 0) {
            PRINTF("format_duration: signed read failed\n");
            return -1;
        }
        if (signed_seconds < 0) {
            PRINTF("format_duration: negative duration %lld\n", signed_seconds);
            return -1;
        }
        total_seconds = (uint64_t) signed_seconds;
    } else {
        if (read_leaf_u64(leaf, &total_seconds) != 0) {
            PRINTF("format_duration: unsupported leaf kind %d\n", leaf->kind);
            return -1;
        }
    }
    hours = total_seconds / 3600;
    minutes = (uint32_t) ((total_seconds % 3600) / 60);
    seconds = (uint32_t) (total_seconds % 60);
    if (print_u64(hours, hours_str, sizeof(hours_str)) != 0) {
        PRINTF("format_duration: print_u64 failed\n");
        return -1;
    }
    const char *hours_pad = "";
    if (strlen(hours_str) < 2) {
        hours_pad = "0";
    }
    written = snprintf(value_out,
                       value_out_size,
                       "%s%s:%02u:%02u",
                       hours_pad,
                       hours_str,
                       minutes,
                       seconds);
    if (written < 0 || (size_t) written >= value_out_size) {
        PRINTF("format_duration: output does not fit\n");
        return -1;
    }
    PRINTF("format_duration: rendered value=%s\n", value_out);
    return 0;
}

// PARAM_DATETIME: a numeric value of ticks rendered as the ISO 8601 UTC form.
static int format_datetime(const idl_resolved_leaf_t *leaf,
                           uint32_t ticks_per_second,
                           char *value_out,
                           size_t value_out_size) {
    int64_t ticks;
    int64_t unix_seconds;
    char timestamp[CS_DATETIME_TEXT_SIZE];
    char *separator;
    int written;

    if (ticks_per_second == 0) {
        PRINTF("format_datetime: ticks_per_second is zero\n");
        return -1;
    }
    if (is_signed_int_kind(leaf->kind)) {
        if (read_leaf_i64(leaf, &ticks) != 0) {
            PRINTF("format_datetime: signed read failed\n");
            return -1;
        }
    } else {
        uint64_t unsigned_ticks;
        if (read_leaf_u64(leaf, &unsigned_ticks) != 0) {
            PRINTF("format_datetime: unsupported leaf kind %d\n", leaf->kind);
            return -1;
        }
        if (unsigned_ticks > (uint64_t) INT64_MAX) {
            PRINTF("format_datetime: unsigned value out of range\n");
            return -1;
        }
        ticks = (int64_t) unsigned_ticks;
    }
    unix_seconds = ticks / (int64_t) ticks_per_second;
    if (print_timestamp(unix_seconds, timestamp, sizeof(timestamp)) != 0) {
        PRINTF("format_datetime: print_timestamp failed\n");
        return -1;
    }
    // print_timestamp renders "YYYY-MM-DD hh:mm:ss"; split at its single space
    // to reassemble the ISO 8601 form with a 'T' separator and an explicit UTC
    // offset.
    separator = strchr(timestamp, ' ');
    if (separator == NULL) {
        PRINTF("format_datetime: missing date-time separator\n");
        return -1;
    }
    *separator = '\0';
    written = snprintf(value_out, value_out_size, "%sT%s+00:00", timestamp, separator + 1);
    if (written < 0 || (size_t) written >= value_out_size) {
        PRINTF("format_datetime: output does not fit\n");
        return -1;
    }
    PRINTF("format_datetime: rendered value=%s\n", value_out);
    return 0;
}

// PARAM_UNIT: a numeric value scaled by decimals with a symbol affixed.
static int format_unit(const idl_resolved_leaf_t *leaf,
                       const cs_format_unit_t *unit,
                       char *value_out,
                       size_t value_out_size) {
    int status;

    if (is_signed_int_kind(leaf->kind)) {
        int64_t signed_value;
        if (read_leaf_i64(leaf, &signed_value) != 0) {
            PRINTF("format_unit: signed read failed\n");
            return -1;
        }
        status = print_signed_token_amount(signed_value,
                                           NULL,
                                           unit->decimals,
                                           value_out,
                                           value_out_size);
    } else {
        uint64_t amount;
        if (read_leaf_u64(leaf, &amount) != 0) {
            PRINTF("format_unit: unsupported leaf kind %d\n", leaf->kind);
            return -1;
        }
        status = print_token_amount(amount, NULL, unit->decimals, value_out, value_out_size);
    }
    if (status != 0) {
        PRINTF("format_unit: amount print failed\n");
        return -1;
    }

    if (unit->symbol != NULL) {
        // value_out was sized for the number plus the symbol, so the symbol is placed over the
        // rendered number rather than into a buffer of its own.
        size_t number_len = strlen(value_out);  // counts the sign a negative value wrote
        size_t symbol_len = strlen(unit->symbol);
        // One separating space, and the NUL.
        if (number_len + 1 + symbol_len + 1 > value_out_size) {
            PRINTF("format_unit: output does not fit (%u)\n", (unsigned) value_out_size);
            return -1;
        }
        if (unit->prefix) {
            // Open a gap at the front for "symbol " without a second rendering of the number.
            memmove(value_out + symbol_len + 1, value_out, number_len + 1);
            memcpy(value_out, unit->symbol, symbol_len);
            value_out[symbol_len] = ' ';
        } else {
            value_out[number_len] = ' ';
            memcpy(value_out + number_len + 1, unit->symbol, symbol_len);
            value_out[number_len + 1 + symbol_len] = '\0';
        }
    }
    PRINTF("format_unit: rendered value=%s\n", value_out);
    return 0;
}

// Encode raw bytes according to the string encoding.
static int encode_string_bytes(uint8_t encoding,
                               const uint8_t *in,
                               size_t in_len,
                               char *out,
                               size_t out_size) {
    switch (encoding) {
        case CS_STRING_ENCODING_ASCII:
            return encode_text(in, in_len, true, out, out_size);

        case CS_STRING_ENCODING_UTF8:
            return encode_text(in, in_len, false, out, out_size);

        case CS_STRING_ENCODING_BASE58:
            if (encode_base58(in, in_len, out, out_size) < 0) {
                PRINTF("encode_string_bytes: base58 encode failed\n");
                return -1;
            }
            return (int) strlen(out);

        case CS_STRING_ENCODING_BASE64:
            return encode_base64(in, in_len, out, out_size);

        case CS_STRING_ENCODING_HEX:
            return encode_hex(in, in_len, out, out_size);

        default:
            PRINTF("encode_string_bytes: unsupported encoding %d\n", encoding);
            return -1;
    }
}

// Compute the [start, len) window over a sequence.
static int compute_string_slice(const cs_format_string_t *string,
                                size_t total_len,
                                size_t *start_out,
                                size_t *len_out) {
    if (string->slice_kind == CS_SLICE_KIND_BOUNDED) {
        size_t start = string->slice_start;
        size_t end = string->slice.bounded.end;
        if (end > total_len) {
            end = total_len;
        }
        if (end < start) {
            PRINTF(
                "compute_string_slice: bounded window [%u,%u) invalid "
                "for length %u\n",
                (unsigned) start,
                (unsigned) end,
                (unsigned) total_len);
            return -1;
        }
        *start_out = start;
        *len_out = end - start;
    } else if (string->slice_kind == CS_SLICE_KIND_SIZED) {
        size_t size = string->slice.sized.size;
        if (string->slice.sized.reversed) {
            if (size > total_len) {
                PRINTF(
                    "compute_string_slice: sized reversed size %u "
                    "exceeds length %u\n",
                    (unsigned) size,
                    (unsigned) total_len);
                return -1;
            }
            *start_out = total_len - size;
            *len_out = size;
        } else {
            size_t start = string->slice_start;
            if (start > total_len || size > total_len - start) {
                PRINTF(
                    "compute_string_slice: sized window start=%u "
                    "size=%u exceeds length %u\n",
                    (unsigned) start,
                    (unsigned) size,
                    (unsigned) total_len);
                return -1;
            }
            *start_out = start;
            *len_out = size;
        }
    } else {
        PRINTF("compute_string_slice: unsupported slice_kind %d\n", string->slice_kind);
        return -1;
    }
    return 0;
}

// Encode the whole leaf, then keep only the slice window. The caller sized value_out for the
// unsliced encoding, which is what makes the encode-then-shift possible in place: a window
// is never longer than the text it is cut from.
static int format_formatted_slice(const idl_resolved_leaf_t *leaf,
                                  const cs_format_string_t *string,
                                  char *value_out,
                                  size_t value_out_size) {
    int encoded_len = encode_string_bytes(string->encoding,
                                          leaf->value,
                                          leaf->value_size,
                                          value_out,
                                          value_out_size);
    if (encoded_len < 0) {
        PRINTF("format_formatted_slice: encode failed\n");
        return -1;
    }
    size_t start;
    size_t len;
    if (compute_string_slice(string, (size_t) encoded_len, &start, &len) != 0) {
        PRINTF("format_formatted_slice: slice computation failed\n");
        return -1;
    }
    PRINTF("format_formatted_slice: start=%u len=%u of encoded=%d\n",
           (unsigned) start,
           (unsigned) len,
           encoded_len);
    memmove(value_out, value_out + start, len);
    value_out[len] = '\0';
    return 0;
}

// Take the slice window over the raw bytes, then encode only that window.
static int format_source_slice(const idl_resolved_leaf_t *leaf,
                               const cs_format_string_t *string,
                               char *value_out,
                               size_t value_out_size) {
    size_t start;
    size_t len;
    if (compute_string_slice(string, leaf->value_size, &start, &len) != 0) {
        PRINTF("format_source_slice: slice computation failed\n");
        return -1;
    }
    PRINTF("format_source_slice: start=%u len=%u encoding=%d\n",
           (unsigned) start,
           (unsigned) len,
           string->encoding);
    if (encode_string_bytes(string->encoding, leaf->value + start, len, value_out, value_out_size) <
        0) {
        PRINTF("format_source_slice: encode failed\n");
        return -1;
    }
    return 0;
}

// PARAM_STRING: render leaf bytes through an encoding, optionally sliced.
static int format_string(const idl_resolved_leaf_t *leaf,
                         const cs_format_string_t *string,
                         char *value_out,
                         size_t value_out_size) {
    int status;
    if (!string->has_slice) {
        PRINTF("format_string: no slice, encoding %u bytes encoding=%d\n",
               (unsigned) leaf->value_size,
               string->encoding);
        status = 0;
        if (encode_string_bytes(string->encoding,
                                leaf->value,
                                leaf->value_size,
                                value_out,
                                value_out_size) < 0) {
            PRINTF("format_string: whole-value encode failed\n");
            status = -1;
        }
    } else if (string->slice_applies_to == CS_SLICE_APPLIES_TO_SOURCE) {
        status = format_source_slice(leaf, string, value_out, value_out_size);
    } else {
        status = format_formatted_slice(leaf, string, value_out, value_out_size);
    }
    if (status == 0) {
        PRINTF("format_string: rendered value=%s\n", value_out);
    }
    return status;
}

// Format an ARGUMENT_PATH field based on its param_type.
static int format_argument_field(const cs_display_field_t *field,
                                 const idl_resolved_leaf_t *leaf,
                                 const uint8_t *mint_pubkey,
                                 char *value_out,
                                 size_t value_out_size) {
    switch (field->argument.param_type) {
        case CS_PARAM_TYPE_RAW:
            return format_leaf(leaf, value_out, value_out_size);

        case CS_PARAM_TYPE_AMOUNT:
            return format_amount(leaf, &field->argument.format.amount, value_out, value_out_size);

        case CS_PARAM_TYPE_TOKEN_AMOUNT:
            return format_token_amount(leaf,
                                       &field->argument.format.token_amount,
                                       mint_pubkey,
                                       value_out,
                                       value_out_size);

        case CS_PARAM_TYPE_ENUM:
            return format_leaf(leaf, value_out, value_out_size);

        case CS_PARAM_TYPE_DATETIME:
            return format_datetime(leaf,
                                   field->argument.format.datetime.ticks_per_second,
                                   value_out,
                                   value_out_size);

        case CS_PARAM_TYPE_DURATION:
            return format_duration(leaf, value_out, value_out_size);

        case CS_PARAM_TYPE_UNIT:
            return format_unit(leaf, &field->argument.format.unit, value_out, value_out_size);

        case CS_PARAM_TYPE_ACCOUNT:
            return format_account_short_named(leaf, value_out, value_out_size);

        case CS_PARAM_TYPE_TRUSTED_NAME:
            return format_trusted_name(leaf,
                                       &field->argument.format.trusted_name,
                                       value_out,
                                       value_out_size);

        case CS_PARAM_TYPE_STRING:
            return format_string(leaf, &field->argument.format.string, value_out, value_out_size);

        default:
            PRINTF("format_argument_field: unsupported param_type %d\n",
                   field->argument.param_type);
            return -1;
    }
}

// Dispatch on the field's source.
static int format_field(const cs_display_field_t *field,
                        const idl_resolved_leaf_t *leaf,
                        const uint8_t *mint_pubkey,
                        char *value_out,
                        size_t value_out_size) {
    if (leaf->value == NULL || leaf->value_size == 0) {
        strlcpy(value_out, "<empty>", value_out_size);
        return 0;
    }

    switch (field->source) {
        case CS_VALUE_SOURCE_ARGUMENT_PATH:
            return format_argument_field(field, leaf, mint_pubkey, value_out, value_out_size);

        case CS_VALUE_SOURCE_ACCOUNT_PATH:
            return format_account_named(leaf, value_out, value_out_size);

        case CS_VALUE_SOURCE_CONSTANT:
            return format_leaf(leaf, value_out, value_out_size);

        default:
            PRINTF("format_field: unsupported source %d\n", field->source);
            return -1;
    }
}

// Find a resolved port whose account candidate resolved to `account_index`.
static const cs_resolved_port_t *find_port_by_account_index(
    const cs_instruction_template_t *template,
    const cs_resolved_port_t *resolved_ports,
    size_t resolved_port_count,
    uint8_t account_index) {
    const cs_resolved_port_t *match = NULL;
    bool match_is_output = false;
    for (size_t p = 0; p < resolved_port_count; p++) {
        if (resolved_ports[p].excluded || !resolved_ports[p].resolved ||
            resolved_ports[p].account_index != account_index) {
            continue;
        }
        bool is_output = (template->ports[p].direction == CS_PORT_DIRECTION_OUTPUT);
        if (match == NULL || is_output || !match_is_output) {
            match = &resolved_ports[p];
            match_is_output = is_output;
        }
    }
    if (match != NULL) {
        PRINTF(
            "find_port_by_account_index: slot %u matched, "
            "is_output=%d\n",
            (unsigned) account_index,
            (int) match_is_output);
    }
    return match;
}

// Find a resolved NUMERIC-amount port whose amount reads the same
// ARGUMENT_PATH.
static const cs_resolved_port_t *find_port_by_argument_path(
    const cs_instruction_template_t *template,
    const cs_resolved_port_t *resolved_ports,
    size_t resolved_port_count,
    const uint8_t *path,
    uint8_t path_size) {
    const cs_resolved_port_t *match = NULL;
    for (size_t p = 0; p < resolved_port_count && match == NULL; p++) {
        if (resolved_ports[p].excluded || !resolved_ports[p].resolved ||
            resolved_ports[p].amount_kind != CS_AMOUNT_KIND_NUMERIC ||
            resolved_ports[p].amount_le == NULL || !template->ports[p].amount.has_value ||
            template->ports[p].amount.value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
            continue;
        }
        if (template->ports[p].amount.value.payload_size == path_size &&
            memcmp(template->ports[p].amount.value.payload, path, path_size) == 0) {
            match = &resolved_ports[p];
            PRINTF(
                "find_port_by_argument_path: matched port %u "
                "path_size=%u\n",
                (unsigned) p,
                (unsigned) path_size);
        }
    }
    return match;
}

// Override a field's leaf and mint from a value-flow port before formatting.
static void apply_port_overrides(const cs_instruction_result_t *instruction,
                                 const cs_display_field_t *display_field,
                                 idl_resolved_leaf_t *override_leaf,
                                 const idl_resolved_leaf_t **leaf,
                                 const uint8_t **mint) {
    if (display_field->source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        const cs_resolved_port_t *port = find_port_by_account_index(
            instruction->template,
            instruction->resolved_ports,
            instruction->resolved_port_count,
            display_field->account.index);
        if (port != NULL) {
            memcpy(override_leaf, *leaf, sizeof(*override_leaf));
            override_leaf->value = port->account;
            override_leaf->value_size = PUBKEY_SIZE;
            *leaf = override_leaf;
            PRINTF(
                "apply_port_overrides: account field overridden by "
                "port\n");
        }
    } else if (display_field->source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
        if (display_field->argument.param_type == CS_PARAM_TYPE_AMOUNT ||
            display_field->argument.param_type == CS_PARAM_TYPE_TOKEN_AMOUNT) {
            const cs_resolved_port_t *port = find_port_by_argument_path(
                instruction->template,
                instruction->resolved_ports,
                instruction->resolved_port_count,
                display_field->argument.path,
                display_field->argument.path_size);
            if (port != NULL) {
                memcpy(override_leaf, *leaf, sizeof(*override_leaf));
                override_leaf->value = port->amount_le;
                override_leaf->value_size = port->amount_size;
                override_leaf->kind = port->amount_leaf_kind;
                *leaf = override_leaf;
                PRINTF(
                    "apply_port_overrides: amount field overridden by "
                    "port\n");
            }
        }
        if (display_field->argument.param_type == CS_PARAM_TYPE_TOKEN_AMOUNT &&
            display_field->argument.format.token_amount.mint_source ==
                CS_TOKEN_MINT_ACCOUNT_INDEX) {
            const cs_resolved_port_t *port = find_port_by_account_index(
                instruction->template,
                instruction->resolved_ports,
                instruction->resolved_port_count,
                display_field->argument.format.token_amount.ref.account_index);
            if (port != NULL && port->mint != NULL) {
                *mint = port->mint;
                PRINTF(
                    "apply_port_overrides: token mint overridden by "
                    "port\n");
            }
        }
    }
}

static bool is_native_program(const uint8_t program_id[PUBKEY_SIZE]) {
    if (memcmp(program_id, &system_program_id, PUBKEY_SIZE) == 0) {
        return true;
    } else if (memcmp(program_id, &stake_program_id, PUBKEY_SIZE) == 0) {
        return true;
    } else if (memcmp(program_id, &vote_program_id, PUBKEY_SIZE) == 0) {
        return true;
    } else if (memcmp(program_id, &spl_token_program_id, PUBKEY_SIZE) == 0) {
        return true;
    } else if (memcmp(program_id, &spl_token2022_program_id, PUBKEY_SIZE) == 0) {
        return true;
    } else if (memcmp(program_id, &spl_associated_token_account_program_id, PUBKEY_SIZE) == 0) {
        return true;
    } else if (memcmp(program_id, &compute_budget_program_id, PUBKEY_SIZE) == 0) {
        return true;
    }
    PRINTF("is_native_program: program is not native\n");
    return false;
}

// Populate an instruction's intent and optional program fields.
static int render_instruction_header(cs_display_instruction_t *display_instruction,
                                     const cs_instruction_result_t *instruction) {
    // The merge engine drops hidden instructions, so one arriving here is a sequencing bug.
    if (cs_instruction_template_is_hidden(instruction->template)) {
        PRINTF("render_instruction_header: hidden instruction reached the renderer\n");
        return -1;
    }
    display_instruction->intent = duplicate_string(instruction->template->operation_type);
    if (display_instruction->intent == NULL) {
        PRINTF("render_instruction_header: intent allocation failed\n");
        return -1;
    }

    // Program field: skip for native programs
    if (!is_native_program(instruction->template->program_id)) {
        if (instruction->template->program_name != NULL &&
            instruction->template->program_name[0] != '\0') {
            display_instruction->program = duplicate_string(instruction->template->program_name);
        } else {
            char address[BASE58_PUBKEY_LENGTH];
            if (encode_base58(instruction->template->program_id,
                              PUBKEY_SIZE,
                              address,
                              sizeof(address)) < 0) {
                PRINTF(
                    "render_instruction_header: base58 encode "
                    "program_id failed\n");
                return -1;
            }
            display_instruction->program = duplicate_string(address);
        }
        if (display_instruction->program == NULL) {
            PRINTF("render_instruction_header: program allocation failed\n");
            return -1;
        }
    }

    PRINTF("render_instruction_header: intent=%s program=%s\n",
           display_instruction->intent,
           display_instruction->program != NULL ? display_instruction->program : "(native)");
    return 0;
}

// Bytes an ARGUMENT_PATH field's rendering can need, judged from its formatter and the
// value it will format. Returns 0 for a formatter that cannot render this field at all.
static size_t argument_render_capacity(const cs_display_field_t *field,
                                       const idl_resolved_leaf_t *leaf,
                                       const uint8_t *mint_pubkey) {
    switch (field->argument.param_type) {
        case CS_PARAM_TYPE_RAW:
        case CS_PARAM_TYPE_ENUM:
            return leaf_render_capacity(leaf);

        case CS_PARAM_TYPE_AMOUNT:
            return amount_render_capacity(field->argument.format.amount.decimals,
                                          NULL,
                                          field->argument.format.amount.max_label);

        case CS_PARAM_TYPE_TOKEN_AMOUNT: {
            // Resolved through the same helper format_token_amount uses, so the buffer and
            // the rendering cannot disagree about the ticker or the scale.
            const char *symbol;
            uint8_t magnitude;
            if (resolve_token_display(&field->argument.format.token_amount,
                                      mint_pubkey,
                                      &symbol,
                                      &magnitude) != 0) {
                return 0;
            }
            return amount_render_capacity(magnitude,
                                          symbol,
                                          field->argument.format.token_amount.max_label);
        }

        case CS_PARAM_TYPE_DATETIME:
            return CS_DATETIME_TEXT_SIZE;

        case CS_PARAM_TYPE_DURATION:
            return CS_DURATION_TEXT_SIZE;

        case CS_PARAM_TYPE_UNIT: {
            size_t needed = amount_render_capacity(field->argument.format.unit.decimals,
                                                   field->argument.format.unit.symbol,
                                                   NULL);
            if (is_signed_int_kind(leaf->kind)) {
                // A negative value prints a minus ahead of the number.
                needed += 1;
            }
            return needed;
        }

        case CS_PARAM_TYPE_ACCOUNT:
        case CS_PARAM_TYPE_TRUSTED_NAME:
            // Either the cached trusted name or the short base58 form.
            return larger_capacity(trusted_name_capacity(leaf), BASE58_PUBKEY_SHORT);

        case CS_PARAM_TYPE_STRING:
            return string_render_capacity(&field->argument.format.string, leaf);

        default:
            PRINTF("argument_render_capacity: unsupported param_type %d\n",
                   field->argument.param_type);
            return 0;
    }
}

// Bytes this field's rendering can need, so the value buffer is sized to the field rather
// than to a ceiling every field shares. Returns 0 when the field cannot be rendered.
static size_t field_render_capacity(const cs_display_field_t *field,
                                    const idl_resolved_leaf_t *leaf,
                                    const uint8_t *mint_pubkey) {
    // format_field answers "<empty>" for a valueless leaf whatever the source says.
    if (leaf->value == NULL || leaf->value_size == 0) {
        return CS_EMPTY_TEXT_SIZE;
    }
    switch (field->source) {
        case CS_VALUE_SOURCE_ARGUMENT_PATH:
            return argument_render_capacity(field, leaf, mint_pubkey);

        case CS_VALUE_SOURCE_ACCOUNT_PATH:
            // Either the cached trusted name or the full base58 address.
            return larger_capacity(trusted_name_capacity(leaf), base58_capacity(PUBKEY_SIZE));

        case CS_VALUE_SOURCE_CONSTANT:
            return leaf_render_capacity(leaf);

        default:
            PRINTF("field_render_capacity: unsupported source %d\n", field->source);
            return 0;
    }
}

// Write the field's label: the descriptor's NAME, or a positional fallback when it carries
// none. Returns 0 on success, -1 when the label cannot be allocated.
static int render_field_title(cs_rendered_field_t *rendered,
                              const cs_display_field_t *field,
                              size_t field_index) {
    if (field->name != NULL && field->name[0] != '\0') {
        rendered->title = duplicate_string(field->name);
    } else {
        char fallback[sizeof("Field ") + CS_UINT64_TEXT_SIZE];
        snprintf(fallback, sizeof(fallback), "Field %u", (unsigned) (field_index + 1));
        rendered->title = duplicate_string(fallback);
    }
    if (rendered->title == NULL) {
        PRINTF("render_field_title: title allocation failed field=%u\n", (unsigned) field_index);
        return -1;
    }
    return 0;
}

// Render one resolved field into the instruction's field list.
static int render_field(cs_display_instruction_t *display_instruction,
                        const cs_instruction_result_t *instruction,
                        size_t field_index) {
    cs_rendered_field_t *rendered = append_instruction_field(display_instruction);
    if (rendered == NULL) {
        PRINTF("render_field: field append failed field=%u\n", (unsigned) field_index);
        return -1;
    }

    if (render_field_title(rendered,
                           &instruction->template->display_fields[field_index],
                           field_index) != 0) {
        return -1;
    }

    const idl_resolved_leaf_t *leaf = &instruction->resolved[field_index];
    const uint8_t *mint = instruction->field_mint[field_index];
    idl_resolved_leaf_t override_leaf;
    apply_port_overrides(instruction,
                         &instruction->template->display_fields[field_index],
                         &override_leaf,
                         &leaf,
                         &mint);

    // Sizing from the field's own formatter and value is what lets a long string, a wide
    // scale or a long trusted name render instead of being refused for overflowing a
    // shared buffer.
    size_t capacity = field_render_capacity(&instruction->template->display_fields[field_index],
                                            leaf,
                                            mint);
    if (capacity == 0) {
        PRINTF("render_field: field=%u cannot be rendered\n", (unsigned) field_index);
        return -1;
    }
    if (!APP_MEM_CALLOC((void **) &rendered->value, capacity)) {
        PRINTF("render_field: value buffer allocation failed field=%u size=%u\n",
               (unsigned) field_index,
               (unsigned) capacity);
        return -1;
    }

    if (format_field(&instruction->template->display_fields[field_index],
                     leaf,
                     mint,
                     rendered->value,
                     capacity) != 0) {
        PRINTF("render_field: format failed field=%u\n", (unsigned) field_index);
        APP_MEM_FREE_AND_NULL((void **) &rendered->value);
        return -1;
    }
    rendered->value = shrink_render_buffer(rendered->value);
    if (rendered->value == NULL) {
        return -1;
    }
    return 0;
}

int cs_display_renderer_run(const cs_instruction_result_t *walked_instructions,
                            size_t walked_instructions_count,
                            const bool *survivors) {
    if (G_cs_display_renderer.instruction_count != 0 ||
        G_cs_display_renderer.instructions != NULL) {
        PRINTF(
            "cs_display_renderer_run: renderer already populated, "
            "refusing to run\n");
        return -1;
    }

    PRINTF("cs_display_renderer_run: %u instructions\n", (unsigned) walked_instructions_count);

    for (size_t ix = 0; ix < walked_instructions_count; ix++) {
        if (!survivors[ix]) {
            continue;
        }
        PRINTF("cs_display_renderer_run: rendering instruction ix=%u\n", (unsigned) ix);

        cs_display_instruction_t *display_instruction = append_instruction();
        if (display_instruction == NULL) {
            PRINTF(
                "cs_display_renderer_run: instruction append failed "
                "ix=%u\n",
                (unsigned) ix);
            return -1;
        }

        if (render_instruction_header(display_instruction, &walked_instructions[ix]) != 0) {
            PRINTF(
                "cs_display_renderer_run: header render failed "
                "ix=%u\n",
                (unsigned) ix);
            return -1;
        }

        for (size_t field = 0; field < walked_instructions[ix].resolved_count; field++) {
            // A path that descends through an absent OPTION reaches no leaf, which is the
            // option being absent from this instance rather than anything wrong: the field
            // does not exist here and is left out. A path that no instance could reach is a
            // descriptor inconsistent with its own type pool, and belongs to ingest.
            if (walked_instructions[ix].resolved[field].value == NULL) {
                PRINTF("cs_display_renderer_run: field=%u of ix=%u absent, not displayed\n",
                       (unsigned) field,
                       (unsigned) ix);
                continue;
            }
            if (render_field(display_instruction, &walked_instructions[ix], field) != 0) {
                PRINTF(
                    "cs_display_renderer_run: field render failed "
                    "ix=%u field=%u\n",
                    (unsigned) ix,
                    (unsigned) field);
                return -1;
            }
        }
    }

    PRINTF("cs_display_renderer_run: produced %u instructions\n",
           (unsigned) G_cs_display_renderer.instruction_count);
    return 0;
}

int cs_display_renderer_append_transaction_field(const char *title, const char *value) {
    if (title == NULL || value == NULL) {
        PRINTF(
            "cs_display_renderer_append_transaction_field: NULL title "
            "or value\n");
        return -1;
    }
    cs_rendered_field_t *field = append_transaction_field();
    if (field == NULL) {
        PRINTF(
            "cs_display_renderer_append_transaction_field: append "
            "failed\n");
        return -1;
    }
    field->title = duplicate_string(title);
    if (field->title == NULL) {
        return -1;
    }
    field->value = duplicate_string(value);
    if (field->value == NULL) {
        return -1;
    }
    PRINTF("cs_display_renderer_append_transaction_field: %s = %s\n", title, value);
    return 0;
}

size_t cs_display_renderer_instruction_count(void) {
    return G_cs_display_renderer.instruction_count;
}

const cs_display_instruction_t *cs_display_renderer_instruction(size_t index) {
    if (index >= G_cs_display_renderer.instruction_count) {
        PRINTF("cs_display_renderer_instruction: index %u out of range\n", (unsigned) index);
        return NULL;
    }
    return &G_cs_display_renderer.instructions[index];
}

const cs_display_transaction_fields_t *cs_display_renderer_transaction_fields(void) {
    return &G_cs_display_renderer.transaction_fields;
}

// Count flat elements for one instruction: intent + optional program + fields.
static size_t instruction_flat_count(const cs_display_instruction_t *instruction) {
    // "Instruction intent" field is always present
    size_t count = 1;
    if (instruction->program != NULL) {
        count++;
    }
    count += instruction->field_count;
    return count;
}

size_t cs_display_renderer_flat_count(void) {
    size_t total = 0;
    bool multi = (G_cs_display_renderer.instruction_count > 1);

    for (size_t i = 0; i < G_cs_display_renderer.instruction_count; i++) {
        if (multi) {
            // Separator screen per instruction
            total++;
        }
        total += instruction_flat_count(&G_cs_display_renderer.instructions[i]);
    }

    // Transaction-level fields (fees)
    if (G_cs_display_renderer.transaction_fields.field_count > 0) {
        if (multi) {
            // Separator screen before fees
            total++;
        }
        total += G_cs_display_renderer.transaction_fields.field_count;
    }

    PRINTF("cs_display_renderer_flat_count: %u\n", (unsigned) total);
    return total;
}

// Translate a flat NBGL index into a display element with layout flags.
// Layout for multi-instruction:
//   [separator] [intent] [program?] [field0..N] ... [fee separator] [fee fields]
// Layout for single instruction:
//   [intent] [program?] [field0..N] [fee fields]
int cs_display_renderer_flat_element(size_t index, cs_display_flat_element_t *out) {
    explicit_bzero(out, sizeof(*out));
    size_t remaining = index;
    bool multi = (G_cs_display_renderer.instruction_count > 1);

    // Walk instruction groups
    for (size_t i = 0; i < G_cs_display_renderer.instruction_count; i++) {
        const cs_display_instruction_t *instruction = &G_cs_display_renderer.instructions[i];

        // Multi-instruction separator
        if (multi) {
            if (remaining == 0) {
                out->title = "Review instruction";
                // Format "X of Y" into a static buffer: the NBGL callback
                // copies the result, so a single static buffer is safe.
                static char separator_value[16];
                snprintf(separator_value,
                         sizeof(separator_value),
                         "%u of %u",
                         (unsigned) (i + 1),
                         (unsigned) G_cs_display_renderer.instruction_count);
                out->value = separator_value;
                out->centered_info = true;
                if (i > 0) {
                    out->force_page_start = true;
                }
                return 0;
            }
            remaining--;
        }

        // Intent field
        if (remaining == 0) {
            out->title = "Instruction intent";
            out->value = instruction->intent;
            return 0;
        }
        remaining--;

        // Program field (optional)
        if (instruction->program != NULL) {
            if (remaining == 0) {
                out->title = "Program";
                out->value = instruction->program;
                return 0;
            }
            remaining--;
        }

        // Instruction fields
        if (remaining < instruction->field_count) {
            out->title = instruction->fields[remaining].title;
            out->value = instruction->fields[remaining].value;
            return 0;
        }
        remaining -= instruction->field_count;
    }

    // Transaction-level fields (fees)
    const cs_display_transaction_fields_t *txn_fields = &G_cs_display_renderer.transaction_fields;
    if (txn_fields->field_count > 0) {
        // Fee separator in multi-instruction layout
        if (multi) {
            if (remaining == 0) {
                out->title = "Review fees";
                out->value = "";
                out->centered_info = true;
                out->force_page_start = true;
                return 0;
            }
            remaining--;
        }

        if (remaining < txn_fields->field_count) {
            out->title = txn_fields->fields[remaining].title;
            out->value = txn_fields->fields[remaining].value;
            return 0;
        }
    }

    PRINTF("cs_display_renderer_flat_element: index %u out of range\n", (unsigned) index);
    return -1;
}
