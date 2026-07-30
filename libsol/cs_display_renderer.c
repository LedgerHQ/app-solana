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

#define CS_DISPLAY_ELEMENTS_CAP_STEP 8

typedef struct cs_display_renderer_table_s {
    cs_display_element_t **elements;  // heap pointer array, grown on demand
    size_t capacity; // Grows in CS_DISPLAY_ELEMENTS_CAP_STEP steps
    size_t count;
} cs_display_renderer_table_t;

static cs_display_renderer_table_t G_cs_display_renderer;

// Max size for formatting a single title or value before it is shrunk to its string length
#define CS_RENDER_BUFFER_SIZE 128

// Ensure the pointer array can hold one more element, growing it by one step on
// demand. The first allocation uses CALLOC; later growth reallocates, so realloc
// is never handed a NULL base.
static int ensure_element_capacity(void) {
    if (G_cs_display_renderer.count < G_cs_display_renderer.capacity) {
        return 0;
    }
    if (G_cs_display_renderer.capacity == 0) {
        cs_display_element_t **initial = NULL;
        if (!APP_MEM_CALLOC((void **) &initial, CS_DISPLAY_ELEMENTS_CAP_STEP * sizeof(*initial))) {
            PRINTF("ensure_element_capacity: element table allocation failed\n");
            return -1;
        }
        G_cs_display_renderer.elements = initial;
        G_cs_display_renderer.capacity = CS_DISPLAY_ELEMENTS_CAP_STEP;
    } else {
        size_t new_capacity = G_cs_display_renderer.capacity + CS_DISPLAY_ELEMENTS_CAP_STEP;
        cs_display_element_t **grown = APP_MEM_REALLOC(G_cs_display_renderer.elements,
                                                       new_capacity * sizeof(*grown));
        if (grown == NULL) {
            PRINTF("ensure_element_capacity: element table growth failed\n");
            return -1;
        }
        G_cs_display_renderer.elements = grown;
        G_cs_display_renderer.capacity = new_capacity;
    }
    return 0;
}

// Allocate, register and return the next display element, or NULL on allocation
// failure (out of pool).
static cs_display_element_t *append_element(void) {
    if (ensure_element_capacity() != 0) {
        return NULL;
    }
    cs_display_element_t *element = NULL;
    if (!APP_MEM_CALLOC((void **) &element, sizeof(*element))) {
        PRINTF("append_element: element allocation failed\n");
        return NULL;
    }
    G_cs_display_renderer.elements[G_cs_display_renderer.count] = element;
    G_cs_display_renderer.count++;
    return element;
}

// Release every element and the pointer array, returning to the empty state.
// Each element's strings are freed before the element struct that points at them.
void cs_display_renderer_reset(void) {
    for (size_t i = 0; i < G_cs_display_renderer.count; i++) {
        cs_display_element_t *element = G_cs_display_renderer.elements[i];
        if (element != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &element->title);
            APP_MEM_FREE_AND_NULL((void **) &element->value);
        }
        APP_MEM_FREE_AND_NULL((void **) &G_cs_display_renderer.elements[i]);
    }
    if (G_cs_display_renderer.elements != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &G_cs_display_renderer.elements);
    }
    G_cs_display_renderer.capacity = 0;
    G_cs_display_renderer.count = 0;
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
            print_u64((uint64_t) (leaf->value[0] | (leaf->value[1] << 8) | (leaf->value[2] << 16) |
                                  (leaf->value[3] << 24)),
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
                PRINTF("format_leaf: string value (%u) does not fit buffer (%u)\n",
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
// Only the unsigned kinds read_leaf_u64 accepts can reach an amount formatter.
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

// Render a MAX_LABEL sentinel. Refuses rather than truncate: a shortened label
// would misrepresent the amount being signed. Returns 0, -1 when it does not fit.
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

// PARAM_TOKEN_AMOUNT: renders a raw amount with the ticker and decimal scaling
// implied by the descriptor's mint_source. A resolved mint reference is looked
// up in the registry; NATIVE and NONE need no lookup.
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
        int magnitude;

        switch (fmt->mint_source) {
            case CS_TOKEN_MINT_NATIVE:
                PRINTF("format_token_amount: native SOL\n");
                symbol = "SOL";
                magnitude = SOL_DECIMALS;
                break;

            case CS_TOKEN_MINT_NONE:
                symbol = NULL;
                magnitude = 0;
                if (fmt->has_decimals) {
                    magnitude = fmt->decimals;
                }
                PRINTF("format_token_amount: no mint, bare render decimals=%d\n", magnitude);
                break;

            case CS_TOKEN_MINT_ACCOUNT_INDEX:
            case CS_TOKEN_MINT_CONSTANT:
                // finalize resolves referenced mints; a NULL here is an upstream bug.
                if (mint_pubkey == NULL) {
                    PRINTF("format_token_amount: mint_source %d has no resolved mint\n",
                           fmt->mint_source);
                    return -1;
                }
                symbol = get_token_symbol(mint_pubkey, false);
                magnitude = get_token_magnitude(mint_pubkey, false);
                PRINTF("format_token_amount: registry symbol=%s magnitude=%d\n",
                       symbol == NULL ? "(none)" : symbol,
                       magnitude);
                // An explicit override wins over the registry magnitude.
                if (fmt->has_decimals) {
                    magnitude = fmt->decimals;
                    PRINTF("format_token_amount: decimals overridden to %d\n", magnitude);
                }
                // Keep the amount visible when the mint is unknown to the registry.
                if (magnitude < 0) {
                    PRINTF("format_token_amount: mint unknown, ticker=???\n");
                    symbol = "???";
                    magnitude = 0;
                }
                break;

            default:
                PRINTF("format_token_amount: unknown mint_source %d\n", fmt->mint_source);
                return -1;
        }

        status = print_token_amount(amount, symbol, (uint8_t) magnitude, value_out, value_out_size);
        if (status != 0) {
            PRINTF("format_token_amount: print_token_amount failed\n");
            status = -1;
        }
    }
    return status;
}

// Write the cached name for a 32-byte address leaf when its type satisfies the
// allow-list mask (zero = no constraint). Returns false on a miss or a
// disallowed type, leaving the caller to render the raw address.
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
// base58 short form (leading and trailing chars separated by "..").
static int format_account_short(const idl_resolved_leaf_t *leaf,
                                char *value_out,
                                size_t value_out_size) {
    char full[BASE58_PUBKEY_LENGTH];

    if (leaf->value_size < PUBKEY_SIZE) {
        PRINTF("format_account_short: value too short (%u < 32)\n", (unsigned) leaf->value_size);
        return -1;
    }
    // Encode the full address, then abbreviate it below.
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
    // Bound print_summary's length to the short form so a full address that
    // would otherwise fit the value buffer is still abbreviated.
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
        PRINTF("format_trusted_name: no permitted name, rendering short address\n");
        return format_account_short(leaf, value_out, value_out_size);
    }
}

// ACCOUNT_PATH: cached trusted name, else the full base58 address. Labels a
// plain account such as a mint; no allow-list applies.
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

    // A duration may be encoded as a signed integer (e.g. i64): read those
    // sign-extended and refuse a negative count. Unsigned kinds read directly.
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
    // Split the total seconds into H:MM:SS components.
    hours = total_seconds / 3600;
    minutes = (uint32_t) ((total_seconds % 3600) / 60);
    seconds = (uint32_t) (total_seconds % 60);
    // Hours are unbounded, so render them through print_u64 rather than %02u.
    if (print_u64(hours, hours_str, sizeof(hours_str)) != 0) {
        PRINTF("format_duration: print_u64 failed\n");
        return -1;
    }
    // Left-pad a single-digit hour to two digits so the whole field reads as the
    // zero-padded HH:MM:SS form; a multi-digit hour count is already wide enough.
    const char *hours_pad = "";
    if (strlen(hours_str) < 2) {
        hours_pad = "0";
    }
    // Refuse rather than truncate: snprintf returns the would-be length on overflow.
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

// PARAM_DATETIME: a numeric value of ticks rendered as the ISO 8601 UTC form
// "YYYY-MM-DDThh:mm:ss+00:00". A Unix timestamp is signed (Solana's UnixTimestamp
// is i64), so signed leaves are read sign-extended and unsigned leaves
// zero-extended, both into an i64.
static int format_datetime(const idl_resolved_leaf_t *leaf,
                           uint32_t ticks_per_second,
                           char *value_out,
                           size_t value_out_size) {
    int64_t ticks;
    int64_t unix_seconds;
    char timestamp[CS_RENDER_BUFFER_SIZE];
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
        // An unsigned tick count above INT64_MAX has no signed timestamp.
        if (unsigned_ticks > (uint64_t) INT64_MAX) {
            PRINTF("format_datetime: unsigned value out of range\n");
            return -1;
        }
        ticks = (int64_t) unsigned_ticks;
    }
    // Scale ticks down to Unix epoch seconds.
    unix_seconds = ticks / (int64_t) ticks_per_second;
    if (print_timestamp(unix_seconds, timestamp, sizeof(timestamp)) != 0) {
        PRINTF("format_datetime: print_timestamp failed\n");
        return -1;
    }
    // print_timestamp renders "YYYY-MM-DD hh:mm:ss"; split at its single space to
    // reassemble the ISO 8601 form with a 'T' separator and an explicit UTC offset.
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

// PARAM_UNIT: a numeric value scaled by decimals with a symbol affixed either
// before (prefix) or after the formatted number.
static int format_unit(const idl_resolved_leaf_t *leaf,
                       const cs_format_unit_t *unit,
                       char *value_out,
                       size_t value_out_size) {
    uint64_t amount;
    char number[CS_RENDER_BUFFER_SIZE];
    int written;

    if (read_leaf_u64(leaf, &amount) != 0) {
        PRINTF("format_unit: unsupported leaf kind %d\n", leaf->kind);
        return -1;
    }
    if (print_token_amount(amount, NULL, unit->decimals, number, sizeof(number)) != 0) {
        PRINTF("format_unit: print_token_amount failed\n");
        return -1;
    }
    // Affix the symbol before or after the scaled number, separated by a space.
    // A field with no symbol renders the bare number with no dangling separator.
    const char *symbol = "";
    const char *separator = "";
    if (unit->symbol != NULL) {
        symbol = unit->symbol;
        separator = " ";
    }
    if (unit->prefix) {
        written = snprintf(value_out, value_out_size, "%s%s%s", symbol, separator, number);
    } else {
        written = snprintf(value_out, value_out_size, "%s%s%s", number, separator, symbol);
    }
    if (written < 0 || (size_t) written >= value_out_size) {
        PRINTF("format_unit: output does not fit\n");
        return -1;
    }
    PRINTF("format_unit: rendered value=%s\n", value_out);
    return 0;
}

// Encode raw bytes according to the string encoding. Returns encoded length or -1.
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

// Compute the [start, len) window over a sequence of total_len units per the
// slice descriptor. Returns 0 on success, -1 on an inconsistent window.
static int compute_string_slice(const cs_format_string_t *string,
                                size_t total_len,
                                size_t *start_out,
                                size_t *len_out) {
    if (string->slice_kind == CS_SLICE_KIND_BOUNDED) {
        size_t start = string->slice_start;
        size_t end = string->slice.bounded.end;
        // SLICE_END defaults to (and is capped at) the value length by spec.
        if (end > total_len) {
            end = total_len;
        }
        // A start past the (capped) end is a mismatch: refuse, never clamp.
        if (end < start) {
            PRINTF("compute_string_slice: bounded window [%u,%u) invalid for length %u\n",
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
            // Trailing window: refuse if the value has fewer units than requested.
            if (size > total_len) {
                PRINTF("compute_string_slice: sized reversed size %u exceeds length %u\n",
                       (unsigned) size,
                       (unsigned) total_len);
                return -1;
            }
            *start_out = total_len - size;
            *len_out = size;
        } else {
            // Forward window: refuse if [start, start+size) runs past the value.
            size_t start = string->slice_start;
            if (start > total_len || size > total_len - start) {
                PRINTF("compute_string_slice: sized window start=%u size=%u exceeds length %u\n",
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

// PARAM_STRING: render leaf bytes through an encoding, optionally slicing either
// the source bytes (before encoding) or the formatted string (after encoding).
static int format_string(const idl_resolved_leaf_t *leaf,
                         const cs_format_string_t *string,
                         char *value_out,
                         size_t value_out_size) {
    if (!string->has_slice) {
        // Whole value: encode the leaf directly into the output buffer.
        PRINTF("format_string: no slice, encoding %u bytes encoding=%d\n",
               (unsigned) leaf->value_size,
               string->encoding);
        if (encode_string_bytes(string->encoding,
                                leaf->value,
                                leaf->value_size,
                                value_out,
                                value_out_size) < 0) {
            PRINTF("format_string: whole-value encode failed\n");
            return -1;
        }
    } else if (string->slice_applies_to == CS_SLICE_APPLIES_TO_SOURCE) {
        // Slice the raw source bytes first, then encode the window.
        size_t start;
        size_t len;
        if (compute_string_slice(string, leaf->value_size, &start, &len) != 0) {
            PRINTF("format_string: source slice computation failed\n");
            return -1;
        }
        PRINTF("format_string: source slice start=%u len=%u encoding=%d\n",
               (unsigned) start,
               (unsigned) len,
               string->encoding);
        if (encode_string_bytes(string->encoding,
                                leaf->value + start,
                                len,
                                value_out,
                                value_out_size) < 0) {
            PRINTF("format_string: source-slice encode failed\n");
            return -1;
        }
    } else {
        // Encode the whole value into scratch, then slice the formatted string.
        char encoded[CS_RENDER_BUFFER_SIZE];
        int encoded_len = encode_string_bytes(string->encoding,
                                              leaf->value,
                                              leaf->value_size,
                                              encoded,
                                              sizeof(encoded));
        if (encoded_len < 0) {
            PRINTF("format_string: formatted-slice encode failed\n");
            return -1;
        }
        // Compute the window over the encoded string.
        size_t start;
        size_t len;
        if (compute_string_slice(string, (size_t) encoded_len, &start, &len) != 0) {
            PRINTF("format_string: formatted slice computation failed\n");
            return -1;
        }
        PRINTF("format_string: formatted slice start=%u len=%u of encoded=%d\n",
               (unsigned) start,
               (unsigned) len,
               encoded_len);
        // Refuse rather than truncate a window that overflows the output.
        if (len + 1 > value_out_size) {
            PRINTF("format_string: sliced value does not fit (%u)\n", (unsigned) len);
            return -1;
        }
        // Copy the window out and NUL-terminate.
        memcpy(value_out, encoded + start, len);
        value_out[len] = '\0';
    }
    PRINTF("format_string: rendered value=%s\n", value_out);
    return 0;
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
            // The walker resolved the enum leaf to its variant name; render it.
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

// Dispatch on the field's source: ARGUMENT_PATH uses param_type, ACCOUNT_PATH
// renders an address (or its trusted name), CONSTANT uses format_leaf.
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

// Find a resolved port whose account candidate resolved to `account_index`, so
// its (possibly merged) value overrides a field referencing the same account.
// Returns NULL when no port covers the slot.
static const cs_resolved_port_t *find_port_by_account_index(const cs_instruction_template_t *template,
                                                            const cs_resolved_port_t *resolved_ports,
                                                            size_t resolved_port_count,
                                                            uint8_t account_index) {
    const cs_resolved_port_t *match = NULL;
    bool match_is_output = false;
    for (size_t p = 0; p < resolved_port_count; p++) {
        // An ACTIVE_WHEN-excluded port overrides nothing, as if never declared.
        if (resolved_ports[p].excluded || !resolved_ports[p].resolved ||
            resolved_ports[p].account_index != account_index) {
            continue;
        }
        // Output ports win over input ports; within a direction the later port wins.
        // A transformer touches one account as both input and output, and the output
        // endpoint is the one a field must display.
        bool is_output = (template->ports[p].direction == CS_PORT_DIRECTION_OUTPUT);
        if (match == NULL || is_output || !match_is_output) {
            match = &resolved_ports[p];
            match_is_output = is_output;
        }
    }
    if (match != NULL) {
        PRINTF("find_port_by_account_index: slot %u matched, is_output=%d\n",
               (unsigned) account_index,
               (int) match_is_output);
    }
    return match;
}

// Find a resolved NUMERIC-amount port whose amount reads the same ARGUMENT_PATH
// as `path`, so its amount overrides a field reading that argument.
static const cs_resolved_port_t *find_port_by_argument_path(const cs_instruction_template_t *template,
                                                            const cs_resolved_port_t *resolved_ports,
                                                            size_t resolved_port_count,
                                                            const uint8_t *path,
                                                            uint8_t path_size) {
    const cs_resolved_port_t *match = NULL;
    for (size_t p = 0; p < resolved_port_count && match == NULL; p++) {
        // An ACTIVE_WHEN-excluded port overrides nothing, as if never declared.
        if (resolved_ports[p].excluded || !resolved_ports[p].resolved ||
            resolved_ports[p].amount_kind != CS_AMOUNT_KIND_NUMERIC ||
            resolved_ports[p].amount_le == NULL || !template->ports[p].amount.has_value ||
            template->ports[p].amount.value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
            continue;
        }
        if (template->ports[p].amount.value.payload_size == path_size &&
            memcmp(template->ports[p].amount.value.payload, path, path_size) == 0) {
            match = &resolved_ports[p];
            PRINTF("find_port_by_argument_path: matched port %u path_size=%u\n",
                   (unsigned) p,
                   (unsigned) path_size);
        }
    }
    return match;
}

// Override a field's leaf and mint from a value-flow port before formatting: a
// port covering the field's account slot replaces the displayed address and, for
// a TOKEN_AMOUNT, its mint; a port whose amount reads the field's ARGUMENT_PATH
// replaces the displayed amount. `override_leaf` is caller-owned scratch; on
// substitution `*leaf` is repointed to it.
static void apply_port_overrides(const cs_instruction_result_t *instruction,
                                 const cs_display_field_t *display_field,
                                 idl_resolved_leaf_t *override_leaf,
                                 const idl_resolved_leaf_t **leaf,
                                 const uint8_t **mint) {
    if (display_field->source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        const cs_resolved_port_t *port = find_port_by_account_index(instruction->template,
                                                                    instruction->resolved_ports,
                                                                    instruction->resolved_port_count,
                                                                    display_field->account.index);
        if (port != NULL) {
            memcpy(override_leaf, *leaf, sizeof(*override_leaf));
            override_leaf->value = port->account;
            override_leaf->value_size = PUBKEY_SIZE;
            *leaf = override_leaf;
            PRINTF("apply_port_overrides: account field overridden by port\n");
        }
    } else if (display_field->source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
        if (display_field->argument.param_type == CS_PARAM_TYPE_AMOUNT ||
            display_field->argument.param_type == CS_PARAM_TYPE_TOKEN_AMOUNT) {
            const cs_resolved_port_t *port = find_port_by_argument_path(instruction->template,
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
                PRINTF("apply_port_overrides: amount field overridden by port\n");
            }
        }
        if (display_field->argument.param_type == CS_PARAM_TYPE_TOKEN_AMOUNT &&
            display_field->argument.format.token_amount.mint_source == CS_TOKEN_MINT_ACCOUNT_INDEX) {
            const cs_resolved_port_t *port =
                find_port_by_account_index(instruction->template,
                                           instruction->resolved_ports,
                                           instruction->resolved_port_count,
                                           display_field->argument.format.token_amount.ref.account_index);
            if (port != NULL && port->mint != NULL) {
                *mint = port->mint;
                PRINTF("apply_port_overrides: token mint overridden by port\n");
            }
        }
    }
}

// Append the "[index/total] operation_type" header element for one instruction,
// showing the program name when the template carries one, else its address.
static int render_instruction_header(const cs_instruction_result_t *instruction,
                                     size_t survivor_index,
                                     size_t survivor_count) {
    cs_display_element_t *header = append_element();
    if (header == NULL) {
        PRINTF("render_instruction_header: element append failed\n");
        return -1;
    }

    if (!APP_MEM_CALLOC((void **) &header->title, CS_RENDER_BUFFER_SIZE)) {
        PRINTF("render_instruction_header: title buffer allocation failed\n");
        return -1;
    }
    snprintf(header->title,
             CS_RENDER_BUFFER_SIZE,
             "[%u/%u] %s",
             (unsigned) survivor_index,
             (unsigned) survivor_count,
             instruction->template->operation_type);
    header->title = shrink_render_buffer(header->title);
    if (header->title == NULL) {
        return -1;
    }

    if (!APP_MEM_CALLOC((void **) &header->value, CS_RENDER_BUFFER_SIZE)) {
        PRINTF("render_instruction_header: value buffer allocation failed\n");
        return -1;
    }
    if (instruction->template->program_name != NULL &&
        instruction->template->program_name[0] != '\0') {
        snprintf(header->value,
                 CS_RENDER_BUFFER_SIZE,
                 "Program: %s",
                 instruction->template->program_name);
    } else {
        char address[BASE58_PUBKEY_LENGTH];
        if (encode_base58(instruction->template->program_id, PUBKEY_SIZE, address, sizeof(address)) <
            0) {
            PRINTF("render_instruction_header: base58 encode program_id failed\n");
            APP_MEM_FREE_AND_NULL((void **) &header->value);
            return -1;
        }
        snprintf(header->value, CS_RENDER_BUFFER_SIZE, "Program: %s", address);
    }
    header->value = shrink_render_buffer(header->value);
    if (header->value == NULL) {
        return -1;
    }
    return 0;
}

// Append the display element for one resolved field: its label (the template
// name or "Field N") and its formatted value.
static int render_field(const cs_instruction_result_t *instruction, size_t field) {
    cs_display_element_t *element = append_element();
    if (element == NULL) {
        PRINTF("render_field: element append failed field=%u\n", (unsigned) field);
        return -1;
    }

    if (!APP_MEM_CALLOC((void **) &element->title, CS_RENDER_BUFFER_SIZE)) {
        PRINTF("render_field: title buffer allocation failed field=%u\n", (unsigned) field);
        return -1;
    }
    if (instruction->template->display_fields[field].name != NULL &&
        instruction->template->display_fields[field].name[0] != '\0') {
        strlcpy(element->title,
                instruction->template->display_fields[field].name,
                CS_RENDER_BUFFER_SIZE);
    } else {
        snprintf(element->title, CS_RENDER_BUFFER_SIZE, "Field %u", (unsigned) (field + 1));
    }
    element->title = shrink_render_buffer(element->title);
    if (element->title == NULL) {
        return -1;
    }

    if (!APP_MEM_CALLOC((void **) &element->value, CS_RENDER_BUFFER_SIZE)) {
        PRINTF("render_field: value buffer allocation failed field=%u\n", (unsigned) field);
        return -1;
    }
    const idl_resolved_leaf_t *leaf = &instruction->resolved[field];
    const uint8_t *mint = instruction->field_mint[field];
    idl_resolved_leaf_t override_leaf;
    apply_port_overrides(instruction,
                         &instruction->template->display_fields[field],
                         &override_leaf,
                         &leaf,
                         &mint);

    if (format_field(&instruction->template->display_fields[field],
                     leaf,
                     mint,
                     element->value,
                     CS_RENDER_BUFFER_SIZE) != 0) {
        PRINTF("render_field: format failed field=%u\n", (unsigned) field);
        APP_MEM_FREE_AND_NULL((void **) &element->value);
        return -1;
    }
    element->value = shrink_render_buffer(element->value);
    if (element->value == NULL) {
        return -1;
    }
    return 0;
}

int cs_display_renderer_run(const cs_instruction_result_t *walked_instructions,
                            size_t walked_instructions_count,
                            const bool *survivors) {
    // A run builds from empty; a populated renderer is a scheduling error. On any
    // failure below the partial list is left for the caller's session teardown.
    if (G_cs_display_renderer.count != 0 || G_cs_display_renderer.elements != NULL) {
        PRINTF("cs_display_renderer_run: renderer already populated, refusing to run\n");
        return -1;
    }

    // Count surviving instructions for the [ix/total] header
    size_t survivor_count = 0;
    for (size_t i = 0; i < walked_instructions_count; i++) {
        if (survivors[i]) {
            survivor_count++;
        }
    }
    PRINTF("cs_display_renderer_run: %u instructions, %u survivors\n",
           (unsigned) walked_instructions_count,
           (unsigned) survivor_count);

    size_t survivor_index = 0;

    for (size_t ix = 0; ix < walked_instructions_count; ix++) {
        if (!survivors[ix]) {
            continue;
        }
        survivor_index++;
        PRINTF("cs_display_renderer_run: rendering instruction ix=%u operation=%s\n",
               (unsigned) ix,
               walked_instructions[ix].template->operation_type);

        if (render_instruction_header(&walked_instructions[ix], survivor_index, survivor_count) !=
            0) {
            PRINTF("cs_display_renderer_run: header render failed ix=%u\n", (unsigned) ix);
            return -1;
        }

        for (size_t field = 0; field < walked_instructions[ix].resolved_count; field++) {
            if (walked_instructions[ix].resolved[field].value == NULL) {
                PRINTF("cs_display_renderer_run: field=%u has no value, skipped\n",
                       (unsigned) field);
                continue;
            }
            if (render_field(&walked_instructions[ix], field) != 0) {
                PRINTF("cs_display_renderer_run: field render failed ix=%u field=%u\n",
                       (unsigned) ix,
                       (unsigned) field);
                return -1;
            }
        }
    }

    PRINTF("cs_display_renderer_run: produced %u elements\n",
           (unsigned) G_cs_display_renderer.count);
    return 0;
}

// Copy a NUL-terminated string into a freshly sized heap buffer. Returns the
// buffer, or NULL on allocation failure.
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

int cs_display_renderer_append(const char *title, const char *value) {
    if (title == NULL || value == NULL) {
        PRINTF("cs_display_renderer_append: NULL title or value\n");
        return -1;
    }
    // Grows the same flat list the run loop fills, so the pair becomes the next
    // trailing review screen. A half-filled element left by a failure here is
    // released by cs_display_renderer_reset, which tolerates NULL strings.
    cs_display_element_t *element = append_element();
    if (element == NULL) {
        PRINTF("cs_display_renderer_append: element append failed\n");
        return -1;
    }
    element->title = duplicate_string(title);
    if (element->title == NULL) {
        return -1;
    }
    element->value = duplicate_string(value);
    if (element->value == NULL) {
        return -1;
    }
    PRINTF("cs_display_renderer_append: %s = %s\n", title, value);
    return 0;
}

size_t cs_display_renderer_element_count(void) {
    return G_cs_display_renderer.count;
}

const cs_display_element_t *cs_display_renderer_element(size_t index) {
    if (index >= G_cs_display_renderer.count) {
        PRINTF("cs_display_renderer_element: index %u out of range\n", (unsigned) index);
        return NULL;
    }
    return G_cs_display_renderer.elements[index];
}
