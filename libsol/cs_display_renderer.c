#include <string.h>
#include <stdio.h>

#include "cs_display_renderer.h"
#include "cs_instruction_template.h"
#include "app_mem_utils.h"
#include "idl_kinds.h"
#include "sol/printer.h"
#include "util.h"
#include "os_print.h"

typedef struct cs_display_renderer_s {
    cs_display_element_t elements[CS_MAX_DISPLAY_ELEMENTS];
    uint8_t element_count;
} cs_display_renderer_t;

static cs_display_renderer_t *G_cs_display_renderer = NULL;

void cs_display_renderer_reset(void) {
    if (G_cs_display_renderer != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &G_cs_display_renderer);
    }
}

// Format a single resolved leaf into the value buffer based on its kind.
// Returns 0 on success, -1 on failure.
static int format_leaf(const idl_resolved_leaf_t *leaf,
                       char *value_out,
                       size_t value_out_size) {
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
            print_u64((uint64_t) (leaf->value[0] | (leaf->value[1] << 8) |
                                  (leaf->value[2] << 16) | (leaf->value[3] << 24)),
                      value_out,
                      value_out_size);
            return 0;

        case IDL_KIND_U64:
            if (leaf->value_size < 8) {
                PRINTF("format_leaf: u64 truncated\n");
                return -1;
            }
            print_u64((uint64_t) leaf->value[0] | ((uint64_t) leaf->value[1] << 8) |
                          ((uint64_t) leaf->value[2] << 16) |
                          ((uint64_t) leaf->value[3] << 24) |
                          ((uint64_t) leaf->value[4] << 32) |
                          ((uint64_t) leaf->value[5] << 40) |
                          ((uint64_t) leaf->value[6] << 48) |
                          ((uint64_t) leaf->value[7] << 56),
                      value_out,
                      value_out_size);
            return 0;

        case IDL_KIND_BOOL_U8:
            if (leaf->value_size < 1) {
                PRINTF("format_leaf: bool_u8 truncated\n");
                return -1;
            }
            strlcpy(value_out, leaf->value[0] ? "True" : "False", value_out_size);
            return 0;

        case IDL_KIND_PUBKEY_32:
            if (leaf->value_size < 32) {
                PRINTF("format_leaf: pubkey truncated\n");
                return -1;
            }
            if (encode_base58(leaf->value, 32, value_out, value_out_size) < 0) {
                PRINTF("format_leaf: base58 encode failed\n");
                return -1;
            }
            return 0;

        case IDL_KIND_STRING_FIXED:
        case IDL_KIND_STRING_PREFIXED: {
            size_t copy_len = leaf->value_size;
            if (copy_len >= value_out_size) {
                copy_len = value_out_size - 1;
            }
            memcpy(value_out, leaf->value, copy_len);
            value_out[copy_len] = '\0';
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

    switch (leaf->kind) {
        case IDL_KIND_U8:
            width = 1;
            break;
        case IDL_KIND_U16:
            width = 2;
            break;
        case IDL_KIND_U32:
            width = 4;
            break;
        case IDL_KIND_U64:
            width = 8;
            break;
        default:
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

// PARAM_AMOUNT: numeric value with fixed decimal scaling.
static int format_amount(const idl_resolved_leaf_t *leaf,
                         uint8_t decimals,
                         char *value_out,
                         size_t value_out_size) {
    uint64_t amount;
    if (read_leaf_u64(leaf, &amount) != 0) {
        PRINTF("format_amount: unsupported leaf kind %d\n", leaf->kind);
        return -1;
    }
    return print_token_amount(amount, NULL, decimals, value_out, value_out_size);
}

// PARAM_TOKEN_AMOUNT: token amount with ticker. Native SOL uses built-in
// metadata. Unresolved tokens render as "123456 ???" with no decimal scaling.
static int format_token_amount(const idl_resolved_leaf_t *leaf,
                               const cs_format_token_amount_t *fmt,
                               char *value_out,
                               size_t value_out_size) {
    uint64_t amount;
    if (read_leaf_u64(leaf, &amount) != 0) {
        PRINTF("format_token_amount: unsupported leaf kind %d\n", leaf->kind);
        return -1;
    }
    if (fmt->is_native) {
        return print_token_amount(amount, "SOL", SOL_DECIMALS, value_out, value_out_size);
    }
    return print_token_amount(amount, "???", 0, value_out, value_out_size);
}

// ACCOUNT_PATH: full base58 address.
static int format_account(const idl_resolved_leaf_t *leaf,
                          char *value_out,
                          size_t value_out_size) {
    if (leaf->value_size < 32) {
        PRINTF("format_account: value too short (%u < 32)\n", (unsigned) leaf->value_size);
        return -1;
    }
    if (encode_base58(leaf->value, 32, value_out, value_out_size) < 0) {
        PRINTF("format_account: base58 encode failed\n");
        return -1;
    }
    return 0;
}

// Format an ARGUMENT_PATH field based on its param_type.
static int format_argument_field(const cs_display_field_t *field,
                                 const idl_resolved_leaf_t *leaf,
                                 char *value_out,
                                 size_t value_out_size) {
    switch (field->argument.param_type) {
        case CS_PARAM_TYPE_RAW:
            return format_leaf(leaf, value_out, value_out_size);

        case CS_PARAM_TYPE_AMOUNT:
            return format_amount(leaf,
                                field->argument.format.amount.decimals,
                                value_out,
                                value_out_size);

        case CS_PARAM_TYPE_TOKEN_AMOUNT:
            return format_token_amount(leaf,
                                       &field->argument.format.token_amount,
                                       value_out,
                                       value_out_size);

        default:
            PRINTF("format_argument_field: unsupported param_type %d\n",
                   field->argument.param_type);
            return -1;
    }
}

// Dispatch formatting based on the display field's source.
// ARGUMENT_PATH fields use param_type for semantic formatting.
// ACCOUNT_PATH fields always render as full base58 addresses.
// CONSTANT fields always use format_leaf with their IDL kind.
static int format_field(const cs_display_field_t *field,
                        const idl_resolved_leaf_t *leaf,
                        char *value_out,
                        size_t value_out_size) {
    if (leaf->value == NULL || leaf->value_size == 0) {
        strlcpy(value_out, "<empty>", value_out_size);
        return 0;
    }

    switch (field->source) {
        case CS_VALUE_SOURCE_ARGUMENT_PATH:
            return format_argument_field(field, leaf, value_out, value_out_size);

        case CS_VALUE_SOURCE_ACCOUNT_PATH:
            return format_account(leaf, value_out, value_out_size);

        case CS_VALUE_SOURCE_CONSTANT:
            return format_leaf(leaf, value_out, value_out_size);

        default:
            PRINTF("format_field: unsupported source %d\n", field->source);
            return -1;
    }
}

int cs_display_renderer_run(const cs_instruction_result_t *walked_instructions,
                            size_t walked_instructions_count,
                            const bool *survivors) {
    cs_display_renderer_reset();

    if (!APP_MEM_CALLOC((void **) &G_cs_display_renderer, sizeof(cs_display_renderer_t))) {
        PRINTF("cs_display_renderer_run: allocation failed\n");
        return -1;
    }

    // Count surviving instructions for the [ix/total] header
    size_t survivor_count = 0;
    for (size_t i = 0; i < walked_instructions_count; i++) {
        if (survivors[i]) {
            survivor_count++;
        }
    }

    uint8_t element_index = 0;
    size_t survivor_index = 0;

    for (size_t ix = 0; ix < walked_instructions_count; ix++) {
        if (!survivors[ix]) {
            continue;
        }
        survivor_index++;

        // Instruction header element: "[ix/total] operation_type"
        if (element_index >= CS_MAX_DISPLAY_ELEMENTS) {
            PRINTF("cs_display_renderer_run: too many display elements\n");
            return -1;
        }
        snprintf(G_cs_display_renderer->elements[element_index].title,
                 CS_DISPLAY_TITLE_SIZE,
                 "[%u/%u] %s",
                 (unsigned) survivor_index,
                 (unsigned) survivor_count,
                 walked_instructions[ix].template->operation_type);

        // Display Program, as name if the template told us, as address otherwise
        if (walked_instructions[ix].template->program_name[0] != '\0') {
            snprintf(G_cs_display_renderer->elements[element_index].value,
                     CS_DISPLAY_VALUE_SIZE,
                     "Program: %s",
                     walked_instructions[ix].template->program_name);
        } else {
            char address[45];
            if (encode_base58(walked_instructions[ix].template->program_id,
                              32,
                              address,
                              sizeof(address)) < 0) {
                PRINTF("cs_display_renderer_run: base58 encode program_id failed\n");
                return -1;
            }
            snprintf(G_cs_display_renderer->elements[element_index].value,
                     CS_DISPLAY_VALUE_SIZE,
                     "Program: %s",
                     address);
        }
        element_index++;

        for (uint8_t field = 0; field < walked_instructions[ix].resolved_count; field++) {
            if (element_index >= CS_MAX_DISPLAY_ELEMENTS) {
                PRINTF("cs_display_renderer_run: too many display elements\n");
                return -1;
            }

            if (walked_instructions[ix].resolved[field].value == NULL) {
                continue;
            }

            if (walked_instructions[ix].template->display_fields[field].name[0] != '\0') {
                strlcpy(G_cs_display_renderer->elements[element_index].title,
                        walked_instructions[ix].template->display_fields[field].name,
                        CS_DISPLAY_TITLE_SIZE);
            } else {
                snprintf(G_cs_display_renderer->elements[element_index].title,
                         CS_DISPLAY_TITLE_SIZE,
                         "Field %u",
                         field + 1);
            }

            if (format_field(&walked_instructions[ix].template->display_fields[field],
                            &walked_instructions[ix].resolved[field],
                            G_cs_display_renderer->elements[element_index].value,
                            CS_DISPLAY_VALUE_SIZE) != 0) {
                PRINTF("cs_display_renderer_run: format failed ix=%u field=%u\n",
                       (unsigned) ix,
                       field);
                return -1;
            }

            element_index++;
        }
    }

    G_cs_display_renderer->element_count = element_index;
    PRINTF("cs_display_renderer_run: produced %d elements\n", element_index);
    return 0;
}

size_t cs_display_renderer_element_count(void) {
    if (G_cs_display_renderer == NULL) {
        return 0;
    }
    return G_cs_display_renderer->element_count;
}

const cs_display_element_t *cs_display_renderer_element(size_t index) {
    if (G_cs_display_renderer == NULL) {
        PRINTF("cs_display_renderer_element: renderer not run\n");
        return NULL;
    }
    if (index >= G_cs_display_renderer->element_count) {
        PRINTF("cs_display_renderer_element: index %u out of range\n", (unsigned) index);
        return NULL;
    }
    return &G_cs_display_renderer->elements[index];
}
