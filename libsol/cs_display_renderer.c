#include <string.h>
#include <stdio.h>

#include "cs_display_renderer.h"
#include "app_mem_utils.h"
#include "idl_kinds.h"
#include "sol/printer.h"
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
            // For unhandled kinds, show hex summary
            if (leaf->value_size <= 8) {
                // Short hex
                for (size_t i = 0; i < leaf->value_size && (2 * i + 2) < value_out_size; i++) {
                    snprintf(value_out + 2 * i, value_out_size - 2 * i, "%02x", leaf->value[i]);
                }
            } else {
                snprintf(value_out,
                         value_out_size,
                         "%02x%02x...%02x%02x (%u B)",
                         leaf->value[0],
                         leaf->value[1],
                         leaf->value[leaf->value_size - 2],
                         leaf->value[leaf->value_size - 1],
                         (unsigned) leaf->value_size);
            }
            return 0;
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
        const cs_instruction_result_t *instr = &walked_instructions[ix];

        // Instruction header element: "[ix/total] operation_type"
        if (element_index >= CS_MAX_DISPLAY_ELEMENTS) {
            PRINTF("cs_display_renderer_run: too many display elements\n");
            return -1;
        }
        cs_display_element_t *header = &G_cs_display_renderer->elements[element_index];
        snprintf(header->title,
                 CS_DISPLAY_TITLE_SIZE,
                 "[%u/%u] %s",
                 (unsigned) survivor_index,
                 (unsigned) survivor_count,
                 instr->template->operation_type);
        header->value[0] = '\0';
        element_index++;

        for (uint8_t field = 0; field < instr->resolved_count; field++) {
            if (element_index >= CS_MAX_DISPLAY_ELEMENTS) {
                PRINTF("cs_display_renderer_run: too many display elements\n");
                return -1;
            }

            const idl_resolved_leaf_t *leaf = &instr->resolved[field];
            if (leaf->value == NULL) {
                continue;
            }

            cs_display_element_t *element = &G_cs_display_renderer->elements[element_index];

            const char *field_name = instr->template->display_fields[field].name;
            if (field_name[0] != '\0') {
                strlcpy(element->title, field_name, CS_DISPLAY_TITLE_SIZE);
            } else {
                snprintf(element->title, CS_DISPLAY_TITLE_SIZE, "Field %u", field + 1);
            }

            if (format_leaf(leaf, element->value, CS_DISPLAY_VALUE_SIZE) != 0) {
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
