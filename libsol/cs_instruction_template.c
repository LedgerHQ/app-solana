// Instruction template table for clear signing. See cs_instruction_template.h.
//
// Assembles each signed INSTRUCTION_INFO template in a single in-flight builder
// and promotes it into the committed array only once its substructure hash has
// matched the descriptor's committed target, so committed templates are always
// whole and walker-ready.

#include <string.h>

#include "cs_instruction_template.h"
#include "cs_substructure.h"
#include "app_mem_utils.h"
#include "os_print.h"

// =============================================================================
// Module-global table
// =============================================================================

typedef struct cs_instruction_template_table_s {
    cs_instruction_template_t *builder;  // heap, non-NULL while a template is in flight
    cs_instruction_template_t **committed;  // demand-grown array of template pointers
    uint8_t committed_count;
} cs_instruction_template_table_t;

static cs_instruction_template_table_t *G_template_table = NULL;

// Free every heap buffer a template owns; leaves the template block itself intact.
static void free_template_owned_buffers(cs_instruction_template_t *template) {
    if (template == NULL) {
        return;
    }
    if (template->discriminator != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &template->discriminator);
    }
    if (template->idl_type_pool != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &template->idl_type_pool);
    }
    if (template->operation_type != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &template->operation_type);
    }
    if (template->program_name != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &template->program_name);
    }
    for (uint8_t f = 0; f < template->display_field_count; f++) {
        if (template->display_fields[f].name != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &template->display_fields[f].name);
        }
        if (template->display_fields[f].source == CS_VALUE_SOURCE_ARGUMENT_PATH &&
            template->display_fields[f].argument.path != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &template->display_fields[f].argument.path);
        }
        if (template->display_fields[f].source == CS_VALUE_SOURCE_CONSTANT &&
            template->display_fields[f].constant.data != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &template->display_fields[f].constant.data);
        }
    }
}

// NULL name is a valid unlabeled field (*out = NULL); a non-NULL name must be non-empty.
static int copy_field_name(char **out, const char *name) {
    *out = NULL;
    if (name != NULL) {
        size_t len = strlen(name);
        if (len == 0) {
            PRINTF("cs_instruction_template: empty field name rejected\n");
            return -1;
        }
        if (!APP_MEM_CALLOC((void **) out, len + 1)) {
            PRINTF("cs_instruction_template: field name allocation failed (%d bytes)\n",
                   (int) len + 1);
            return -1;
        }
        memcpy(*out, name, len);
    }
    return 0;
}

static bool ensure_table(void) {
    if (G_template_table != NULL) {
        return true;
    }
    if (!APP_MEM_CALLOC((void **) &G_template_table, sizeof(*G_template_table))) {
        PRINTF("cs_instruction_template: table allocation failed\n");
        return false;
    }
    return true;
}

cs_instruction_template_t *cs_instruction_template_open(const uint8_t target_hash[32]) {
    if (!ensure_table()) {
        return NULL;
    }

    // Drop any previous unfinished builder before opening a fresh one.
    if (G_template_table->builder != NULL) {
        free_template_owned_buffers(G_template_table->builder);
        APP_MEM_FREE_AND_NULL((void **) &G_template_table->builder);
    }
    if (!APP_MEM_CALLOC((void **) &G_template_table->builder, sizeof(*G_template_table->builder))) {
        PRINTF("cs_instruction_template: builder allocation failed\n");
        return NULL;
    }
    cs_substructure_begin(target_hash);
    return G_template_table->builder;
}

cs_instruction_template_t *cs_instruction_template_current(void) {
    if (G_template_table == NULL) {
        return NULL;
    }
    return G_template_table->builder;
}

int cs_instruction_template_add_display_path(const uint8_t *path,
                                             size_t path_size,
                                             uint8_t param_type,
                                             const char *name) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_add_display_path: no builder open\n");
        return -1;
    }
    if (path_size == 0 || path_size > UINT8_MAX) {
        PRINTF("cs_instruction_template_add_display_path: invalid path size %d\n", (int) path_size);
        return -1;
    }
    if (builder->display_field_count >= CS_MAX_DISPLAY_FIELDS) {
        PRINTF("cs_instruction_template_add_display_path: too many display fields (max %d)\n",
               CS_MAX_DISPLAY_FIELDS);
        return -1;
    }

    uint8_t *path_copy = NULL;
    if (!APP_MEM_CALLOC((void **) &path_copy, path_size)) {
        PRINTF("cs_instruction_template_add_display_path: path allocation failed (%d bytes)\n",
               (int) path_size);
        return -1;
    }
    memcpy(path_copy, path, path_size);
    char *name_copy = NULL;
    if (copy_field_name(&name_copy, name) != 0) {
        APP_MEM_FREE_AND_NULL((void **) &path_copy);
        return -1;
    }

    builder->display_fields[builder->display_field_count].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    builder->display_fields[builder->display_field_count].argument.param_type = param_type;
    builder->display_fields[builder->display_field_count].argument.path = path_copy;
    builder->display_fields[builder->display_field_count].argument.path_size = (uint8_t) path_size;
    builder->display_fields[builder->display_field_count].name = name_copy;
    builder->display_field_count++;
    return 0;
}

int cs_instruction_template_add_account_field(uint8_t account_index, const char *name) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_add_account_field: no builder open\n");
        return -1;
    }
    if (builder->display_field_count >= CS_MAX_DISPLAY_FIELDS) {
        PRINTF("cs_instruction_template_add_account_field: too many display fields (max %d)\n",
               CS_MAX_DISPLAY_FIELDS);
        return -1;
    }

    char *name_copy = NULL;
    if (copy_field_name(&name_copy, name) != 0) {
        return -1;
    }

    builder->display_fields[builder->display_field_count].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    builder->display_fields[builder->display_field_count].account.index = account_index;
    builder->display_fields[builder->display_field_count].name = name_copy;
    builder->display_field_count++;
    return 0;
}

int cs_instruction_template_add_constant_field(const uint8_t *data,
                                               size_t data_size,
                                               uint8_t kind,
                                               const char *name) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_add_constant_field: no builder open\n");
        return -1;
    }
    if (data_size == 0 || data_size > UINT8_MAX) {
        PRINTF("cs_instruction_template_add_constant_field: invalid data size %d\n", (int) data_size);
        return -1;
    }
    if (builder->display_field_count >= CS_MAX_DISPLAY_FIELDS) {
        PRINTF("cs_instruction_template_add_constant_field: too many display fields (max %d)\n",
               CS_MAX_DISPLAY_FIELDS);
        return -1;
    }

    uint8_t *data_copy = NULL;
    if (!APP_MEM_CALLOC((void **) &data_copy, data_size)) {
        PRINTF("cs_instruction_template_add_constant_field: data allocation failed (%d bytes)\n",
               (int) data_size);
        return -1;
    }
    memcpy(data_copy, data, data_size);
    char *name_copy = NULL;
    if (copy_field_name(&name_copy, name) != 0) {
        APP_MEM_FREE_AND_NULL((void **) &data_copy);
        return -1;
    }

    builder->display_fields[builder->display_field_count].source = CS_VALUE_SOURCE_CONSTANT;
    builder->display_fields[builder->display_field_count].constant.data = data_copy;
    builder->display_fields[builder->display_field_count].constant.data_size = (uint8_t) data_size;
    builder->display_fields[builder->display_field_count].constant.kind = kind;
    builder->display_fields[builder->display_field_count].name = name_copy;
    builder->display_field_count++;
    return 0;
}

int cs_instruction_template_set_format_amount(uint8_t decimals) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL || builder->display_field_count == 0) {
        PRINTF("cs_instruction_template_set_format_amount: no field to configure\n");
        return -1;
    }
    cs_display_field_t *field = &builder->display_fields[builder->display_field_count - 1];
    if (field->source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("cs_instruction_template_set_format_amount: source %d != ARGUMENT_PATH\n",
               field->source);
        return -1;
    }
    if (field->argument.param_type != CS_PARAM_TYPE_AMOUNT) {
        PRINTF("cs_instruction_template_set_format_amount: param_type %d != AMOUNT\n",
               field->argument.param_type);
        return -1;
    }
    field->argument.format.amount.decimals = decimals;
    return 0;
}

int cs_instruction_template_set_format_token_amount(const cs_format_token_amount_t *format) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL || builder->display_field_count == 0) {
        PRINTF("cs_instruction_template_set_format_token_amount: no field to configure\n");
        return -1;
    }
    cs_display_field_t *field = &builder->display_fields[builder->display_field_count - 1];
    if (field->source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("cs_instruction_template_set_format_token_amount: source %d != ARGUMENT_PATH\n",
               field->source);
        return -1;
    }
    if (field->argument.param_type != CS_PARAM_TYPE_TOKEN_AMOUNT) {
        PRINTF("cs_instruction_template_set_format_token_amount: param_type %d != TOKEN_AMOUNT\n",
               field->argument.param_type);
        return -1;
    }
    memcpy(&field->argument.format.token_amount, format, sizeof(*format));
    return 0;
}

int cs_instruction_template_set_format_datetime(uint32_t ticks_per_second) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL || builder->display_field_count == 0) {
        PRINTF("cs_instruction_template_set_format_datetime: no field to configure\n");
        return -1;
    }
    cs_display_field_t *field = &builder->display_fields[builder->display_field_count - 1];
    if (field->source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("cs_instruction_template_set_format_datetime: source %d != ARGUMENT_PATH\n",
               field->source);
        return -1;
    }
    if (field->argument.param_type != CS_PARAM_TYPE_DATETIME) {
        PRINTF("cs_instruction_template_set_format_datetime: param_type %d != DATETIME\n",
               field->argument.param_type);
        return -1;
    }
    field->argument.format.datetime.ticks_per_second = ticks_per_second;
    return 0;
}

int cs_instruction_template_set_format_unit(const cs_format_unit_t *format) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL || builder->display_field_count == 0) {
        PRINTF("cs_instruction_template_set_format_unit: no field to configure\n");
        return -1;
    }
    cs_display_field_t *field = &builder->display_fields[builder->display_field_count - 1];
    if (field->source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("cs_instruction_template_set_format_unit: source %d != ARGUMENT_PATH\n",
               field->source);
        return -1;
    }
    if (field->argument.param_type != CS_PARAM_TYPE_UNIT) {
        PRINTF("cs_instruction_template_set_format_unit: param_type %d != UNIT\n",
               field->argument.param_type);
        return -1;
    }
    memcpy(&field->argument.format.unit, format, sizeof(*format));
    return 0;
}

int cs_instruction_template_set_format_string(const cs_format_string_t *format) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL || builder->display_field_count == 0) {
        PRINTF("cs_instruction_template_set_format_string: no field to configure\n");
        return -1;
    }
    cs_display_field_t *field = &builder->display_fields[builder->display_field_count - 1];
    if (field->source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("cs_instruction_template_set_format_string: source %d != ARGUMENT_PATH\n",
               field->source);
        return -1;
    }
    if (field->argument.param_type != CS_PARAM_TYPE_STRING) {
        PRINTF("cs_instruction_template_set_format_string: param_type %d != STRING\n",
               field->argument.param_type);
        return -1;
    }
    memcpy(&field->argument.format.string, format, sizeof(*format));
    return 0;
}

int cs_instruction_template_set_format_trusted_name(const cs_format_trusted_name_t *format) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL || builder->display_field_count == 0) {
        PRINTF("cs_instruction_template_set_format_trusted_name: no field to configure\n");
        return -1;
    }
    cs_display_field_t *field = &builder->display_fields[builder->display_field_count - 1];
    if (field->source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        PRINTF("cs_instruction_template_set_format_trusted_name: source %d != ARGUMENT_PATH\n",
               field->source);
        return -1;
    }
    if (field->argument.param_type != CS_PARAM_TYPE_TRUSTED_NAME) {
        PRINTF("cs_instruction_template_set_format_trusted_name: param_type %d != TRUSTED_NAME\n",
               field->argument.param_type);
        return -1;
    }
    memcpy(&field->argument.format.trusted_name, format, sizeof(*format));
    return 0;
}

int cs_instruction_template_set_idl_type_pool(const uint8_t *data, size_t size) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_set_idl_type_pool: no builder open\n");
        return -1;
    }
    // ENFORCE_UNIQUE_TAG bounds this to one call per builder; free defensively anyway.
    if (builder->idl_type_pool != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &builder->idl_type_pool);
    }
    if (!APP_MEM_CALLOC((void **) &builder->idl_type_pool, size)) {
        PRINTF("cs_instruction_template_set_idl_type_pool: allocation failed (%d bytes)\n",
               (int) size);
        return -1;
    }
    memcpy(builder->idl_type_pool, data, size);
    builder->idl_type_pool_size = size;
    return 0;
}

// Copy str_size bytes into a fresh NUL-terminated heap buffer at *dst. Empty is
// rejected; the caller skips the call when there is nothing to store.
static int set_builder_string(char **dst, const char *str, size_t str_size) {
    if (str_size == 0) {
        PRINTF("cs_instruction_template: empty string rejected\n");
        return -1;
    }
    if (*dst != NULL) {
        APP_MEM_FREE_AND_NULL((void **) dst);
    }
    if (!APP_MEM_CALLOC((void **) dst, str_size + 1)) {
        PRINTF("cs_instruction_template: string allocation failed (%d bytes)\n", (int) str_size + 1);
        return -1;
    }
    memcpy(*dst, str, str_size);
    return 0;
}

int cs_instruction_template_set_operation_type(const char *str, size_t str_size) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_set_operation_type: no builder open\n");
        return -1;
    }
    return set_builder_string(&builder->operation_type, str, str_size);
}

int cs_instruction_template_set_program_name(const char *str, size_t str_size) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_set_program_name: no builder open\n");
        return -1;
    }
    return set_builder_string(&builder->program_name, str, str_size);
}

int cs_instruction_template_set_discriminator(const uint8_t *data, size_t size) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_set_discriminator: no builder open\n");
        return -1;
    }
    if (size > UINT8_MAX) {
        PRINTF("cs_instruction_template_set_discriminator: discriminator too long (%d)\n",
               (int) size);
        return -1;
    }
    if (builder->discriminator != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &builder->discriminator);
    }
    builder->discriminator_size = 0;
    if (size > 0) {
        if (!APP_MEM_CALLOC((void **) &builder->discriminator, size)) {
            PRINTF("cs_instruction_template_set_discriminator: allocation failed (%d bytes)\n",
                   (int) size);
            return -1;
        }
        memcpy(builder->discriminator, data, size);
    }
    builder->discriminator_size = (uint8_t) size;
    return 0;
}

// Record which instruction accounts carry the token account and the mint,
// so the finalize step can resolve the mint pubkey for TOKEN_AMOUNT display.
int cs_instruction_template_set_mint_assoc(uint8_t account_idx, uint8_t mint_idx) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_set_mint_assoc: no builder open\n");
        return -1;
    }
    builder->mint_assoc_account = account_idx;
    builder->mint_assoc_mint = mint_idx;
    builder->has_mint_assoc = true;
    return 0;
}

int cs_instruction_template_commit(void) {
    if (G_template_table == NULL || G_template_table->builder == NULL) {
        PRINTF("cs_instruction_template_commit: no builder open\n");
        return -1;
    }

    // Grow the pointer array by one, then hand the builder block over: a zero-copy
    // transfer, so the builder's idl_type_pool rides along with no aliasing.
    cs_instruction_template_t **grown =
        APP_MEM_REALLOC(G_template_table->committed,
                        (G_template_table->committed_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("cs_instruction_template_commit: committed array growth failed\n");
        return -1;
    }
    G_template_table->committed = grown;

    G_template_table->committed[G_template_table->committed_count] = G_template_table->builder;
    G_template_table->committed_count++;
    G_template_table->builder = NULL;
    return 0;
}

uint8_t cs_instruction_template_committed_count(void) {
    if (G_template_table == NULL) {
        return 0;
    }
    return G_template_table->committed_count;
}

bool cs_instruction_template_pending(void) {
    if (G_template_table == NULL) {
        return false;
    }
    return G_template_table->builder != NULL;
}

const cs_instruction_template_t *cs_instruction_template_find(const uint8_t program_id[32],
                                                              const uint8_t *data,
                                                              size_t data_size) {
    if (G_template_table == NULL) {
        return NULL;
    }

    for (uint8_t i = 0; i < G_template_table->committed_count; i++) {
        const cs_instruction_template_t *template = G_template_table->committed[i];
        if (memcmp(template->program_id, program_id, 32) != 0) {
            continue;
        }
        if (data_size < template->discriminator_size) {
            continue;
        }
        // Empty discriminator matches any instruction (and keeps NULL out of memcmp).
        if (template->discriminator_size > 0 &&
            memcmp(data, template->discriminator, template->discriminator_size) != 0) {
            continue;
        }
        return template;
    }
    return NULL;
}

void cs_instruction_template_table_reset(void) {
    cs_substructure_reset();
    if (G_template_table != NULL) {
        if (G_template_table->builder != NULL) {
            free_template_owned_buffers(G_template_table->builder);
            APP_MEM_FREE_AND_NULL((void **) &G_template_table->builder);
        }
        // Each committed template owns heap buffers and its own block; free the
        // buffers then the block per entry, then the pointer array, before the table.
        for (uint8_t i = 0; i < G_template_table->committed_count; i++) {
            free_template_owned_buffers(G_template_table->committed[i]);
            APP_MEM_FREE_AND_NULL((void **) &G_template_table->committed[i]);
        }
        if (G_template_table->committed != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &G_template_table->committed);
        }
        APP_MEM_FREE_AND_NULL((void **) &G_template_table);
    }
}
