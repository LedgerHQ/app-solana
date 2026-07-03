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
    cs_instruction_template_t committed[CS_MAX_INSTRUCTION_TEMPLATES];
    uint8_t committed_count;
} cs_instruction_template_table_t;

static cs_instruction_template_table_t *G_template_table = NULL;

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
    if (G_template_table->committed_count >= CS_MAX_INSTRUCTION_TEMPLATES) {
        PRINTF("cs_instruction_template: committed array full (max %d)\n",
               CS_MAX_INSTRUCTION_TEMPLATES);
        return NULL;
    }

    // Drop any previous unfinished builder before opening a fresh one.
    if (G_template_table->builder != NULL) {
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
    if (path_size > CS_MAX_ARGUMENT_PATH_SIZE) {
        PRINTF("cs_instruction_template_add_display_path: path too long (%d > %d)\n",
               path_size,
               CS_MAX_ARGUMENT_PATH_SIZE);
        return -1;
    }
    if (builder->display_field_count >= CS_MAX_DISPLAY_FIELDS) {
        PRINTF("cs_instruction_template_add_display_path: too many display fields (max %d)\n",
               CS_MAX_DISPLAY_FIELDS);
        return -1;
    }

    builder->display_fields[builder->display_field_count].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    builder->display_fields[builder->display_field_count].argument.param_type = param_type;
    memcpy(builder->display_fields[builder->display_field_count].argument.path, path, path_size);
    builder->display_fields[builder->display_field_count].argument.path_size = (uint8_t) path_size;
    if (name != NULL) {
        strlcpy(builder->display_fields[builder->display_field_count].name,
                name,
                sizeof(builder->display_fields[builder->display_field_count].name));
    } else {
        builder->display_fields[builder->display_field_count].name[0] = '\0';
    }
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

    builder->display_fields[builder->display_field_count].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    builder->display_fields[builder->display_field_count].account.index = account_index;
    if (name != NULL) {
        strlcpy(builder->display_fields[builder->display_field_count].name,
                name,
                sizeof(builder->display_fields[builder->display_field_count].name));
    } else {
        builder->display_fields[builder->display_field_count].name[0] = '\0';
    }
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
    if (data_size > CS_MAX_CONSTANT_SIZE) {
        PRINTF("cs_instruction_template_add_constant_field: data too long (%d > %d)\n",
               (int) data_size,
               CS_MAX_CONSTANT_SIZE);
        return -1;
    }
    if (builder->display_field_count >= CS_MAX_DISPLAY_FIELDS) {
        PRINTF("cs_instruction_template_add_constant_field: too many display fields (max %d)\n",
               CS_MAX_DISPLAY_FIELDS);
        return -1;
    }

    builder->display_fields[builder->display_field_count].source = CS_VALUE_SOURCE_CONSTANT;
    memcpy(builder->display_fields[builder->display_field_count].constant.data, data, data_size);
    builder->display_fields[builder->display_field_count].constant.data_size = (uint8_t) data_size;
    builder->display_fields[builder->display_field_count].constant.kind = kind;
    if (name != NULL) {
        strlcpy(builder->display_fields[builder->display_field_count].name,
                name,
                sizeof(builder->display_fields[builder->display_field_count].name));
    } else {
        builder->display_fields[builder->display_field_count].name[0] = '\0';
    }
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
    if (G_template_table->committed_count >= CS_MAX_INSTRUCTION_TEMPLATES) {
        PRINTF("cs_instruction_template_commit: committed array full (max %d)\n",
               CS_MAX_INSTRUCTION_TEMPLATES);
        return -1;
    }

    memcpy(&G_template_table->committed[G_template_table->committed_count],
           G_template_table->builder,
           sizeof(*G_template_table->builder));
    G_template_table->committed_count++;
    APP_MEM_FREE_AND_NULL((void **) &G_template_table->builder);
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
        const cs_instruction_template_t *template = &G_template_table->committed[i];
        if (memcmp(template->program_id, program_id, 32) != 0) {
            continue;
        }
        if (data_size < template->discriminator_size) {
            continue;
        }
        if (memcmp(data, template->discriminator, template->discriminator_size) != 0) {
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
            APP_MEM_FREE_AND_NULL((void **) &G_template_table->builder);
        }
        APP_MEM_FREE_AND_NULL((void **) &G_template_table);
    }
}
