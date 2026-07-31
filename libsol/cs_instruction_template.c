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
    cs_instruction_template_t *builder;     // heap, non-NULL while a template is in flight
    cs_instruction_template_t **committed;  // demand-grown array of template pointers
    size_t committed_count;
} cs_instruction_template_table_t;

static cs_instruction_template_table_t *G_template_table = NULL;

static void free_stored_value(cs_stored_value_t *value) {
    if (value->payload != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &value->payload);
    }
    value->payload_size = 0;
}

static void free_port_owned_buffers(cs_value_flow_port_t *port) {
    if (port->account_candidates != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &port->account_candidates);
    }
    if (port->active_when != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &port->active_when);
    }
    free_stored_value(&port->amount.value);
    free_stored_value(&port->token.value);
}

static void free_hide_rule_owned_buffers(cs_hide_rule_t *rule) {
    free_stored_value(&rule->target);
}

static void free_account_reset_owned_buffers(cs_account_reset_t *reset) {
    free_stored_value(&reset->reset_value.value);
    for (size_t d = 0; d < reset->scope.discriminator_count; d++) {
        if (reset->scope.discriminators[d].data != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &reset->scope.discriminators[d].data);
        }
    }
    if (reset->scope.discriminators != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &reset->scope.discriminators);
    }
    reset->scope.discriminator_count = 0;
}

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
    // Free each field's owned buffers before the field array itself (two-level).
    for (size_t f = 0; f < template->display_field_count; f++) {
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
        if (template->display_fields[f].source == CS_VALUE_SOURCE_ARGUMENT_PATH &&
            template->display_fields[f].argument.param_type == CS_PARAM_TYPE_UNIT &&
            template->display_fields[f].argument.format.unit.symbol != NULL) {
            APP_MEM_FREE_AND_NULL(
                (void **) &template->display_fields[f].argument.format.unit.symbol);
        }
        if (template->display_fields[f].source == CS_VALUE_SOURCE_ARGUMENT_PATH &&
            template->display_fields[f].argument.param_type == CS_PARAM_TYPE_AMOUNT &&
            template->display_fields[f].argument.format.amount.max_label != NULL) {
            APP_MEM_FREE_AND_NULL(
                (void **) &template->display_fields[f].argument.format.amount.max_label);
        }
        if (template->display_fields[f].source == CS_VALUE_SOURCE_ARGUMENT_PATH &&
            template->display_fields[f].argument.param_type == CS_PARAM_TYPE_TOKEN_AMOUNT &&
            template->display_fields[f].argument.format.token_amount.max_label != NULL) {
            APP_MEM_FREE_AND_NULL(
                (void **) &template->display_fields[f].argument.format.token_amount.max_label);
        }
    }
    if (template->display_fields != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &template->display_fields);
    }
    template->display_field_count = 0;

    // Merge-engine substructures: free each entry's owned buffers before its array.
    for (size_t p = 0; p < template->port_count; p++) {
        free_port_owned_buffers(&template->ports[p]);
    }
    if (template->ports != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &template->ports);
    }
    template->port_count = 0;

    for (size_t h = 0; h < template->hide_rule_count; h++) {
        free_hide_rule_owned_buffers(&template->hide_rules[h]);
    }
    if (template->hide_rules != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &template->hide_rules);
    }
    template->hide_rule_count = 0;

    for (size_t r = 0; r < template->account_reset_count; r++) {
        free_account_reset_owned_buffers(&template->account_resets[r]);
    }
    if (template->account_resets != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &template->account_resets);
    }
    template->account_reset_count = 0;

    free_stored_value(&template->owner_assoc_owner);
}

// Grow the builder's display-field array by one zeroed slot and return it, or
// NULL on allocation failure (the existing array is left intact).
static cs_display_field_t *append_display_field(cs_instruction_template_t *builder) {
    cs_display_field_t *grown = APP_MEM_REALLOC(
        builder->display_fields,
        (builder->display_field_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("cs_instruction_template: display field array growth failed\n");
        return NULL;
    }
    builder->display_fields = grown;
    cs_display_field_t *slot = &builder->display_fields[builder->display_field_count];
    memset(slot, 0, sizeof(*slot));
    builder->display_field_count++;
    return slot;
}

// Deep-copy a borrowed VALUE into template-owned heap. On alloc failure the dst
// payload stays NULL, so the caller's teardown is a no-op for it.
static int copy_stored_value(cs_stored_value_t *dst,
                             uint8_t source,
                             const uint8_t *payload,
                             size_t payload_size) {
    dst->source = source;
    dst->payload = NULL;
    dst->payload_size = 0;
    if (payload_size > 0) {
        if (!APP_MEM_CALLOC((void **) &dst->payload, payload_size)) {
            PRINTF("cs_instruction_template: stored value allocation failed (%d bytes)\n",
                   (int) payload_size);
            return -1;
        }
        memcpy(dst->payload, payload, payload_size);
        dst->payload_size = payload_size;
    }
    return 0;
}

static int copy_amount_value(cs_amount_value_t *dst, const cs_amount_value_t *source) {
    dst->kind = source->kind;
    dst->has_value = source->has_value;
    if (source->has_value) {
        return copy_stored_value(&dst->value,
                                 source->value.source,
                                 source->value.payload,
                                 source->value.payload_size);
    }
    return 0;
}

static int copy_token_value(cs_token_value_t *dst, const cs_token_value_t *source) {
    dst->kind = source->kind;
    dst->has_value = source->has_value;
    dst->has_account = source->has_account;
    dst->account_index = source->account_index;
    dst->has_fallback_account = source->has_fallback_account;
    dst->fallback_account_index = source->fallback_account_index;
    if (source->has_value) {
        return copy_stored_value(&dst->value,
                                 source->value.source,
                                 source->value.payload,
                                 source->value.payload_size);
    }
    return 0;
}

// Grow a merge-engine substructure array by one zeroed slot, returning it or NULL
// on allocation failure (the existing array is left intact).
static cs_value_flow_port_t *append_port(cs_instruction_template_t *builder) {
    cs_value_flow_port_t *grown = APP_MEM_REALLOC(builder->ports,
                                                  (builder->port_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("cs_instruction_template: port array growth failed\n");
        return NULL;
    }
    builder->ports = grown;
    cs_value_flow_port_t *slot = &builder->ports[builder->port_count];
    memset(slot, 0, sizeof(*slot));
    builder->port_count++;
    return slot;
}

static cs_hide_rule_t *append_hide_rule(cs_instruction_template_t *builder) {
    cs_hide_rule_t *grown = APP_MEM_REALLOC(builder->hide_rules,
                                            (builder->hide_rule_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("cs_instruction_template: hide rule array growth failed\n");
        return NULL;
    }
    builder->hide_rules = grown;
    cs_hide_rule_t *slot = &builder->hide_rules[builder->hide_rule_count];
    memset(slot, 0, sizeof(*slot));
    builder->hide_rule_count++;
    return slot;
}

static cs_account_reset_t *append_account_reset(cs_instruction_template_t *builder) {
    cs_account_reset_t *grown = APP_MEM_REALLOC(
        builder->account_resets,
        (builder->account_reset_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("cs_instruction_template: account reset array growth failed\n");
        return NULL;
    }
    builder->account_resets = grown;
    cs_account_reset_t *slot = &builder->account_resets[builder->account_reset_count];
    memset(slot, 0, sizeof(*slot));
    builder->account_reset_count++;
    return slot;
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

cs_instruction_template_t *cs_instruction_template_open(const uint8_t target_hash[CX_SHA256_SIZE]) {
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

    cs_display_field_t *slot = append_display_field(builder);
    if (slot == NULL) {
        APP_MEM_FREE_AND_NULL((void **) &path_copy);
        APP_MEM_FREE_AND_NULL((void **) &name_copy);
        return -1;
    }
    slot->source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    slot->argument.param_type = param_type;
    slot->argument.path = path_copy;
    slot->argument.path_size = (uint8_t) path_size;
    slot->name = name_copy;
    return 0;
}

int cs_instruction_template_add_account_field(uint8_t account_index, const char *name) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_add_account_field: no builder open\n");
        return -1;
    }
    char *name_copy = NULL;
    if (copy_field_name(&name_copy, name) != 0) {
        return -1;
    }

    cs_display_field_t *slot = append_display_field(builder);
    if (slot == NULL) {
        APP_MEM_FREE_AND_NULL((void **) &name_copy);
        return -1;
    }
    slot->source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    slot->account.index = account_index;
    slot->name = name_copy;
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
        PRINTF("cs_instruction_template_add_constant_field: invalid data size %d\n",
               (int) data_size);
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

    cs_display_field_t *slot = append_display_field(builder);
    if (slot == NULL) {
        APP_MEM_FREE_AND_NULL((void **) &data_copy);
        APP_MEM_FREE_AND_NULL((void **) &name_copy);
        return -1;
    }
    slot->source = CS_VALUE_SOURCE_CONSTANT;
    slot->constant.data = data_copy;
    slot->constant.data_size = (uint8_t) data_size;
    slot->constant.kind = kind;
    slot->name = name_copy;
    return 0;
}

// Copy an optional label (NUL-terminated string) into a template-owned heap
// buffer, freeing any previous one first. An empty label leaves *dst NULL.
// Returns 0, -1 on allocation failure (leaving *dst NULL).
static int copy_optional_label(char **dst, const uint8_t *label, size_t label_size) {
    if (*dst != NULL) {
        APP_MEM_FREE_AND_NULL((void **) dst);
    }
    if (label_size > 0) {
        if (!APP_MEM_CALLOC((void **) dst, label_size + 1)) {
            PRINTF("cs_instruction_template: label allocation failed (%d bytes)\n",
                   (int) label_size + 1);
            return -1;
        }
        memcpy(*dst, label, label_size);
    }
    return 0;
}

int cs_instruction_template_set_format_amount(uint8_t decimals,
                                              const uint8_t *max_label,
                                              size_t max_label_size) {
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
    return copy_optional_label(&field->argument.format.amount.max_label, max_label, max_label_size);
}

int cs_instruction_template_set_format_token_amount(const cs_format_token_amount_t *format,
                                                    const uint8_t *max_label,
                                                    size_t max_label_size) {
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
    // The label is template-owned; never keep the caller's borrowed pointer.
    field->argument.format.token_amount.max_label = NULL;
    return copy_optional_label(&field->argument.format.token_amount.max_label,
                               max_label,
                               max_label_size);
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

int cs_instruction_template_set_format_unit(const uint8_t *symbol,
                                            size_t symbol_size,
                                            uint8_t decimals,
                                            bool prefix) {
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
    if (field->argument.format.unit.symbol != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &field->argument.format.unit.symbol);
    }
    if (symbol_size > 0) {
        if (!APP_MEM_CALLOC((void **) &field->argument.format.unit.symbol, symbol_size + 1)) {
            PRINTF("cs_instruction_template_set_format_unit: symbol allocation failed (%d bytes)\n",
                   (int) symbol_size + 1);
            return -1;
        }
        memcpy(field->argument.format.unit.symbol, symbol, symbol_size);
    }
    field->argument.format.unit.decimals = decimals;
    field->argument.format.unit.prefix = prefix;
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
    if (size == 0) {
        PRINTF("cs_instruction_template_set_idl_type_pool: empty pool rejected\n");
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
        PRINTF("cs_instruction_template: string allocation failed (%d bytes)\n",
               (int) str_size + 1);
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
    if (size > CS_DISCRIMINATOR_MAX_SIZE) {
        PRINTF("cs_instruction_template_set_discriminator: discriminator too long (%d > %d)\n",
               (int) size,
               CS_DISCRIMINATOR_MAX_SIZE);
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

int cs_instruction_template_add_port(const cs_value_flow_port_t *port) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_add_port: no builder open\n");
        return -1;
    }
    cs_value_flow_port_t *slot = append_port(builder);
    if (slot == NULL) {
        return -1;
    }
    slot->direction = port->direction;
    slot->value_kind = port->value_kind;
    slot->optional_account_strategy = port->optional_account_strategy;
    slot->has_token = port->has_token;

    if (port->candidate_count > 0) {
        if (!APP_MEM_CALLOC((void **) &slot->account_candidates, port->candidate_count)) {
            PRINTF("cs_instruction_template_add_port: candidate list allocation failed\n");
            free_port_owned_buffers(slot);
            return -1;
        }
        memcpy(slot->account_candidates, port->account_candidates, port->candidate_count);
        slot->candidate_count = port->candidate_count;
    }
    if (copy_amount_value(&slot->amount, &port->amount) != 0) {
        free_port_owned_buffers(slot);
        return -1;
    }
    if (port->has_token) {
        if (copy_token_value(&slot->token, &port->token) != 0) {
            free_port_owned_buffers(slot);
            return -1;
        }
    }
    if (port->active_when_size > 0) {
        if (!APP_MEM_CALLOC((void **) &slot->active_when, port->active_when_size)) {
            PRINTF("cs_instruction_template_add_port: active_when allocation failed\n");
            free_port_owned_buffers(slot);
            return -1;
        }
        memcpy(slot->active_when, port->active_when, port->active_when_size);
        slot->active_when_size = port->active_when_size;
    }
    return 0;
}

int cs_instruction_template_add_hide_rule(const cs_hide_rule_t *rule) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_add_hide_rule: no builder open\n");
        return -1;
    }
    cs_hide_rule_t *slot = append_hide_rule(builder);
    if (slot == NULL) {
        return -1;
    }
    slot->rule_set_index = rule->rule_set_index;
    slot->condition = rule->condition;
    if (copy_stored_value(&slot->target,
                          rule->target.source,
                          rule->target.payload,
                          rule->target.payload_size) != 0) {
        free_hide_rule_owned_buffers(slot);
        return -1;
    }
    return 0;
}

int cs_instruction_template_add_account_reset(const cs_account_reset_t *reset) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_add_account_reset: no builder open\n");
        return -1;
    }
    cs_account_reset_t *slot = append_account_reset(builder);
    if (slot == NULL) {
        return -1;
    }
    slot->account_index = reset->account_index;
    slot->require_pre_balance_zero = reset->require_pre_balance_zero;
    slot->has_reset_value = reset->has_reset_value;
    slot->has_scope = reset->has_scope;

    if (reset->has_reset_value) {
        if (copy_amount_value(&slot->reset_value, &reset->reset_value) != 0) {
            free_account_reset_owned_buffers(slot);
            return -1;
        }
    }
    if (reset->has_scope) {
        slot->scope.has_program_id = reset->scope.has_program_id;
        if (reset->scope.has_program_id) {
            memcpy(slot->scope.scope_program_id, reset->scope.scope_program_id, PUBKEY_SIZE);
        }
        if (reset->scope.discriminator_count > 0) {
            if (!APP_MEM_CALLOC(
                    (void **) &slot->scope.discriminators,
                    reset->scope.discriminator_count * sizeof(*slot->scope.discriminators))) {
                PRINTF(
                    "cs_instruction_template_add_account_reset: discriminator array alloc "
                    "failed\n");
                free_account_reset_owned_buffers(slot);
                return -1;
            }
            // Set the count before filling data so a mid-loop failure frees cleanly.
            slot->scope.discriminator_count = reset->scope.discriminator_count;
            for (size_t d = 0; d < reset->scope.discriminator_count; d++) {
                if (reset->scope.discriminators[d].size == 0) {
                    continue;
                }
                if (!APP_MEM_CALLOC((void **) &slot->scope.discriminators[d].data,
                                    reset->scope.discriminators[d].size)) {
                    PRINTF(
                        "cs_instruction_template_add_account_reset: discriminator alloc failed\n");
                    free_account_reset_owned_buffers(slot);
                    return -1;
                }
                memcpy(slot->scope.discriminators[d].data,
                       reset->scope.discriminators[d].data,
                       reset->scope.discriminators[d].size);
                slot->scope.discriminators[d].size = reset->scope.discriminators[d].size;
            }
        }
    }
    return 0;
}

int cs_instruction_template_set_owner_assoc(uint8_t account_idx,
                                            uint8_t owner_source,
                                            const uint8_t *owner_payload,
                                            size_t owner_payload_size) {
    cs_instruction_template_t *builder = cs_instruction_template_current();
    if (builder == NULL) {
        PRINTF("cs_instruction_template_set_owner_assoc: no builder open\n");
        return -1;
    }
    if (copy_stored_value(&builder->owner_assoc_owner,
                          owner_source,
                          owner_payload,
                          owner_payload_size) != 0) {
        return -1;
    }
    builder->owner_assoc_account = account_idx;
    builder->has_owner_assoc = true;
    return 0;
}

int cs_instruction_template_commit(void) {
    if (G_template_table == NULL || G_template_table->builder == NULL) {
        PRINTF("cs_instruction_template_commit: no builder open\n");
        return -1;
    }

    // Grow the pointer array by one, then hand the builder block over: a zero-copy
    // transfer, so the builder's idl_type_pool rides along with no aliasing.
    cs_instruction_template_t **grown = APP_MEM_REALLOC(
        G_template_table->committed,
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

size_t cs_instruction_template_committed_count(void) {
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

const cs_instruction_template_t *cs_instruction_template_find(const uint8_t program_id[PUBKEY_SIZE],
                                                              const uint8_t *data,
                                                              size_t data_size) {
    if (G_template_table == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < G_template_table->committed_count; i++) {
        const cs_instruction_template_t *template = G_template_table->committed[i];
        if (memcmp(template->program_id, program_id, PUBKEY_SIZE) != 0) {
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
        for (size_t i = 0; i < G_template_table->committed_count; i++) {
            free_template_owned_buffers(G_template_table->committed[i]);
            APP_MEM_FREE_AND_NULL((void **) &G_template_table->committed[i]);
        }
        if (G_template_table->committed != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &G_template_table->committed);
        }
        APP_MEM_FREE_AND_NULL((void **) &G_template_table);
    }
}
