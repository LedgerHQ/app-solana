#include <os.h>
#include <string.h>

#include "clear_signing_context.h"
#include "cs_substructure.h"
#include "app_mem_utils.h"

clear_signing_context_t *G_clear_signing_context;

void clear_signing_context_reset(void) {
    cs_substructure_reset();
    if (G_clear_signing_context == NULL) {
        return;
    }
    if (G_clear_signing_context->transaction != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &G_clear_signing_context->transaction);
    }
    APP_MEM_FREE_AND_NULL((void **) &G_clear_signing_context);
}

int clear_signing_context_begin(const uint8_t *transaction, size_t transaction_size) {
    clear_signing_context_reset();

    if (transaction == NULL || transaction_size == 0) {
        PRINTF("clear_signing_context_begin: empty transaction\n");
        return -1;
    }

    if (!APP_MEM_CALLOC((void **) &G_clear_signing_context, sizeof(clear_signing_context_t))) {
        PRINTF("clear_signing_context_begin: context allocation failed\n");
        return -1;
    }

    G_clear_signing_context->transaction = APP_MEM_ALLOC(transaction_size);
    if (G_clear_signing_context->transaction == NULL) {
        PRINTF("clear_signing_context_begin: transaction copy allocation failed\n");
        clear_signing_context_reset();
        return -1;
    }

    memcpy(G_clear_signing_context->transaction, transaction, transaction_size);
    G_clear_signing_context->transaction_size = transaction_size;
    return 0;
}

cs_instruction_template_t *clear_signing_context_new_template(void) {
    if (G_clear_signing_context == NULL) {
        PRINTF("clear_signing_context_new_template: no active context\n");
        return NULL;
    }
    if (G_clear_signing_context->template_count >= CS_MAX_INSTRUCTION_TEMPLATES) {
        PRINTF("clear_signing_context_new_template: too many templates (max %d)\n",
               CS_MAX_INSTRUCTION_TEMPLATES);
        return NULL;
    }

    cs_instruction_template_t *template =
        &G_clear_signing_context->templates[G_clear_signing_context->template_count];
    explicit_bzero(template, sizeof(*template));
    G_clear_signing_context->template_count++;
    return template;
}

cs_instruction_template_t *clear_signing_context_current_template(void) {
    if (G_clear_signing_context == NULL || G_clear_signing_context->template_count == 0) {
        return NULL;
    }
    return &G_clear_signing_context->templates[G_clear_signing_context->template_count - 1];
}

int clear_signing_context_add_display_path(const uint8_t *path, size_t path_size) {
    cs_instruction_template_t *template = clear_signing_context_current_template();
    if (template == NULL) {
        PRINTF("clear_signing_context_add_display_path: no active template\n");
        return -1;
    }
    if (path_size > CS_MAX_ARGUMENT_PATH_SIZE) {
        PRINTF("clear_signing_context_add_display_path: path too long (%d > %d)\n",
               path_size,
               CS_MAX_ARGUMENT_PATH_SIZE);
        return -1;
    }
    if (template->display_field_count >= CS_MAX_DISPLAY_FIELDS) {
        PRINTF("clear_signing_context_add_display_path: too many display fields (max %d)\n",
               CS_MAX_DISPLAY_FIELDS);
        return -1;
    }

    cs_display_field_t *field = &template->display_fields[template->display_field_count];
    memcpy(field->path, path, path_size);
    field->path_size = (uint8_t) path_size;
    template->display_field_count++;
    return 0;
}

const cs_instruction_template_t *clear_signing_context_find_template(
    const uint8_t program_id[32],
    const uint8_t *data,
    size_t data_size) {
    if (G_clear_signing_context == NULL) {
        return NULL;
    }

    for (uint8_t i = 0; i < G_clear_signing_context->template_count; i++) {
        const cs_instruction_template_t *template = &G_clear_signing_context->templates[i];
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
