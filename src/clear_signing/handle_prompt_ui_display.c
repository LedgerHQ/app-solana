#include <os.h>
#include <string.h>

#include "handle_prompt_ui_display.h"
#include "clear_signing_context.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "sol/parser.h"
#include "idl_pool.h"
#include "idl_walker.h"

// MVP leaf sink: report each decoded leaf and whether the template exposes a
// DISPLAY_FIELD whose argument path matches it. No UI is rendered yet.
static void cs_leaf_callback(const idl_leaf_t *leaf, void *callback_context) {
    const cs_instruction_template_t *template =
        (const cs_instruction_template_t *) callback_context;

    bool has_display = false;
    for (uint8_t i = 0; i < template->display_field_count; i++) {
        const cs_display_field_t *field = &template->display_fields[i];
        if (field->path_size != leaf->path_size) {
            continue;
        }
        if (memcmp(field->path, leaf->path, leaf->path_size) == 0) {
            has_display = true;
            break;
        }
    }

    PRINTF("cs_leaf: kind=%d path=%.*H value=%.*H has_display=%d\n",
           leaf->kind,
           leaf->path_size,
           leaf->path,
           leaf->value_size,
           leaf->value,
           has_display);
}

// Walk every transaction instruction against the IDL type pool of its matching
// template. Every instruction must resolve to a template: an instruction with no
// descriptor would otherwise be signed without ever being decoded or displayed,
// so a missing template aborts the whole session.
static int walk_transaction(void) {
    Parser parser = {G_clear_signing_context->transaction,
                     G_clear_signing_context->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("prompt ui: failed to parse buffered transaction\n");
        return -1;
    }

    for (size_t i = 0; i < header.instructions_length; i++) {
        Instruction instruction;
        if (parse_instruction(&parser, &instruction) != 0) {
            PRINTF("prompt ui: failed to parse instruction %d\n", i);
            return -1;
        }

        if (instruction.program_id_index >= header.pubkeys_header.pubkeys_length) {
            PRINTF("prompt ui: instruction %d program id index out of range\n", i);
            return -1;
        }
        const uint8_t *program_id = header.pubkeys[instruction.program_id_index].data;

        const cs_instruction_template_t *template =
            clear_signing_context_find_template(program_id,
                                                instruction.data,
                                                instruction.data_length);
        if (template == NULL) {
            PRINTF("prompt ui: no template for instruction %d, refusing to sign\n", i);
            return -1;
        }

        if (idl_pool_provide(template->idl_type_pool,
                             template->idl_type_pool_size,
                             template->idl_root_type) != 0) {
            PRINTF("prompt ui: idl pool load failed for instruction %d\n", i);
            return -1;
        }

        int walk_status = idl_walker_run(instruction.data,
                                         instruction.data_length,
                                         cs_leaf_callback,
                                         (void *) template);
        idl_pool_reset();
        if (walk_status != 0) {
            PRINTF("prompt ui: walk failed for instruction %d\n", i);
            return -1;
        }
    }
    return 0;
}

int handle_prompt_ui_display(void) {
    PRINTF("handle_prompt_ui_display\n");

    if (G_command.instruction != InsPromptUiDisplay ||
        G_command.state != ApduStatePayloadComplete) {
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    if (G_clear_signing_context == NULL || G_clear_signing_context->template_count == 0) {
        PRINTF("prompt ui: no clear-signing context\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }

    for (uint8_t i = 0; i < G_clear_signing_context->template_count; i++) {
        if (!G_clear_signing_context->templates[i].complete) {
            PRINTF("prompt ui: template %d incomplete\n", i);
            return io_send_sw(ApduReplySolanaClearSigningIncomplete);
        }
    }

    int status = walk_transaction();
    clear_signing_context_reset();
    if (status != 0) {
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }
    return io_send_sw(ApduReplySuccess);
}
