#include <os.h>
#include <string.h>

#include "handle_finalize_generic_clear_signing.h"
#include "cs_transaction.h"
#include "cs_merge_engine.h"
#include "cs_display_renderer.h"
#include "cs_instruction_template.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "sol/parser.h"
#include "idl_pool.h"
#include "idl_walker.h"

// Walk every transaction instruction against the IDL type pool of its matching
// template, collecting the display-field leaf values into per-instruction
// results for the merge engine. Every instruction must resolve to a template.
static int walk_transaction(cs_instruction_result_t *walked_instructions,
                            size_t *walked_instructions_count) {
    Parser parser = {G_cs_transaction->transaction,
                     G_cs_transaction->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("finalize cs: failed to parse buffered transaction\n");
        return -1;
    }

    *walked_instructions_count = 0;

    for (size_t i = 0; i < header.instructions_length; i++) {
        Instruction instruction;
        if (parse_instruction(&parser, &instruction) != 0) {
            PRINTF("finalize cs: failed to parse instruction %d\n", i);
            return -1;
        }

        if (instruction.program_id_index >= header.pubkeys_header.pubkeys_length) {
            PRINTF("finalize cs: instruction %d program id index out of range\n", i);
            return -1;
        }
        const uint8_t *program_id = header.pubkeys[instruction.program_id_index].data;

        const cs_instruction_template_t *template =
            cs_instruction_template_find(program_id,
                                         instruction.data,
                                         instruction.data_length);
        if (template == NULL) {
            PRINTF("finalize cs: no template for instruction %d, refusing to sign\n", i);
            return -1;
        }

        if (idl_pool_provide(template->idl_type_pool,
                             template->idl_type_pool_size,
                             template->idl_root_type) != 0) {
            PRINTF("finalize cs: idl pool load failed for instruction %d\n", i);
            return -1;
        }

        // Run walker on received instruction, take as input the instruction + display template
        int walk_status = idl_walker_run(
            instruction.data,
            instruction.data_length,
            (const idl_match_path_t *) template->display_fields,
            template->display_field_count,
            walked_instructions[*walked_instructions_count].resolved,
            &walked_instructions[*walked_instructions_count].resolved_count);

        // IDL pool has been used for this descriptor.
        // we can free the memory now because host is required to re-provide even if same
        idl_pool_reset();

        if (walk_status != 0) {
            PRINTF("finalize cs: walk failed for instruction %d\n", i);
            return -1;
        }

        // Forward the template that matched for the merge engine down the line
        walked_instructions[*walked_instructions_count].template = template;
        (*walked_instructions_count)++;
    }
    return 0;
}

int handle_finalize_generic_clear_signing(void) {
    PRINTF("handle_finalize_generic_clear_signing\n");

    if (G_command.instruction != InsFinalizeGenericClearSigning ||
        G_command.state != ApduStatePayloadComplete) {
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    if (G_cs_transaction == NULL) {
        PRINTF("finalize cs: no clear-signing context\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (cs_merge_engine_finalized()) {
        PRINTF("finalize cs: already finalized\n");
        return io_send_sw(ApduReplySdkInvalidParameter);
    }
    if (cs_instruction_template_pending()) {
        PRINTF("finalize cs: an instruction template was never completed\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (cs_instruction_template_committed_count() == 0) {
        PRINTF("finalize cs: no instruction templates provided\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }

    cs_instruction_result_t walked_instructions[CS_MAX_INSTRUCTION_TEMPLATES];
    size_t walked_instructions_count = 0;

    if (walk_transaction(walked_instructions, &walked_instructions_count) != 0) {
        PRINTF("finalize cs: walk engine failed\n");
        cs_transaction_reset();
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    if (cs_merge_engine_run(walked_instructions, walked_instructions_count) != 0) {
        PRINTF("finalize cs: merge engine failed\n");
        cs_transaction_reset();
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    // MVP: all instructions survived merge — render them all
    if (cs_display_renderer_run(walked_instructions, walked_instructions_count) != 0) {
        PRINTF("finalize cs: display renderer failed\n");
        cs_transaction_reset();
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    return io_send_sw(ApduReplySuccess);
}
