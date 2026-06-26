#include <os.h>
#include <string.h>

#include "handle_finalize_generic_clear_signing.h"
#include "cs_transaction.h"
#include "cs_merge_engine.h"
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
static int walk_transaction(cs_instruction_result_t *results, size_t *result_count) {
    Parser parser = {G_cs_transaction->transaction,
                     G_cs_transaction->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("finalize cs: failed to parse buffered transaction\n");
        return -1;
    }

    *result_count = 0;

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

        cs_instruction_result_t *result = &results[*result_count];
        memset(result, 0, sizeof(*result));
        result->template = template;

        idl_leaf_collector_t collector;
        memset(&collector, 0, sizeof(collector));
        for (uint8_t f = 0; f < template->display_field_count; f++) {
            memcpy(collector.match_paths[f].data,
                   template->display_fields[f].path,
                   template->display_fields[f].path_size);
            collector.match_paths[f].size = template->display_fields[f].path_size;
        }
        collector.match_count = template->display_field_count;

        int walk_status = idl_walker_run(instruction.data,
                                         instruction.data_length,
                                         &collector);
        idl_pool_reset();
        if (walk_status != 0) {
            PRINTF("finalize cs: walk failed for instruction %d\n", i);
            return -1;
        }

        result->collected = collector;
        (*result_count)++;
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
    if (cs_merge_engine_element_count() > 0) {
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

    cs_instruction_result_t results[CS_MAX_INSTRUCTION_TEMPLATES];
    size_t result_count = 0;

    int status = walk_transaction(results, &result_count);
    if (status != 0) {
        cs_transaction_reset();
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    if (cs_merge_engine_run(results, result_count) != 0) {
        PRINTF("finalize cs: merge engine failed\n");
        cs_transaction_reset();
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    return io_send_sw(ApduReplySuccess);
}
