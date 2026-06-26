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
// template. Every instruction must resolve to a template: an instruction with no
// descriptor would otherwise be signed without ever being decoded or displayed,
// so a missing template aborts the whole session.
static int walk_transaction(void) {
    Parser parser = {G_cs_transaction->transaction,
                     G_cs_transaction->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("finalize cs: failed to parse buffered transaction\n");
        return -1;
    }

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

        int walk_status = idl_walker_run(instruction.data,
                                         instruction.data_length,
                                         NULL,
                                         NULL);
        idl_pool_reset();
        if (walk_status != 0) {
            PRINTF("finalize cs: walk failed for instruction %d\n", i);
            return -1;
        }
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

    int status = walk_transaction();
    if (status != 0) {
        cs_transaction_reset();
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    if (cs_merge_engine_run() != 0) {
        PRINTF("finalize cs: merge engine failed\n");
        cs_transaction_reset();
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    return io_send_sw(ApduReplySuccess);
}
