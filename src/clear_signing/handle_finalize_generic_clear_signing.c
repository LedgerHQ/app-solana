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
#include "idl_kinds.h"

// Walk every transaction instruction against the IDL type pool of its matching
// template, collecting the display-field leaf values into per-instruction
// results for the merge engine. Every instruction must resolve to a template.
static int walk_transaction(const cs_transaction_t *cs_tx,
                            cs_instruction_result_t *walked_instructions,
                            size_t *walked_instructions_count) {
    Parser parser = {cs_tx->transaction, cs_tx->transaction_size};
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

        // Build a compact array of only ARGUMENT_PATH entries for the walker,
        // tracking which original indices they came from.
        idl_match_path_t argument_paths[CS_MAX_DISPLAY_FIELDS];
        uint8_t argument_indices[CS_MAX_DISPLAY_FIELDS];
        uint8_t argument_count = 0;
        for (uint8_t f = 0; f < template->display_field_count; f++) {
            if (template->display_fields[f].source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
                memcpy(argument_paths[argument_count].path,
                       template->display_fields[f].argument.path,
                       template->display_fields[f].argument.path_size);
                argument_paths[argument_count].path_size =
                    template->display_fields[f].argument.path_size;
                argument_indices[argument_count] = f;
                argument_count++;
            }
        }

        // Run walker only on the ARGUMENT_PATH subset
        idl_resolved_leaf_t walker_results[CS_MAX_DISPLAY_FIELDS];
        uint8_t walker_resolved_count = 0;
        int walk_status = idl_walker_run(instruction.data,
                                         instruction.data_length,
                                         argument_paths,
                                         argument_count,
                                         walker_results,
                                         &walker_resolved_count);

        idl_pool_reset();

        if (walk_status != 0) {
            PRINTF("finalize cs: walk failed for instruction %d\n", i);
            return -1;
        }

        // Initialize full resolved array then scatter walker results back
        cs_instruction_result_t *result = &walked_instructions[*walked_instructions_count];
        memset(result->resolved, 0, sizeof(result->resolved));
        result->resolved_count = template->display_field_count;

        for (uint8_t w = 0; w < argument_count; w++) {
            result->resolved[argument_indices[w]] = walker_results[w];
        }

        // Resolve ACCOUNT_PATH fields from the instruction's accounts array
        for (uint8_t f = 0; f < template->display_field_count; f++) {
            if (template->display_fields[f].source != CS_VALUE_SOURCE_ACCOUNT_PATH) {
                continue;
            }
            uint8_t account_index = template->display_fields[f].account.index;
            if (account_index >= instruction.accounts_length) {
                PRINTF("finalize cs: instruction %d account_index %d out of range (%d)\n",
                       i,
                       account_index,
                       instruction.accounts_length);
                return -1;
            }
            uint8_t pubkey_index = instruction.accounts[account_index];
            if (pubkey_index >= header.pubkeys_header.pubkeys_length) {
                PRINTF("finalize cs: instruction %d pubkey_index %d out of range (%d)\n",
                       i,
                       pubkey_index,
                       header.pubkeys_header.pubkeys_length);
                return -1;
            }
            result->resolved[f].kind = IDL_KIND_PUBKEY_32;
            result->resolved[f].value = header.pubkeys[pubkey_index].data;
            result->resolved[f].value_size = 32;
        }

        // Resolve CONSTANT fields directly from the template
        for (uint8_t f = 0; f < template->display_field_count; f++) {
            if (template->display_fields[f].source != CS_VALUE_SOURCE_CONSTANT) {
                continue;
            }
            result->resolved[f].kind = template->display_fields[f].constant.kind;
            result->resolved[f].value = template->display_fields[f].constant.data;
            result->resolved[f].value_size = template->display_fields[f].constant.data_size;
        }

        result->template = template;
        result->mint_pubkey = NULL;

        // Resolve the mint pubkey from the template's mint association indices
        // so the renderer can look up token symbol and decimals.
        if (template->has_mint_assoc) {
            if (template->mint_assoc_mint >= instruction.accounts_length) {
                PRINTF("finalize cs: instruction %d mint_assoc_mint %d out of range (%d)\n",
                       i,
                       template->mint_assoc_mint,
                       instruction.accounts_length);
                return -1;
            }
            if (instruction.accounts[template->mint_assoc_mint] >=
                header.pubkeys_header.pubkeys_length) {
                PRINTF("finalize cs: instruction %d mint pubkey_index %d out of range (%d)\n",
                       i,
                       instruction.accounts[template->mint_assoc_mint],
                       header.pubkeys_header.pubkeys_length);
                return -1;
            }
            result->mint_pubkey =
                header.pubkeys[instruction.accounts[template->mint_assoc_mint]].data;
        }

        (*walked_instructions_count)++;
    }
    return 0;
}

int handle_finalize_generic_clear_signing(void) {
    PRINTF("handle_finalize_generic_clear_signing\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return io_send_sw(state_err);
    }

    if (G_command.instruction != InsFinalizeGenericClearSigning ||
        G_command.state != ApduStatePayloadComplete) {
        cs_transaction_reset();
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    const cs_transaction_t *cs_tx = cs_transaction_get();
    if (cs_tx == NULL) {
        PRINTF("finalize cs: no clear-signing context\n");
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (cs_instruction_template_pending()) {
        PRINTF("finalize cs: an instruction template was never completed\n");
        cs_transaction_reset();
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (cs_instruction_template_committed_count() == 0) {
        PRINTF("finalize cs: no instruction templates provided\n");
        cs_transaction_reset();
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }

    cs_instruction_result_t walked_instructions[CS_MAX_INSTRUCTION_TEMPLATES];
    size_t walked_instructions_count = 0;

    if (walk_transaction(cs_tx, walked_instructions, &walked_instructions_count) != 0) {
        PRINTF("finalize cs: walk engine failed\n");
        cs_transaction_reset();
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    bool survivors[CS_MAX_INSTRUCTION_TEMPLATES];
    if (cs_merge_engine_run(walked_instructions, walked_instructions_count, survivors) != 0) {
        PRINTF("finalize cs: merge engine failed\n");
        cs_transaction_reset();
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    if (cs_display_renderer_run(walked_instructions, walked_instructions_count, survivors) != 0) {
        PRINTF("finalize cs: display renderer failed\n");
        cs_transaction_reset();
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    G_cs_session_state = CS_SESSION_FINALIZED;
    return io_send_sw(ApduReplySuccess);
}
