#include <os.h>
#include <string.h>

#include "handle_finalize_generic_clear_signing.h"
#include "cs_transaction.h"
#include "cs_merge_engine.h"
#include "cs_display_renderer.h"
#include "cs_instruction_template.h"
#include "cs_token_account_cache.h"
#include "cs_alt_cache.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "reply.h"
#include "app_mem_utils.h"
#include "sol/parser.h"
#include "idl_pool.h"
#include "idl_walker.h"
#include "idl_kinds.h"

// One entry of the transaction-scoped mint-binding map: a token account pubkey
// bound to the mint pubkey that identifies its token. Seeded from every
// instruction template's MINT_ASSOC association. Pointers reference the buffered
// transaction, which outlives the walk.
typedef struct mint_binding_s {
    const uint8_t *token_account;
    const uint8_t *mint;
} mint_binding_t;

// Resolve a 32-byte token reference (a token account or a mint) to the mint that
// identifies its token, per spec "Token amount metadata resolution": the
// MINT_ASSOC bindings take priority, then the chain-attested TOKEN_ACCOUNT_STATE
// cache, and finally the reference is treated as the mint itself.
static const uint8_t *resolve_field_mint(const mint_binding_t *bindings,
                                         size_t binding_count,
                                         const uint8_t *token_ref) {
    for (size_t b = 0; b < binding_count; b++) {
        if (memcmp(bindings[b].token_account, token_ref, 32) == 0) {
            return bindings[b].mint;
        }
    }
    const cs_token_account_t *entry = cs_token_account_cache_find(token_ref);
    if (entry != NULL) {
        return entry->mint;
    }
    return token_ref;
}

// Resolve an instruction accounts-array index to its pubkey. A static index
// reads directly from the message's key list. An ALT-loaded index (beyond the
// static keys, only possible in versioned transactions) is mapped back to its
// (alt_address, entry_index) origin and looked up in the ALT resolution cache;
// without a matching attested resolution it returns NULL so finalize refuses to
// sign. Returns NULL when the index is out of range or unresolved.
static const uint8_t *pubkey_from_account_index(const cs_transaction_t *cs_tx,
                                                 const MessageHeader *header,
                                                 const Instruction *instruction,
                                                 uint8_t account_index) {
    if (account_index >= instruction->accounts_length) {
        PRINTF("finalize cs: account_index %d out of range (%d)\n",
               account_index,
               instruction->accounts_length);
        return NULL;
    }
    uint8_t pubkey_index = instruction->accounts[account_index];

    const uint8_t *pubkey;
    if (pubkey_index < header->pubkeys_header.pubkeys_length) {
        // Static key: read directly from the message's account list.
        pubkey = header->pubkeys[pubkey_index].data;
    } else {
        // ALT-loaded key: map the global index back to its (alt_address, entry_index) origin.
        const uint8_t *alt_address = NULL;
        uint8_t entry_index = 0;
        if (resolve_alt_loaded_index(cs_tx->transaction,
                                     cs_tx->transaction_size,
                                     pubkey_index,
                                     &alt_address,
                                     &entry_index) != 0) {
            PRINTF("finalize cs: pubkey_index %d is not a resolvable ALT-loaded account\n",
                   pubkey_index);
            return NULL;
        }
        // Only an attested ALT_RESOLUTION descriptor can supply the concrete key.
        pubkey = cs_alt_cache_find(alt_address, entry_index);
        if (pubkey == NULL) {
            PRINTF("finalize cs: no ALT resolution for entry index %d, refusing to sign\n",
                   entry_index);
            return NULL;
        }
    }
    return pubkey;
}

// Fill one result slot from one parsed instruction, using the caller-allocated
// scratch (all sized to the template's field count) and the result's own
// resolved / field_mint arrays. Returns 0, -1 on error.
static int walk_instruction_inner(const cs_transaction_t *cs_tx,
                                  const MessageHeader *header,
                                  const Instruction *instruction,
                                  const uint8_t *program_id,
                                  const cs_instruction_template_t *template,
                                  cs_instruction_result_t *result,
                                  idl_match_path_t *argument_paths,
                                  size_t *argument_indices,
                                  idl_resolved_leaf_t *walker_results,
                                  mint_binding_t *bindings,
                                  size_t *binding_count) {
    if (idl_pool_provide(template->idl_type_pool,
                         template->idl_type_pool_size,
                         template->idl_root_type) != 0) {
        PRINTF("finalize cs: idl pool load failed\n");
        return -1;
    }

    // Compact only the ARGUMENT_PATH fields for the walker, tracking their
    // original field indices so results can be scattered back.
    size_t argument_count = 0;
    for (size_t f = 0; f < template->display_field_count; f++) {
        if (template->display_fields[f].source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
            argument_paths[argument_count].path = template->display_fields[f].argument.path;
            argument_paths[argument_count].path_size =
                template->display_fields[f].argument.path_size;
            argument_indices[argument_count] = f;
            argument_count++;
        }
    }

    size_t walker_resolved_count = 0;
    int walk_status = idl_walker_run(instruction->data,
                                     instruction->data_length,
                                     program_id,
                                     argument_paths,
                                     argument_count,
                                     walker_results,
                                     &walker_resolved_count);
    idl_pool_reset();
    if (walk_status != 0) {
        PRINTF("finalize cs: walk failed\n");
        return -1;
    }

    // Scatter the compacted walker results back to their original field slots.
    for (size_t w = 0; w < argument_count; w++) {
        result->resolved[argument_indices[w]] = walker_results[w];
    }

    // Resolve ACCOUNT_PATH fields from the instruction's accounts array
    for (size_t f = 0; f < template->display_field_count; f++) {
        if (template->display_fields[f].source != CS_VALUE_SOURCE_ACCOUNT_PATH) {
            continue;
        }
        const uint8_t *pubkey =
            pubkey_from_account_index(cs_tx,
                                      header,
                                      instruction,
                                      template->display_fields[f].account.index);
        if (pubkey == NULL) {
            PRINTF("finalize cs: ACCOUNT_PATH field %d index out of range\n", (int) f);
            return -1;
        }
        result->resolved[f].kind = IDL_KIND_PUBKEY_32;
        result->resolved[f].value = pubkey;
        result->resolved[f].value_size = 32;
    }

    // Resolve CONSTANT fields directly from the template
    for (size_t f = 0; f < template->display_field_count; f++) {
        if (template->display_fields[f].source != CS_VALUE_SOURCE_CONSTANT) {
            continue;
        }
        result->resolved[f].kind = template->display_fields[f].constant.kind;
        result->resolved[f].value = template->display_fields[f].constant.data;
        result->resolved[f].value_size = template->display_fields[f].constant.data_size;
    }

    // Seed the mint-binding map from this instruction's MINT_ASSOC pair.
    if (template->has_mint_assoc) {
        const uint8_t *token_account =
            pubkey_from_account_index(cs_tx, header, instruction, template->mint_assoc_account);
        const uint8_t *mint =
            pubkey_from_account_index(cs_tx, header, instruction, template->mint_assoc_mint);
        if (token_account == NULL || mint == NULL) {
            PRINTF("finalize cs: mint_assoc index out of range\n");
            return -1;
        }
        bindings[*binding_count].token_account = token_account;
        bindings[*binding_count].mint = mint;
        (*binding_count)++;
    }

    // Resolve each TOKEN_AMOUNT field's mint reference to a token_ref pubkey.
    // The mint it maps to is resolved in a second pass, once every MINT_ASSOC
    // binding has been collected. NATIVE and NONE carry no reference and leave
    // field_mint NULL; the invalid ARGUMENT_PATH source is refused at ingest.
    for (size_t f = 0; f < template->display_field_count; f++) {
        const cs_display_field_t *field = &template->display_fields[f];
        if (field->source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
            continue;
        }
        if (field->argument.param_type != CS_PARAM_TYPE_TOKEN_AMOUNT) {
            continue;
        }
        switch (field->argument.format.token_amount.mint_source) {
            case CS_TOKEN_MINT_NATIVE:
            case CS_TOKEN_MINT_NONE:
                break;
            case CS_TOKEN_MINT_ACCOUNT_INDEX: {
                const uint8_t *token_ref =
                    pubkey_from_account_index(cs_tx,
                                              header,
                                              instruction,
                                              field->argument.format.token_amount.ref.account_index);
                if (token_ref == NULL) {
                    PRINTF("finalize cs: TOKEN account index out of range\n");
                    return -1;
                }
                result->field_mint[f] = token_ref;
                break;
            }
            case CS_TOKEN_MINT_CONSTANT:
                result->field_mint[f] = field->argument.format.token_amount.ref.mint;
                break;
            default:
                PRINTF("finalize cs: unknown TOKEN mint_source %d\n",
                       field->argument.format.token_amount.mint_source);
                return -1;
        }
    }
    return 0;
}

// Match one instruction to its template, allocate the result's field-count-sized
// arrays (freed by the outer handler) plus the per-instruction walker scratch
// (freed here on every exit), and fill the result. Returns 0, -1 on error.
static int walk_instruction(const cs_transaction_t *cs_tx,
                            const MessageHeader *header,
                            const Instruction *instruction,
                            const uint8_t *program_id,
                            cs_instruction_result_t *result,
                            mint_binding_t *bindings,
                            size_t *binding_count) {
    const cs_instruction_template_t *template =
        cs_instruction_template_find(program_id, instruction->data, instruction->data_length);
    if (template == NULL) {
        PRINTF("finalize cs: no template for instruction, refusing to sign\n");
        return -1;
    }
    result->template = template;
    result->resolved_count = template->display_field_count;

    size_t field_count = template->display_field_count;
    if (field_count > 0) {
        if (!APP_MEM_CALLOC((void **) &result->resolved,
                            field_count * sizeof(*result->resolved)) ||
            !APP_MEM_CALLOC((void **) &result->field_mint,
                            field_count * sizeof(*result->field_mint))) {
            PRINTF("finalize cs: result array allocation failed\n");
            return -1;
        }
    }

    idl_match_path_t *argument_paths = NULL;
    size_t *argument_indices = NULL;
    idl_resolved_leaf_t *walker_results = NULL;
    int rc = 0;
    if (field_count > 0) {
        if (!APP_MEM_CALLOC((void **) &argument_paths,
                            field_count * sizeof(*argument_paths)) ||
            !APP_MEM_CALLOC((void **) &argument_indices,
                            field_count * sizeof(*argument_indices)) ||
            !APP_MEM_CALLOC((void **) &walker_results,
                            field_count * sizeof(*walker_results))) {
            PRINTF("finalize cs: walk scratch allocation failed\n");
            rc = -1;
        }
    }
    if (rc == 0) {
        rc = walk_instruction_inner(cs_tx,
                                    header,
                                    instruction,
                                    program_id,
                                    template,
                                    result,
                                    argument_paths,
                                    argument_indices,
                                    walker_results,
                                    bindings,
                                    binding_count);
    }

    // Free scratch in reverse order of allocation; NULL-safe when field_count is 0.
    if (walker_results != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &walker_results);
    }
    if (argument_indices != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &argument_indices);
    }
    if (argument_paths != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &argument_paths);
    }
    return rc;
}

// Walk every transaction instruction against the IDL type pool of its matching
// template, collecting the display-field leaf values into per-instruction
// results for the merge engine. Every instruction must resolve to a template.
static int walk_transaction(const cs_transaction_t *cs_tx,
                            cs_instruction_result_t *walked_instructions,
                            size_t *walked_instructions_count,
                            mint_binding_t *bindings) {
    Parser parser = {cs_tx->transaction, cs_tx->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("finalize cs: failed to parse buffered transaction\n");
        return -1;
    }

    *walked_instructions_count = 0;

    // Transaction-scoped mint-binding map (caller-owned, sized to the instruction
    // count), seeded from each instruction's MINT_ASSOC pair and queried below.
    size_t binding_count = 0;

    for (size_t i = 0; i < header.instructions_length; i++) {
        Instruction instruction;
        if (parse_instruction(&parser, &instruction) != 0) {
            PRINTF("finalize cs: failed to parse instruction %d\n", (int) i);
            return -1;
        }
        if (instruction.program_id_index >= header.pubkeys_header.pubkeys_length) {
            PRINTF("finalize cs: instruction %d program id index out of range\n", (int) i);
            return -1;
        }
        const uint8_t *program_id = header.pubkeys[instruction.program_id_index].data;

        cs_instruction_result_t *result = &walked_instructions[*walked_instructions_count];
        if (walk_instruction(cs_tx, &header, &instruction, program_id, result, bindings,
                             &binding_count) != 0) {
            PRINTF("finalize cs: instruction %d walk failed\n", (int) i);
            return -1;
        }
        (*walked_instructions_count)++;
    }

    // Second pass: with every MINT_ASSOC binding collected, resolve each token
    // reference to the mint that identifies its token (binding map, then the
    // TOKEN_ACCOUNT_STATE cache, then the reference itself).
    for (size_t i = 0; i < *walked_instructions_count; i++) {
        for (size_t f = 0; f < walked_instructions[i].resolved_count; f++) {
            if (walked_instructions[i].field_mint[f] != NULL) {
                walked_instructions[i].field_mint[f] =
                    resolve_field_mint(bindings,
                                       binding_count,
                                       walked_instructions[i].field_mint[f]);
            }
        }
    }
    return 0;
}

// Free the result-owned arrays of every walked-instruction slot. Safe over the
// whole calloc'd array: unpopulated slots hold NULL pointers.
static void free_walked_instructions(cs_instruction_result_t *walked_instructions, size_t count) {
    if (walked_instructions == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        if (walked_instructions[i].field_mint != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].field_mint);
        }
        if (walked_instructions[i].resolved != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].resolved);
        }
    }
}

// Walk, merge and render the transaction into the display buffer. The three walk
// buffers are caller-owned (allocated and freed by the outer handler). Returns
// the APDU status word to send.
static uint16_t finalize_cs_run(const cs_transaction_t *cs_tx,
                                cs_instruction_result_t *walked_instructions,
                                bool *survivors,
                                mint_binding_t *bindings) {
    size_t walked_instructions_count = 0;
    if (walk_transaction(cs_tx, walked_instructions, &walked_instructions_count, bindings) != 0) {
        PRINTF("finalize cs: walk engine failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    if (cs_merge_engine_run(walked_instructions, walked_instructions_count, survivors) != 0) {
        PRINTF("finalize cs: merge engine failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    if (cs_display_renderer_run(walked_instructions, walked_instructions_count, survivors) != 0) {
        PRINTF("finalize cs: display renderer failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    return ApduReplySuccess;
}

int handle_finalize_generic_clear_signing(void) {
    PRINTF("handle_finalize_generic_clear_signing\n");

    int state_err = cs_check_state(CS_SESSION_STREAMING);
    if (state_err != 0) {
        return reply_sw(state_err);
    }

    if (G_command.instruction != InsFinalizeGenericClearSigning ||
        G_command.state != ApduStatePayloadComplete) {
        return reply_sw(ApduReplySdkInvalidParameter);
    }

    const cs_transaction_t *cs_tx = cs_transaction_get();
    if (cs_tx == NULL) {
        PRINTF("finalize cs: no clear-signing context\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (cs_instruction_template_pending()) {
        PRINTF("finalize cs: an instruction template was never completed\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (cs_instruction_template_committed_count() == 0) {
        PRINTF("finalize cs: no instruction templates provided\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }

    // Size the walk buffers to the real instruction count, bounded only by the
    // wire transaction and the pool. An empty transaction has nothing to sign.
    Parser parser = {cs_tx->transaction, cs_tx->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0 || header.instructions_length == 0) {
        PRINTF("finalize cs: bad or empty transaction header\n");
        return reply_sw(ApduReplySolanaClearSigningIncomplete);
    }
    size_t instruction_count = header.instructions_length;

    cs_instruction_result_t *walked_instructions = NULL;
    bool *survivors = NULL;
    mint_binding_t *bindings = NULL;
    bool alloc_ok =
        APP_MEM_CALLOC((void **) &walked_instructions,
                       instruction_count * sizeof(*walked_instructions)) &&
        APP_MEM_CALLOC((void **) &survivors, instruction_count * sizeof(*survivors)) &&
        APP_MEM_CALLOC((void **) &bindings, instruction_count * sizeof(*bindings));

    uint16_t sw;
    if (!alloc_ok) {
        PRINTF("finalize cs: walk buffer allocation failed\n");
        sw = ApduReplySolanaClearSigningIncomplete;
    } else {
        sw = finalize_cs_run(cs_tx, walked_instructions, survivors, bindings);
    }

    // Free in strict reverse order of allocation; each guard tolerates a NULL from
    // a short-circuited allocation above.
    if (bindings != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &bindings);
    }
    if (survivors != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &survivors);
    }
    if (walked_instructions != NULL) {
        free_walked_instructions(walked_instructions, instruction_count);
        APP_MEM_FREE_AND_NULL((void **) &walked_instructions);
    }

    // On success the session survives to PROMPT UI DISPLAY; on error reply_sw abandons it.
    if (sw == ApduReplySuccess) {
        G_cs_session_state = CS_SESSION_FINALIZED;
    }
    return reply_sw(sw);
}
