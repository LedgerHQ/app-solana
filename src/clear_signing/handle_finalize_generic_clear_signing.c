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
#include "sol/printer.h"
#include "compute_budget_instruction.h"
#include "idl_pool.h"
#include "idl_walker.h"
#include "idl_kinds.h"
#include "sol/pubkey.h"
#include "utils.h"

// What the transaction fee needs from the ComputeBudget instructions, collected
// by value so the pointer-based ComputeBudgetFeeInfo can be built at the append
// site without dangling into a freed frame. ComputeBudget instructions carry no
// clear-signing template and are excluded from the descriptor walk; this is how
// their fee effect still reaches the user.
typedef struct cs_compute_budget_summary_s {
    bool present;
    bool has_unit_limit;
    ComputeBudgetChangeUnitLimitInfo unit_limit;
    bool has_unit_price;
    ComputeBudgetChangeUnitPriceInfo unit_price;
    size_t signatures_count;
} cs_compute_budget_summary_t;

// One entry of the transaction-scoped mint-binding map: a token account pubkey
// bound to the mint pubkey that identifies its token. Seeded from every
// instruction template's MINT_ASSOC association. Pointers reference the buffered
// transaction, which outlives the walk.
typedef struct mint_binding_s {
    const uint8_t *token_account;
    const uint8_t *mint;
} mint_binding_t;

// Look up the mint that identifies a token reference (a token account) through
// the MINT_ASSOC bindings first, then the chain-attested TOKEN_ACCOUNT_STATE
// cache. Returns NULL when neither source covers the reference.
static const uint8_t *lookup_mint_binding(const mint_binding_t *bindings,
                                          size_t binding_count,
                                          const uint8_t *token_ref) {
    for (size_t b = 0; b < binding_count; b++) {
        if (memcmp(bindings[b].token_account, token_ref, PUBKEY_SIZE) == 0) {
            return bindings[b].mint;
        }
    }
    const cs_token_account_t *entry = cs_token_account_cache_find(token_ref);
    if (entry != NULL) {
        return entry->mint;
    }
    return NULL;
}

// Resolve a 32-byte token reference (a token account or a mint) to the mint that
// identifies its token, per spec "Token amount metadata resolution": the
// MINT_ASSOC bindings take priority, then the chain-attested TOKEN_ACCOUNT_STATE
// cache, and finally the reference is treated as the mint itself.
static const uint8_t *resolve_field_mint(const mint_binding_t *bindings,
                                         size_t binding_count,
                                         const uint8_t *token_ref) {
    const uint8_t *mint = lookup_mint_binding(bindings, binding_count, token_ref);
    if (mint != NULL) {
        return mint;
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
                                                 size_t account_index) {
    if (account_index >= instruction->accounts_length) {
        PRINTF("finalize cs: account_index %d out of range (%d)\n",
               (int) account_index,
               (int) instruction->accounts_length);
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

// Resolve which of an instruction's accounts it may write, for the merge guards to reason
// over. Returns 0, -1 on allocation failure.
static int collect_writable_accounts(const cs_transaction_t *cs_tx,
                                     const MessageHeader *header,
                                     const Instruction *instruction,
                                     size_t alt_writable_count,
                                     cs_instruction_result_t *result) {
    result->writable_complete = true;
    if (instruction->accounts_length == 0) {
        PRINTF("finalize cs: instruction has no accounts, no writable list\n");
        return 0;
    }
    // Sized to every slot, since how many are writable is only known while walking them.
    if (!APP_MEM_CALLOC((void **) &result->writable_accounts,
                        instruction->accounts_length * sizeof(*result->writable_accounts))) {
        PRINTF("finalize cs: writable account list allocation failed\n");
        return -1;
    }

    // The raw account list is walked, not the descriptor's ports: a write the descriptor
    // never mentioned is exactly what the guards need to see.
    for (size_t slot = 0; slot < instruction->accounts_length; slot++) {
        if (!pubkey_index_is_writable(header, alt_writable_count, instruction->accounts[slot])) {
            continue;
        }
        const uint8_t *pubkey = pubkey_from_account_index(cs_tx, header, instruction, slot);
        // An ALT-loaded account with no attested resolution cannot be named, so the list
        // is recorded as partial instead of quietly missing an entry.
        if (pubkey == NULL) {
            PRINTF("finalize cs: writable slot %d unresolved, list marked incomplete\n",
                   (int) slot);
            result->writable_complete = false;
            continue;
        }
        result->writable_accounts[result->writable_account_count] = pubkey;
        result->writable_account_count++;
    }
    PRINTF("finalize cs: %d writable accounts collected, complete=%d\n",
           (int) result->writable_account_count,
           result->writable_complete);
    return 0;
}

// Resolve every account of an instruction's raw account list that can be named, so the
// condition vocabulary can prove an address appears outside its own instruction even when
// no port declares it. Returns 0, -1 on allocation failure.
static int collect_all_accounts(const cs_transaction_t *cs_tx,
                                const MessageHeader *header,
                                const Instruction *instruction,
                                cs_instruction_result_t *result) {
    if (instruction->accounts_length == 0) {
        PRINTF("finalize cs: instruction has no accounts, no raw list\n");
        return 0;
    }
    if (!APP_MEM_CALLOC((void **) &result->accounts,
                        instruction->accounts_length * sizeof(*result->accounts))) {
        PRINTF("finalize cs: raw account list allocation failed\n");
        return -1;
    }
    for (size_t slot = 0; slot < instruction->accounts_length; slot++) {
        const uint8_t *pubkey = pubkey_from_account_index(cs_tx, header, instruction, slot);
        // An ALT-loaded account with no attested resolution cannot be named; leaving it out
        // only makes accountUsedElsewhere miss it, which errs toward showing more.
        if (pubkey == NULL) {
            PRINTF("finalize cs: raw account slot %d unresolved, skipped\n", (int) slot);
            continue;
        }
        result->accounts[result->account_count] = pubkey;
        result->account_count++;
    }
    PRINTF("finalize cs: %d raw accounts collected\n", (int) result->account_count);
    return 0;
}

// Where an ARGUMENT_PATH walker result must be scattered after the single walk.
enum walk_scatter_kind {
    WALK_SCATTER_DISPLAY_FIELD,
    WALK_SCATTER_PORT_AMOUNT,
    WALK_SCATTER_PORT_MINT,
    WALK_SCATTER_RESET_AMOUNT,
    WALK_SCATTER_HIDE_TARGET,
    WALK_SCATTER_OWNER,
};

typedef struct walk_scatter_target_s {
    uint8_t kind;   // enum walk_scatter_kind
    size_t index;   // display field / port / reset / hide-rule index (unused for OWNER)
} walk_scatter_target_t;

// Register one ARGUMENT_PATH VALUE path into the walker match set, recording where
// its result is scattered. Returns 0, -1 when the path length is out of range.
static int match_set_register(idl_match_path_t *paths,
                              walk_scatter_target_t *targets,
                              size_t *count,
                              const uint8_t *path,
                              size_t path_size,
                              uint8_t kind,
                              size_t index) {
    if (path_size == 0 || path_size > UINT8_MAX) {
        PRINTF("finalize cs: argument path size %d out of range\n", (int) path_size);
        return -1;
    }
    paths[*count].path = path;
    paths[*count].path_size = (uint8_t) path_size;
    targets[*count].kind = kind;
    targets[*count].index = index;
    (*count)++;
    return 0;
}

// Resolve the port's ACCOUNT_INDEX candidate list to one concrete account, per
// spec "Account resolution": scan in order, skipping a non-final candidate that
// is out of range or (PROGRAM_ID strategy) whose slot holds the program id; the
// final candidate always resolves. On success writes the winning slot to
// `*out_index` and returns its pubkey; returns NULL when no candidate resolves.
static const uint8_t *resolve_port_account(const cs_transaction_t *cs_tx,
                                           const MessageHeader *header,
                                           const Instruction *instruction,
                                           const cs_value_flow_port_t *port,
                                           uint8_t *out_index) {
    for (size_t c = 0; c < port->candidate_count; c++) {
        bool is_final = (c + 1 == port->candidate_count);
        if (port->account_candidates[c] >= instruction->accounts_length) {
            if (is_final) {
                PRINTF("finalize cs: final port candidate index out of range\n");
                return NULL;
            }
            continue;
        }
        // In range but unresolved means an ALT-loaded account with no attested
        // resolution: a provided candidate we cannot resolve, so refuse rather
        // than skip to a later/default candidate.
        const uint8_t *pubkey =
            pubkey_from_account_index(cs_tx, header, instruction, port->account_candidates[c]);
        if (pubkey == NULL) {
            PRINTF("finalize cs: in-range port candidate unresolved, refusing to sign\n");
            return NULL;
        }
        if (!is_final &&
            port->optional_account_strategy == CS_OPTIONAL_ACCOUNT_STRATEGY_PROGRAM_ID &&
            memcmp(pubkey, header->pubkeys[instruction->program_id_index].data, PUBKEY_SIZE) == 0) {
            continue;
        }
        *out_index = port->account_candidates[c];
        return pubkey;
    }
    PRINTF("finalize cs: port has no resolvable account candidate\n");
    return NULL;
}

// Resolve a non-ARGUMENT_PATH VALUE that must yield a 32-byte pubkey. ARGUMENT_PATH
// is handled through the walker instead. Returns the pubkey or NULL on error.
static const uint8_t *resolve_pubkey_value_direct(const cs_transaction_t *cs_tx,
                                                  const MessageHeader *header,
                                                  const Instruction *instruction,
                                                  const cs_stored_value_t *value) {
    if (value->source == CS_VALUE_SOURCE_ACCOUNT_PATH) {
        if (value->payload_size != 1) {
            PRINTF("finalize cs: pubkey ACCOUNT_PATH payload size %d != 1\n",
                   (int) value->payload_size);
            return NULL;
        }
        return pubkey_from_account_index(cs_tx, header, instruction, value->payload[0]);
    } else if (value->source == CS_VALUE_SOURCE_CONSTANT) {
        if (value->payload_size != 32) {
            PRINTF("finalize cs: pubkey CONSTANT payload size %d != 32\n",
                   (int) value->payload_size);
            return NULL;
        }
        return value->payload;
    }
    PRINTF("finalize cs: unexpected pubkey VALUE source %d\n", value->source);
    return NULL;
}

// Work out how wide a literal amount embedded in a descriptor is. Returns 0, -1.
//
// An ARGUMENT_PATH amount carries its width in the IDL type pool, but a CONSTANT one has
// no kind of its own, leaving its byte count as the only thing that says. The bytes are
// then read little-endian like every other number embedded in a descriptor; the format
// does not state the byte order, so anything wider than one byte rests on that convention.
static int constant_amount_leaf_kind(size_t payload_size, uint8_t *out_kind) {
    // The substructure parser turns away any other length, so a stored template only ever
    // holds a usable one and this guards data already checked.
    if (idl_unsigned_kind_for_width(payload_size, out_kind) != 0) {
        PRINTF("finalize cs: constant amount size %d is not an integer width\n",
               (int) payload_size);
        return -1;
    }
    return 0;
}

// Read out an amount the descriptor states outright, rather than one it points into the
// instruction data for. Returns 0, -1.
static int resolve_amount_value_direct(const cs_stored_value_t *value,
                                       const uint8_t **out_bytes,
                                       size_t *out_size,
                                       uint8_t *out_kind) {
    // Only a CONSTANT gets this far. An ACCOUNT_PATH would resolve to an address, which is
    // not a number, and the substructure parser turns those away on arrival.
    if (value->source != CS_VALUE_SOURCE_CONSTANT) {
        PRINTF("finalize cs: unexpected amount VALUE source %d\n", value->source);
        return -1;
    }
    if (constant_amount_leaf_kind(value->payload_size, out_kind) != 0) {
        return -1;
    }
    *out_bytes = value->payload;
    *out_size = value->payload_size;
    return 0;
}

// Whether a leaf reached through the instruction data can serve as an amount.
static bool amount_leaf_kind_is_readable(uint8_t kind) {
    // A path landing on a pubkey, a string, or a width past the decoders yields bytes no
    // comparison can use. Refusing here beats carrying a port whose amount is beyond
    // checking, and matches what the renderer already does with such a leaf.
    size_t width = 0;
    if (idl_unsigned_kind_width(kind, &width) != 0) {
        PRINTF("finalize cs: amount leaf kind %d is not a readable integer\n", kind);
        return false;
    }
    return true;
}

// Resolve everything local to one port except ARGUMENT_PATH values (filled by the
// walker scatter) and the RESOLVE mint (deferred to the binding second pass).
static int resolve_port_local(const cs_transaction_t *cs_tx,
                              const MessageHeader *header,
                              const Instruction *instruction,
                              const cs_value_flow_port_t *port,
                              cs_resolved_port_t *out) {
    out->value_kind = port->value_kind;
    out->amount_kind = port->amount.kind;
    if (port->has_token) {
        out->token_kind = port->token.kind;
    } else {
        out->token_kind = CS_TOKEN_KIND_NULL;
    }

    const uint8_t *account =
        resolve_port_account(cs_tx, header, instruction, port, &out->account_index);
    if (account == NULL) {
        return -1;
    }
    out->account = account;
    out->resolved = true;

    if (port->amount.kind == CS_AMOUNT_KIND_NUMERIC && port->amount.has_value &&
        port->amount.value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        if (resolve_amount_value_direct(&port->amount.value,
                                        &out->amount_le,
                                        &out->amount_size,
                                        &out->amount_leaf_kind) != 0) {
            return -1;
        }
    }

    // DIRECT non-ARGUMENT_PATH mint resolves now; RESOLVE waits for the binding
    // map (second pass); ARGUMENT_PATH mint is filled by the walker scatter.
    if (port->has_token && port->token.kind == CS_TOKEN_KIND_DIRECT && port->token.has_value &&
        port->token.value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        const uint8_t *mint =
            resolve_pubkey_value_direct(cs_tx, header, instruction, &port->token.value);
        if (mint == NULL) {
            return -1;
        }
        out->mint = mint;
    }
    return 0;
}

// Resolve everything local to one account reset (ARGUMENT_PATH amount deferred to
// the walker scatter). Returns 0, -1 on error.
static int resolve_reset_local(const cs_transaction_t *cs_tx,
                              const MessageHeader *header,
                              const Instruction *instruction,
                              const cs_account_reset_t *reset,
                              cs_resolved_reset_t *out) {
    const uint8_t *account =
        pubkey_from_account_index(cs_tx, header, instruction, reset->account_index);
    if (account == NULL) {
        return -1;
    }
    out->account = account;
    if (reset->has_reset_value && reset->reset_value.has_value &&
        reset->reset_value.value.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
        if (resolve_amount_value_direct(&reset->reset_value.value,
                                        &out->amount_le,
                                        &out->amount_size,
                                        &out->amount_leaf_kind) != 0) {
            return -1;
        }
        out->has_amount = true;
    }
    return 0;
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
                                  walk_scatter_target_t *scatter_targets,
                                  idl_resolved_leaf_t *walker_results,
                                  mint_binding_t *bindings,
                                  size_t *binding_count,
                                  cs_owner_binding_t *owner_bindings,
                                  size_t *owner_binding_count) {
    if (idl_pool_provide(template->idl_type_pool,
                         template->idl_type_pool_size,
                         template->idl_root_type) != 0) {
        PRINTF("finalize cs: idl pool load failed\n");
        return -1;
    }

    // Build the ARGUMENT_PATH match set from every ARGUMENT_PATH VALUE across the
    // display fields and the merge-engine substructures, recording each result's
    // scatter destination so a single walk resolves them all.
    size_t match_count = 0;
    int register_status = 0;
    for (size_t f = 0; f < template->display_field_count && register_status == 0; f++) {
        if (template->display_fields[f].source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
            register_status = match_set_register(argument_paths,
                                                 scatter_targets,
                                                 &match_count,
                                                 template->display_fields[f].argument.path,
                                                 template->display_fields[f].argument.path_size,
                                                 WALK_SCATTER_DISPLAY_FIELD,
                                                 f);
        }
    }
    for (size_t p = 0; p < template->port_count && register_status == 0; p++) {
        if (template->ports[p].amount.kind == CS_AMOUNT_KIND_NUMERIC &&
            template->ports[p].amount.has_value &&
            template->ports[p].amount.value.source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
            register_status = match_set_register(argument_paths,
                                                 scatter_targets,
                                                 &match_count,
                                                 template->ports[p].amount.value.payload,
                                                 template->ports[p].amount.value.payload_size,
                                                 WALK_SCATTER_PORT_AMOUNT,
                                                 p);
        }
        if (register_status == 0 && template->ports[p].has_token &&
            template->ports[p].token.kind == CS_TOKEN_KIND_DIRECT &&
            template->ports[p].token.has_value &&
            template->ports[p].token.value.source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
            register_status = match_set_register(argument_paths,
                                                 scatter_targets,
                                                 &match_count,
                                                 template->ports[p].token.value.payload,
                                                 template->ports[p].token.value.payload_size,
                                                 WALK_SCATTER_PORT_MINT,
                                                 p);
        }
    }
    for (size_t r = 0; r < template->account_reset_count && register_status == 0; r++) {
        if (template->account_resets[r].has_reset_value &&
            template->account_resets[r].reset_value.has_value &&
            template->account_resets[r].reset_value.value.source ==
                CS_VALUE_SOURCE_ARGUMENT_PATH) {
            register_status = match_set_register(argument_paths,
                                                 scatter_targets,
                                                 &match_count,
                                                 template->account_resets[r].reset_value.value.payload,
                                                 template->account_resets[r].reset_value.value.payload_size,
                                                 WALK_SCATTER_RESET_AMOUNT,
                                                 r);
        }
    }
    for (size_t h = 0; h < template->hide_rule_count && register_status == 0; h++) {
        if (template->hide_rules[h].target.source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
            register_status = match_set_register(argument_paths,
                                                 scatter_targets,
                                                 &match_count,
                                                 template->hide_rules[h].target.payload,
                                                 template->hide_rules[h].target.payload_size,
                                                 WALK_SCATTER_HIDE_TARGET,
                                                 h);
        }
    }
    if (register_status == 0 && template->has_owner_assoc &&
        template->owner_assoc_owner.source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
        register_status = match_set_register(argument_paths,
                                             scatter_targets,
                                             &match_count,
                                             template->owner_assoc_owner.payload,
                                             template->owner_assoc_owner.payload_size,
                                             WALK_SCATTER_OWNER,
                                             0);
    }
    if (register_status != 0) {
        idl_pool_reset();
        return -1;
    }

    size_t walker_resolved_count = 0;
    int walk_status = idl_walker_run(instruction->data,
                                     instruction->data_length,
                                     program_id,
                                     argument_paths,
                                     match_count,
                                     walker_results,
                                     &walker_resolved_count);
    idl_pool_reset();
    if (walk_status != 0) {
        PRINTF("finalize cs: walk failed\n");
        return -1;
    }

    // Scatter each walker result to its recorded destination. Pubkey-resolving
    // targets must reach a 32-byte publicKey leaf.
    const uint8_t *owner_walker_pubkey = NULL;
    for (size_t w = 0; w < match_count; w++) {
        size_t index = scatter_targets[w].index;
        switch (scatter_targets[w].kind) {
            case WALK_SCATTER_DISPLAY_FIELD:
                result->resolved[index] = walker_results[w];
                break;
            case WALK_SCATTER_PORT_AMOUNT:
                if (!amount_leaf_kind_is_readable(walker_results[w].kind)) {
                    PRINTF("finalize cs: port %d amount path reaches no readable integer\n",
                           (int) index);
                    return -1;
                }
                result->resolved_ports[index].amount_le = walker_results[w].value;
                result->resolved_ports[index].amount_size = walker_results[w].value_size;
                result->resolved_ports[index].amount_leaf_kind = walker_results[w].kind;
                break;
            case WALK_SCATTER_PORT_MINT:
                if (walker_results[w].kind != IDL_KIND_PUBKEY_32 ||
                    walker_results[w].value_size != 32) {
                    PRINTF("finalize cs: port %d DIRECT mint path is not a pubkey\n", (int) index);
                    return -1;
                }
                result->resolved_ports[index].mint = walker_results[w].value;
                break;
            case WALK_SCATTER_RESET_AMOUNT:
                if (!amount_leaf_kind_is_readable(walker_results[w].kind)) {
                    PRINTF("finalize cs: reset %d amount path reaches no readable integer\n",
                           (int) index);
                    return -1;
                }
                result->resolved_resets[index].amount_le = walker_results[w].value;
                result->resolved_resets[index].amount_size = walker_results[w].value_size;
                result->resolved_resets[index].amount_leaf_kind = walker_results[w].kind;
                result->resolved_resets[index].has_amount = true;
                break;
            case WALK_SCATTER_HIDE_TARGET:
                if (walker_results[w].kind != IDL_KIND_PUBKEY_32 ||
                    walker_results[w].value_size != 32) {
                    PRINTF("finalize cs: hide rule %d target path is not a pubkey\n", (int) index);
                    return -1;
                }
                result->resolved_hide_rules[index].target = walker_results[w].value;
                break;
            case WALK_SCATTER_OWNER:
                if (walker_results[w].kind != IDL_KIND_PUBKEY_32 ||
                    walker_results[w].value_size != 32) {
                    PRINTF("finalize cs: owner assoc path is not a pubkey\n");
                    return -1;
                }
                owner_walker_pubkey = walker_results[w].value;
                break;
            default:
                PRINTF("finalize cs: unknown scatter kind %d\n", scatter_targets[w].kind);
                return -1;
        }
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
        // The merge engine's accountEffectsDisplayedElsewhere reads the pair per instruction,
        // and the raw accounts list is compacted so it cannot recover them by slot index.
        result->has_resolved_mint_assoc = true;
        result->mint_assoc_token_account = token_account;
        result->mint_assoc_mint = mint;
    }

    // Resolve each port's local values (account, non-ARGUMENT_PATH amount and
    // DIRECT mint). RESOLVE mints wait for the transaction-wide binding map.
    for (size_t p = 0; p < template->port_count; p++) {
        if (resolve_port_local(cs_tx,
                               header,
                               instruction,
                               &template->ports[p],
                               &result->resolved_ports[p]) != 0) {
            PRINTF("finalize cs: port %d resolution failed\n", (int) p);
            return -1;
        }
    }

    // Resolve each account reset's local values.
    for (size_t r = 0; r < template->account_reset_count; r++) {
        if (resolve_reset_local(cs_tx,
                                header,
                                instruction,
                                &template->account_resets[r],
                                &result->resolved_resets[r]) != 0) {
            PRINTF("finalize cs: reset %d resolution failed\n", (int) r);
            return -1;
        }
    }

    // Resolve non-ARGUMENT_PATH hide-rule targets (ARGUMENT_PATH filled above).
    for (size_t h = 0; h < template->hide_rule_count; h++) {
        if (template->hide_rules[h].target.source != CS_VALUE_SOURCE_ARGUMENT_PATH) {
            const uint8_t *target = resolve_pubkey_value_direct(cs_tx,
                                                                header,
                                                                instruction,
                                                                &template->hide_rules[h].target);
            if (target == NULL) {
                PRINTF("finalize cs: hide rule %d target resolution failed\n", (int) h);
                return -1;
            }
            result->resolved_hide_rules[h].target = target;
        }
    }

    // Seed the owner-binding map from this instruction's OWNER_ASSOC pair.
    if (template->has_owner_assoc) {
        const uint8_t *owner;
        if (template->owner_assoc_owner.source == CS_VALUE_SOURCE_ARGUMENT_PATH) {
            if (owner_walker_pubkey == NULL) {
                PRINTF("finalize cs: owner assoc argument path not resolved\n");
                return -1;
            }
            owner = owner_walker_pubkey;
        } else {
            owner = resolve_pubkey_value_direct(cs_tx,
                                                header,
                                                instruction,
                                                &template->owner_assoc_owner);
            if (owner == NULL) {
                return -1;
            }
        }
        const uint8_t *owner_token_account =
            pubkey_from_account_index(cs_tx, header, instruction, template->owner_assoc_account);
        if (owner_token_account == NULL) {
            PRINTF("finalize cs: owner assoc account index out of range\n");
            return -1;
        }
        owner_bindings[*owner_binding_count].token_account = owner_token_account;
        owner_bindings[*owner_binding_count].owner = owner;
        (*owner_binding_count)++;
        // The merge engine's accountEffectsDisplayedElsewhere reads the pair per instruction,
        // and the raw accounts list is compacted so it cannot recover them by slot index.
        result->has_resolved_owner_assoc = true;
        result->owner_assoc_token_account = owner_token_account;
        result->owner_assoc_owner = owner;
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
                            size_t alt_writable_count,
                            cs_instruction_result_t *result,
                            mint_binding_t *bindings,
                            size_t *binding_count,
                            cs_owner_binding_t *owner_bindings,
                            size_t *owner_binding_count) {
    const cs_instruction_template_t *template =
        cs_instruction_template_find(program_id, instruction->data, instruction->data_length);
    if (template == NULL) {
        PRINTF("finalize cs: no template for instruction, refusing to sign\n");
        return -1;
    }
    result->template = template;
    result->instruction_data = instruction->data;
    result->instruction_data_size = instruction->data_length;
    result->resolved_count = template->display_field_count;
    result->resolved_port_count = template->port_count;
    result->resolved_hide_rule_count = template->hide_rule_count;
    result->resolved_reset_count = template->account_reset_count;

    size_t field_count = template->display_field_count;
    bool alloc_ok = true;
    if (field_count > 0) {
        alloc_ok = APP_MEM_CALLOC((void **) &result->resolved,
                                  field_count * sizeof(*result->resolved)) &&
                   APP_MEM_CALLOC((void **) &result->field_mint,
                                  field_count * sizeof(*result->field_mint));
    }
    if (alloc_ok && template->port_count > 0) {
        alloc_ok = APP_MEM_CALLOC((void **) &result->resolved_ports,
                                  template->port_count * sizeof(*result->resolved_ports));
    }
    if (alloc_ok && template->hide_rule_count > 0) {
        alloc_ok = APP_MEM_CALLOC((void **) &result->resolved_hide_rules,
                                  template->hide_rule_count * sizeof(*result->resolved_hide_rules));
    }
    if (alloc_ok && template->account_reset_count > 0) {
        alloc_ok = APP_MEM_CALLOC((void **) &result->resolved_resets,
                                  template->account_reset_count * sizeof(*result->resolved_resets));
    }
    if (!alloc_ok) {
        PRINTF("finalize cs: result array allocation failed\n");
        return -1;
    }

    if (collect_writable_accounts(cs_tx, header, instruction, alt_writable_count, result) != 0) {
        return -1;
    }
    if (collect_all_accounts(cs_tx, header, instruction, result) != 0) {
        return -1;
    }

    // Scratch sized to the total possible ARGUMENT_PATH match count: display
    // fields, one per port amount and per port DIRECT mint, one per reset amount,
    // one per hide-rule target, and one owner-assoc owner.
    size_t max_paths = field_count + template->port_count * 2 + template->account_reset_count +
                       template->hide_rule_count + 1;
    idl_match_path_t *argument_paths = NULL;
    walk_scatter_target_t *scatter_targets = NULL;
    idl_resolved_leaf_t *walker_results = NULL;
    int rc = 0;
    if (!APP_MEM_CALLOC((void **) &argument_paths, max_paths * sizeof(*argument_paths)) ||
        !APP_MEM_CALLOC((void **) &scatter_targets, max_paths * sizeof(*scatter_targets)) ||
        !APP_MEM_CALLOC((void **) &walker_results, max_paths * sizeof(*walker_results))) {
        PRINTF("finalize cs: walk scratch allocation failed\n");
        rc = -1;
    }
    if (rc == 0) {
        rc = walk_instruction_inner(cs_tx,
                                    header,
                                    instruction,
                                    program_id,
                                    template,
                                    result,
                                    argument_paths,
                                    scatter_targets,
                                    walker_results,
                                    bindings,
                                    binding_count,
                                    owner_bindings,
                                    owner_binding_count);
    }

    // Free scratch in reverse order of allocation.
    if (walker_results != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &walker_results);
    }
    if (scatter_targets != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &scatter_targets);
    }
    if (argument_paths != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &argument_paths);
    }
    return rc;
}

// Resolve one instruction's RESOLVE-kind port token mints through the completed
// binding map: the map first, then the fallback account address, then the token
// reference treated as the mint itself. Returns 0, -1 on error.
static int resolve_port_mints_for_instruction(const cs_transaction_t *cs_tx,
                                              const MessageHeader *header,
                                              const Instruction *instruction,
                                              const cs_instruction_template_t *template,
                                              cs_resolved_port_t *resolved_ports,
                                              const mint_binding_t *bindings,
                                              size_t binding_count) {
    for (size_t p = 0; p < template->port_count; p++) {
        if (!template->ports[p].has_token ||
            template->ports[p].token.kind != CS_TOKEN_KIND_RESOLVE) {
            continue;
        }
        const uint8_t *token_ref;
        if (template->ports[p].token.has_account) {
            token_ref = pubkey_from_account_index(cs_tx,
                                                  header,
                                                  instruction,
                                                  template->ports[p].token.account_index);
        } else {
            token_ref = resolved_ports[p].account;
        }
        if (token_ref == NULL) {
            PRINTF("finalize cs: port %d RESOLVE token reference unresolved\n", (int) p);
            return -1;
        }
        const uint8_t *mint = lookup_mint_binding(bindings, binding_count, token_ref);
        if (mint == NULL && template->ports[p].token.has_fallback_account) {
            mint = pubkey_from_account_index(cs_tx,
                                             header,
                                             instruction,
                                             template->ports[p].token.fallback_account_index);
            if (mint == NULL) {
                PRINTF("finalize cs: port %d fallback account unresolved\n", (int) p);
                return -1;
            }
        }
        if (mint == NULL) {
            mint = token_ref;
        }
        resolved_ports[p].mint = mint;
    }
    return 0;
}

// Second pass over ports: resolve every RESOLVE-kind token mint now that the
// whole transaction's binding map is complete. Re-parses the buffered
// transaction for each instruction's account context. Returns 0, -1 on error.
static int resolve_port_mints(const cs_transaction_t *cs_tx,
                             cs_instruction_result_t *walked_instructions,
                             size_t count,
                             const mint_binding_t *bindings,
                             size_t binding_count) {
    Parser parser = {cs_tx->transaction, cs_tx->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("finalize cs: port mint pass header parse failed\n");
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        Instruction instruction;
        if (parse_instruction(&parser, &instruction) != 0) {
            PRINTF("finalize cs: port mint pass instruction %d parse failed\n", (int) i);
            return -1;
        }
        if (resolve_port_mints_for_instruction(cs_tx,
                                               &header,
                                               &instruction,
                                               walked_instructions[i].template,
                                               walked_instructions[i].resolved_ports,
                                               bindings,
                                               binding_count) != 0) {
            return -1;
        }
    }
    return 0;
}

// Parse one ComputeBudget instruction and fold the fee-relevant kinds into the
// running summary. Heap-frame and data-size kinds parse but contribute nothing
// to the fee. Returns 0, -1 on a malformed instruction (refuse rather than
// sign an unparseable ComputeBudget).
static int accumulate_compute_budget(const Instruction *instruction,
                                     const MessageHeader *header,
                                     cs_compute_budget_summary_t *summary) {
    ComputeBudgetInfo info;
    if (parse_compute_budget_instructions(instruction, header, &info) != 0) {
        PRINTF("finalize cs: malformed ComputeBudget instruction\n");
        return -1;
    }
    summary->present = true;
    summary->signatures_count = info.signatures_count;
    // Last writer wins on duplicates; the chain rejects duplicates anyway.
    if (info.kind == ComputeBudgetChangeUnitLimit) {
        summary->has_unit_limit = true;
        memcpy(&summary->unit_limit, &info.change_unit_limit, sizeof(summary->unit_limit));
    } else if (info.kind == ComputeBudgetChangeUnitPrice) {
        summary->has_unit_price = true;
        memcpy(&summary->unit_price, &info.change_unit_price, sizeof(summary->unit_price));
    }
    PRINTF("finalize cs: ComputeBudget kind=%d accumulated\n", (int) info.kind);
    return 0;
}

// Walk every transaction instruction against the IDL type pool of its matching
// template, collecting the display-field leaf values and resolved merge-engine
// substructures into per-instruction results. Seeds the caller-owned mint- and
// owner-binding maps. Every instruction must resolve to a template, except
// ComputeBudget instructions, which are excluded from the walk and folded into
// cb_summary for a later fee field.
static int walk_transaction(const cs_transaction_t *cs_tx,
                            cs_instruction_result_t *walked_instructions,
                            size_t *walked_instructions_count,
                            mint_binding_t *bindings,
                            cs_owner_binding_t *owner_bindings,
                            size_t *owner_binding_count,
                            cs_compute_budget_summary_t *cb_summary) {
    Parser parser = {cs_tx->transaction, cs_tx->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("finalize cs: failed to parse buffered transaction\n");
        return -1;
    }

    // Writable-block boundary of the ALT-loaded key range. Computed once here because
    // it depends on the whole message, then applied to every raw account index.
    size_t alt_writable_count = 0;
    if (message_alt_writable_count(cs_tx->transaction,
                                   cs_tx->transaction_size,
                                   &alt_writable_count) != 0) {
        PRINTF("finalize cs: ALT writable count failed\n");
        return -1;
    }

    *walked_instructions_count = 0;
    memset(cb_summary, 0, sizeof(*cb_summary));

    // Transaction-scoped binding maps (caller-owned, sized to the instruction
    // count), seeded from each instruction's MINT_ASSOC / OWNER_ASSOC pairs.
    size_t binding_count = 0;
    *owner_binding_count = 0;

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

        // ComputeBudget instructions carry no clear-signing template. Rather than
        // refuse (no template) or silence them, collect their fee effect and skip
        // them so the mint passes, merge engine and renderer keep their
        // non-NULL-template, 1:1-index invariants over the walked slots.
        if (memcmp(program_id, &compute_budget_program_id, PUBKEY_SIZE) == 0) {
            if (accumulate_compute_budget(&instruction, &header, cb_summary) != 0) {
                return -1;
            }
            continue;
        }

        cs_instruction_result_t *result = &walked_instructions[*walked_instructions_count];
        if (walk_instruction(cs_tx, &header, &instruction, program_id, alt_writable_count, result,
                             bindings, &binding_count, owner_bindings, owner_binding_count) != 0) {
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

    // Resolve RESOLVE-kind port token mints against the same completed map.
    if (resolve_port_mints(cs_tx, walked_instructions, *walked_instructions_count, bindings,
                           binding_count) != 0) {
        return -1;
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
        if (walked_instructions[i].writable_accounts != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].writable_accounts);
        }
        if (walked_instructions[i].accounts != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].accounts);
        }
        if (walked_instructions[i].resolved_resets != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].resolved_resets);
        }
        if (walked_instructions[i].resolved_hide_rules != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].resolved_hide_rules);
        }
        if (walked_instructions[i].resolved_ports != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].resolved_ports);
        }
        if (walked_instructions[i].field_mint != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].field_mint);
        }
        if (walked_instructions[i].resolved != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &walked_instructions[i].resolved);
        }
    }
}

// Append the aggregate "Max fees" field when a ComputeBudget unit price or limit
// was seen. Builds the pointer-based fee info from the by-value summary, reuses
// calculate_max_fee, and formats lamports as a SOL amount. Returns the APDU
// status word: success, or a refusal on fee overflow / format / append failure.
static uint16_t append_compute_budget_fee(cs_compute_budget_summary_t *summary,
                                          size_t instruction_count) {
    ComputeBudgetFeeInfo fee_info = {0};
    fee_info.instructions_count = instruction_count;
    fee_info.signatures_count = summary->signatures_count;
    // The fee info borrows the summary's own storage, which outlives this call.
    if (summary->has_unit_limit) {
        fee_info.change_unit_limit = &summary->unit_limit;
    }
    if (summary->has_unit_price) {
        fee_info.change_unit_price = &summary->unit_price;
    }

    uint64_t max_fee = 0;
    if (calculate_max_fee(&fee_info, &max_fee) != 0) {
        PRINTF("finalize cs: ComputeBudget fee calculation failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    // Same amount-string buffer sizing the transaction summary uses for print_amount.
    char fee_text[BASE58_PUBKEY_LENGTH];
    if (print_amount(max_fee, fee_text, sizeof(fee_text)) != 0) {
        PRINTF("finalize cs: ComputeBudget fee format failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    if (cs_display_renderer_append("Max fees", fee_text) != 0) {
        PRINTF("finalize cs: ComputeBudget fee field append failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    return ApduReplySuccess;
}

// Walk, merge and render the transaction into the display buffer. The three walk
// buffers are caller-owned (allocated and freed by the outer handler). Returns
// the APDU status word to send.
static uint16_t finalize_cs_run(const cs_transaction_t *cs_tx,
                                cs_instruction_result_t *walked_instructions,
                                bool *survivors,
                                mint_binding_t *bindings,
                                cs_owner_binding_t *owner_bindings) {
    size_t walked_instructions_count = 0;
    size_t owner_binding_count = 0;
    cs_compute_budget_summary_t cb_summary;
    if (walk_transaction(cs_tx, walked_instructions, &walked_instructions_count, bindings,
                         owner_bindings, &owner_binding_count, &cb_summary) != 0) {
        PRINTF("finalize cs: walk engine failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }

    // Parse the header for the merge context's signer set. Its pubkeys reference
    // the buffered transaction, which outlives the merge run.
    Parser parser = {cs_tx->transaction, cs_tx->transaction_size};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("finalize cs: merge context header parse failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    // Derive the device user's own signing key so isSigner and isAnotherSigner match against
    // it, never the fee payer. Lives on this stack frame, which outlives the merge run below.
    Pubkey device_signer;
    if (get_public_key(device_signer.data,
                       cs_tx->derivation_path,
                       cs_tx->derivation_path_length) != CX_OK) {
        PRINTF("finalize cs: device signer derivation failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    cs_merge_context_t context = {.header = &header,
                                  .device_signer = device_signer.data,
                                  .owner_bindings = owner_bindings,
                                  .owner_binding_count = owner_binding_count};
    if (cs_merge_engine_run(walked_instructions, walked_instructions_count, &context, survivors) !=
        0) {
        PRINTF("finalize cs: merge engine failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }
    if (cs_display_renderer_run(walked_instructions, walked_instructions_count, survivors) != 0) {
        PRINTF("finalize cs: display renderer failed\n");
        return ApduReplySolanaInvalidGenericPreview;
    }

    // A ComputeBudget unit price/limit contributes a transaction-level fee shown
    // as a last field, but only alongside at least one rendered instruction: a
    // fee-only transaction has no signable intent and stays refused (zero
    // elements -> PROMPT UI DISPLAY reports incomplete).
    if ((cb_summary.has_unit_limit || cb_summary.has_unit_price) &&
        cs_display_renderer_element_count() > 0) {
        uint16_t fee_sw = append_compute_budget_fee(&cb_summary, header.instructions_length);
        if (fee_sw != ApduReplySuccess) {
            return fee_sw;
        }
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
    cs_owner_binding_t *owner_bindings = NULL;
    bool alloc_ok =
        APP_MEM_CALLOC((void **) &walked_instructions,
                       instruction_count * sizeof(*walked_instructions)) &&
        APP_MEM_CALLOC((void **) &survivors, instruction_count * sizeof(*survivors)) &&
        APP_MEM_CALLOC((void **) &bindings, instruction_count * sizeof(*bindings)) &&
        APP_MEM_CALLOC((void **) &owner_bindings, instruction_count * sizeof(*owner_bindings));

    uint16_t sw;
    if (!alloc_ok) {
        PRINTF("finalize cs: walk buffer allocation failed\n");
        sw = ApduReplySolanaClearSigningIncomplete;
    } else {
        sw = finalize_cs_run(cs_tx, walked_instructions, survivors, bindings, owner_bindings);
    }

    // Free in strict reverse order of allocation; each guard tolerates a NULL from
    // a short-circuited allocation above.
    if (owner_bindings != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &owner_bindings);
    }
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
