#pragma once

// Merge engine for clear signing.
//
// Receives the per-instruction resolved leaf values and decides which
// instructions survive (MVP: all survive). Value-flow port matching and
// hide-rule evaluation will be added here later.
//
// Output is a caller-provided bool array: survivors[i] == true means
// walked_instructions[i] should be rendered.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "idl_walker.h"
#include "cs_instruction_template.h"
#include "sol/parser.h"

// Resolved form of one VALUE_FLOW_PORT, produced by the finalize walk. Concrete
// values mirror the descriptor port in cs_value_flow_port_t. Borrowed pointers
// reference the buffered transaction / ALT cache / token-account cache / template.
typedef struct cs_resolved_port_s {
    bool resolved;             // account candidate resolved to a concrete pubkey
    const uint8_t *account;    // resolved port account, or NULL
    uint8_t value_kind;        // enum cs_port_value_kind
    uint8_t amount_kind;       // enum cs_amount_kind
    const uint8_t *amount_le;  // little-endian amount bytes (NUMERIC only), or NULL
    size_t amount_size;
    uint8_t amount_leaf_kind;  // IDL kind of the amount leaf
    uint8_t token_kind;        // enum cs_token_kind
    const uint8_t *mint;       // resolved mint pubkey, or NULL
} cs_resolved_port_t;

// Resolved form of one HIDE_RULE: the concrete target account.
typedef struct cs_resolved_hide_rule_s {
    const uint8_t *target;  // resolved target pubkey, or NULL
} cs_resolved_hide_rule_t;

// Resolved form of one ACCOUNT_RESET: the concrete account and reset amount.
typedef struct cs_resolved_reset_s {
    const uint8_t *account;    // resolved reset account, or NULL
    bool has_amount;
    const uint8_t *amount_le;  // little-endian amount bytes, or NULL
    size_t amount_size;
    uint8_t amount_leaf_kind;
} cs_resolved_reset_t;

// Per-instruction walk result: the template that matched and the resolved
// display-field leaf values plus the resolved merge-engine substructures.
typedef struct cs_instruction_result_s {
    const cs_instruction_template_t *template;
    idl_resolved_leaf_t *resolved;  // heap, sized to resolved_count; owned by the finalize walk
    size_t resolved_count;
    // Per display-field resolved mint pubkey, heap array sized to resolved_count,
    // indexed like `resolved`. Non-NULL entry only for TOKEN_AMOUNT fields whose
    // TOKEN reference resolved to a mint.
    const uint8_t **field_mint;
    // Parallel resolved arrays, sized to the template's port / hide_rule /
    // account_reset counts. Owned by the finalize walk.
    cs_resolved_port_t *resolved_ports;
    size_t resolved_port_count;
    cs_resolved_hide_rule_t *resolved_hide_rules;
    size_t resolved_hide_rule_count;
    cs_resolved_reset_t *resolved_resets;
    size_t resolved_reset_count;
} cs_instruction_result_t;

// One transaction-scoped token-account -> owner binding, seeded from OWNER_ASSOC.
typedef struct cs_owner_binding_s {
    const uint8_t *token_account;
    const uint8_t *owner;
} cs_owner_binding_t;

// Transaction-global inputs the merge engine cannot derive from a single result:
// the parsed message header (signer set + account keys) and the owner-binding map.
typedef struct cs_merge_context_s {
    const MessageHeader *header;
    const cs_owner_binding_t *owner_bindings;
    size_t owner_binding_count;
} cs_merge_context_t;

// Run the merge engine on walked instructions. Fills survivors[i] = true for
// each instruction that should be displayed. Returns 0 on success, -1 on failure.
int cs_merge_engine_run(const cs_instruction_result_t *walked_instructions,
                        size_t walked_instructions_count,
                        const cs_merge_context_t *context,
                        bool *survivors);
