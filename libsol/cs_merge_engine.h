#pragma once

// Merge engine for clear signing.
//
// Receives the per-instruction resolved leaf values and reduces the transaction to the
// intent the user reviews, over three stages run in order:
//
//   - Annotate: each port's ACTIVE_WHEN predicates are evaluated; a port failing any
//     predicate is excluded, so the rest of the engine and the renderer behave as if that
//     port were never declared. Runs before the collapse scan, since it changes the port
//     set the scan sees.
//   - Merge (collapse): chains of value-flow legs that describe one movement are fused, so
//     the review shows the intent rather than the plumbing. Two rules apply at a junction,
//     the account both a downstream input port and an upstream output port name:
//       - exact relay: both legs carry the same concrete amount, so the upstream leg
//         provably passes its value through untouched.
//       - symbolic junction: at least one leg drains or fills a whole balance the device
//         cannot read from the instruction data. Collapsing is only sound when an
//         ACCOUNT_RESET establishes that balance and no unaccounted instruction deposited
//         into the account first, which the symbolic-junction guard checks.
//     The surviving instruction's junction ports are rewritten with the consumed
//     instruction's far-side ports, so the review shows the real endpoints and amount
//     instead of the intermediate account. That rewrite is why the walked instructions are
//     passed mutable: the display renderer reads the merged ports.
//   - Hide: each merge survivor is tested against its HIDE_RULEs, grouped by rule set
//     (AND within a set, OR across sets); a survivor whose rules pass is dropped from the
//     output so its plumbing does not reach the screen.
//
// The pipeline this implements also drops described instructions that resolve to no
// ports and carry no intent. That stage has no effect here: an operation type is a
// required INSTRUCTION_INFO field, so every committed template carries an intent.
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
    // Set by the Annotate stage when an ACTIVE_WHEN predicate excludes the port, so every
    // later stage and the renderer treat it as never declared. Zero-initialised, so a port
    // with no ACTIVE_WHEN, and any port before annotation runs, is included.
    bool excluded;
    const uint8_t *account;    // resolved port account, or NULL
    uint8_t account_index;     // accounts-array slot `account` resolved to
    uint8_t value_kind;        // enum cs_port_value_kind
    uint8_t amount_kind;       // enum cs_amount_kind
    const uint8_t *amount_le;  // little-endian amount bytes, or NULL
    size_t amount_size;
    uint8_t amount_leaf_kind;  // IDL kind of the amount leaf
    // A BALANCE amount the engine could not tie to a known balance: the device does
    // not know how much this leg moves. Set by the merge engine's balance pass, for
    // NUMERIC ports always false. A symbolic leg may only be collapsed under the
    // symbolic-junction guard.
    bool is_symbolic;
    uint8_t token_kind;   // enum cs_token_kind
    const uint8_t *mint;  // resolved mint pubkey, or NULL
} cs_resolved_port_t;

// Resolved form of one HIDE_RULE: the concrete target account.
typedef struct cs_resolved_hide_rule_s {
    const uint8_t *target;  // resolved target pubkey, or NULL
} cs_resolved_hide_rule_t;

// Resolved form of one ACCOUNT_RESET: the concrete account and the balance it declares.
typedef struct cs_resolved_reset_s {
    const uint8_t *account;  // resolved reset account, or NULL
    // False when the descriptor carried no RESET_VALUE, which declares zero rather than
    // leaving the balance unknown.
    bool has_amount;
    const uint8_t *amount_le;  // little-endian amount bytes, or NULL
    size_t amount_size;
    uint8_t amount_leaf_kind;
} cs_resolved_reset_t;

// Per-instruction walk result: the template that matched and the resolved
// display-field leaf values plus the resolved merge-engine substructures.
typedef struct cs_instruction_result_s {
    const cs_instruction_template_t *template;
    // Raw instruction data, borrowed from the buffered transaction. Read by the
    // merge engine to match a RESET_SCOPE discriminator prefix.
    const uint8_t *instruction_data;
    size_t instruction_data_size;
    // Every writable account of the instruction's raw account list that resolved to a
    // concrete pubkey, in slot order. The guards read this rather than the ports, so a
    // write no descriptor declared still counts.
    const uint8_t **writable_accounts;  // heap, owned by the finalize walk
    size_t writable_account_count;
    // False when some writable slot could not be resolved, which happens for an
    // ALT-loaded account with no attested resolution. The list is then a subset of the
    // real one, so the instruction has to be treated as touching anything.
    bool writable_complete;
    // Every account of the instruction's raw account list that resolved to a concrete
    // pubkey, in slot order, writable or not. accountUsedElsewhere reads it to prove an
    // address appears outside the current instruction even when no port declares it.
    const uint8_t **accounts;  // heap, owned by the finalize walk
    size_t account_count;
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
    // Resolved MINT_ASSOC pair, borrowed from the buffered transaction. The hide stage reads it
    // to learn the mint this instruction binds its token account to.
    bool has_resolved_mint_assoc;
    const uint8_t *mint_assoc_token_account;
    const uint8_t *mint_assoc_mint;
    // Resolved OWNER_ASSOC pair, borrowed from the buffered transaction. The hide stage reads it
    // to learn the owner this instruction binds its token account to.
    bool has_resolved_owner_assoc;
    const uint8_t *owner_assoc_token_account;
    const uint8_t *owner_assoc_owner;
} cs_instruction_result_t;

// One transaction-scoped token-account -> owner binding, seeded from OWNER_ASSOC.
typedef struct cs_owner_binding_s {
    const uint8_t *token_account;
    const uint8_t *owner;
} cs_owner_binding_t;

// Facts about the transaction as a whole, which no single instruction result carries.
// Read by the Annotate and Hide stages to evaluate the shared condition vocabulary.
typedef struct cs_merge_context_s {
    const MessageHeader *header;  // signer set and account keys
    // The device user's own signing key, derived from the session derivation path. isSigner
    // and isAnotherSigner match against it specifically, never the fee payer or another
    // signer. NULL when the session carries no derivation path.
    const uint8_t *device_signer;
    const cs_owner_binding_t *owner_bindings;
    size_t owner_binding_count;
} cs_merge_context_t;

// Run the merge engine over the walked instructions. Fills survivors[i] = true for each
// instruction that should be displayed, and rewrites the junction ports of the survivors
// with the endpoints and amounts propagated from the instructions they absorbed.
// Returns 0 on success, -1 on failure.
int cs_merge_engine_run(cs_instruction_result_t *walked_instructions,
                        size_t walked_instructions_count,
                        const cs_merge_context_t *context,
                        bool *survivors);
