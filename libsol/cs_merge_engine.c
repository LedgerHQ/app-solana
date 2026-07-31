#include <stdint.h>
#include <string.h>

#include "cs_merge_engine.h"
#include "cs_instruction_template.h"
#include "cs_token_account_cache.h"
#include "app_mem_utils.h"
#include "idl_kinds.h"
#include "sol/pubkey.h"
#include "os_print.h"
#include "util.h"

// Which collapse a junction supports, if any.
enum cs_merge_rule {
    CS_MERGE_RULE_NONE = 0,
    // Both legs declare the same concrete amount. Spec Rule 1.
    CS_MERGE_RULE_EXACT_RELAY,
    // At least one leg drains or fills a whole balance. Spec Rule 2.
    CS_MERGE_RULE_SYMBOLIC_JUNCTION,
};

// One ACCOUNT_RESET declaration, reduced to what the guard needs from it.
typedef struct safe_account_s {
    const uint8_t *account;
    // Instruction that declared the reset. The guard needs it twice: to check the reset
    // precedes the junction, and to exempt that instruction's own write of the account.
    size_t declarer_index;
    // Restricts which consumer may rely on the reset. NULL admits any consumer.
    const cs_reset_scope_t *scope;
} safe_account_t;

// A balance the device knows for an account. Entries live from the reset that declared
// them until an instruction writes the account, which ends the knowledge.
typedef struct known_balance_s {
    const uint8_t *account;
    const uint8_t *amount_le;
    size_t amount_size;
    uint8_t amount_leaf_kind;
} known_balance_t;

// What the merge run tracks about one instruction.
typedef struct merge_state_s {
    bool consumed;
    // Every instruction whose value flow this one now accounts for, itself included.
    // The guard reads it to tell a chain member from an unaccounted depositor.
    bool *merged_from;  // slice of the shared history block, indexed by instruction
} merge_state_t;

// Everything one merge run allocates, gathered so a single free path releases it all.
typedef struct merge_scratch_s {
    merge_state_t *states;
    bool *history;  // instruction_count * instruction_count block sliced by `states`
    safe_account_t *safe_accounts;
    size_t safe_account_count;
    known_balance_t *known_balances;
    size_t known_balance_count;
} merge_scratch_t;

// Stands in for the RESET_VALUE of a reset that carries none, which declares an
// implicit zero. Static so the known-balance map can borrow it like any other amount.
static const uint8_t G_implicit_zero_reset_le[8] = {0};

// Find the nth input or output port of an instruction. Returns its index in
// `resolved_ports`, or SIZE_MAX when the instruction has no such port.
static size_t nth_directional_port_index(const cs_instruction_result_t *item,
                                         uint8_t direction,
                                         size_t n) {
    // Inputs and outputs share one array in streaming order, so the nth port of a
    // direction is found by counting past the ports of the other one. The direction
    // lives on the template side; the resolved side is positionally identical.
    size_t seen = 0;
    for (size_t p = 0; p < item->resolved_port_count; p++) {
        // An ACTIVE_WHEN-excluded port is not a leg: the scan treats it as never declared.
        if (item->template->ports[p].direction == direction && !item->resolved_ports[p].excluded) {
            if (seen == n) {
                return p;
            }
            seen++;
        }
    }
    PRINTF("nth_directional_port_index: no port #%d of direction %d\n", (int) n, direction);
    return SIZE_MAX;
}

// Read the nth input or output port of an instruction. Returns NULL when it has none.
// Callers that need to write the port take the index variant instead.
static const cs_resolved_port_t *nth_directional_port(const cs_instruction_result_t *item,
                                                      uint8_t direction,
                                                      size_t n) {
    size_t index = nth_directional_port_index(item, direction, n);
    if (index == SIZE_MAX) {
        PRINTF("nth_directional_port: out of range\n");
        return NULL;
    }
    return &item->resolved_ports[index];
}

// Count how many input or output ports an instruction declares.
static size_t count_directional_ports(const cs_instruction_result_t *item, uint8_t direction) {
    size_t count = 0;
    for (size_t p = 0; p < item->resolved_port_count; p++) {
        // An ACTIVE_WHEN-excluded port is not counted: the scan treats it as never declared.
        if (item->template->ports[p].direction == direction && !item->resolved_ports[p].excluded) {
            count++;
        }
    }
    PRINTF("count_directional_ports: direction=%d count=%d\n", direction, (int) count);
    return count;
}

// Read an amount's raw bytes as a number. Returns 0, -1 when the kind is not an
// unsigned integer or the bytes are too few for it.
static int decode_le_amount(const uint8_t *amount_le,
                            size_t amount_size,
                            uint8_t leaf_kind,
                            uint64_t *out) {
    // The kind fixes the width, not the byte count: a leaf may sit inside a longer
    // buffer, so only the first `width` bytes belong to this amount.
    size_t width = 0;
    if (idl_unsigned_kind_width(leaf_kind, &width) != 0) {
        PRINTF("decode_le_amount: unsupported leaf kind=%d\n", leaf_kind);
        return -1;
    }
    if (amount_le == NULL || amount_size < width) {
        PRINTF("decode_le_amount: truncated (size=%d width=%d)\n", (int) amount_size, (int) width);
        return -1;
    }
    *out = 0;
    for (size_t i = 0; i < width; i++) {
        *out |= (uint64_t) amount_le[i] << (8 * i);
    }
    return 0;
}

// Whether a port names which token it moves.
static bool port_has_token(const cs_resolved_port_t *port) {
    // A descriptor states NULL when the port is a creation placeholder, which asserts no
    // token identity and so contradicts nothing another port claims.
    bool has_token = (port->token_kind != CS_TOKEN_KIND_NULL);
    PRINTF("port_has_token: token_kind=%d has_token=%d\n", port->token_kind, has_token);
    return has_token;
}

// Whether a port declares an account coming into existence rather than value moving.
// The depositor check uses it to let a creation step past.
static bool port_moves_no_value(const cs_resolved_port_t *port) {
    // Descriptors write that shape as a zero amount and no token. Either of those being
    // absent means value may well be moving, and so does an amount nothing can read.
    if (port_has_token(port) || port->is_symbolic) {
        return false;
    }
    uint64_t amount = 0;
    if (decode_le_amount(port->amount_le, port->amount_size, port->amount_leaf_kind, &amount) !=
        0) {
        PRINTF("port_moves_no_value: amount undecodable, assuming value moves\n");
        return false;
    }
    PRINTF("port_moves_no_value: amount is zero=%d\n", amount == 0);
    return amount == 0;
}

// Whether two junction legs can be carrying the same token.
static bool tokens_compatible(const cs_resolved_port_t *output_port,
                              const cs_resolved_port_t *input_port) {
    // An unresolved mint states no identity, so it contradicts none.
    if (output_port->mint == NULL || input_port->mint == NULL) {
        PRINTF("tokens_compatible: a mint unresolved, treated compatible\n");
        return true;
    }
    if (memcmp(output_port->mint, input_port->mint, PUBKEY_SIZE) != 0) {
        PRINTF("tokens_compatible: mint mismatch\n");
        return false;
    }
    return true;
}

// Whether two junction legs can be carrying the same value.
static bool value_kinds_compatible(uint8_t output_kind, uint8_t input_kind) {
    // Both defined kinds move fungible value between accounts, so a junction may
    // change form across them: a lamport deposit then a wrap reads the same account as
    // NATIVE then as SPL_TOKEN. Any other kind is unknown here and lines up with nothing.
    bool compatible = (output_kind == CS_PORT_VALUE_KIND_NATIVE ||
                       output_kind == CS_PORT_VALUE_KIND_SPL_TOKEN) &&
                      (input_kind == CS_PORT_VALUE_KIND_NATIVE ||
                       input_kind == CS_PORT_VALUE_KIND_SPL_TOKEN);
    if (!compatible) {
        PRINTF("value_kinds_compatible: unknown kind (%d, %d)\n", output_kind, input_kind);
    }
    return compatible;
}

// Whether an output leg of the upstream instruction and an input leg of the downstream
// one meet on the same account, forming one leg of a junction.
static bool junction_pair_matches(const cs_resolved_port_t *output_port,
                                  const cs_resolved_port_t *input_port) {
    // A port whose account candidate never resolved names nothing to meet on.
    if (!output_port->resolved || !input_port->resolved) {
        PRINTF("junction_pair_matches: unresolved port\n");
        return false;
    }
    if (output_port->account == NULL || input_port->account == NULL) {
        PRINTF("junction_pair_matches: missing account\n");
        return false;
    }
    if (memcmp(output_port->account, input_port->account, PUBKEY_SIZE) != 0) {
        PRINTF("junction_pair_matches: accounts differ\n");
        return false;
    }
    // Meeting on an account is not enough: what leaves must be what the other side
    // takes in, so the two legs also have to agree on the value and the token.
    if (!value_kinds_compatible(output_port->value_kind, input_port->value_kind)) {
        PRINTF("junction_pair_matches: value kinds do not line up\n");
        return false;
    }
    // The rule table scopes the token guard to Rule 2, but applying it before the rule is
    // classified holds it over Rule 1 too. Deliberately stricter: two legs naming different
    // mints describe different tokens whatever their amounts say, so the merges this turns
    // away are ones no display would gain from.
    return tokens_compatible(output_port, input_port);
}

// Which rule one leg of a junction supports, judged from the two amounts alone.
static enum cs_merge_rule classify_junction_leg(const cs_resolved_port_t *output_port,
                                                const cs_resolved_port_t *input_port) {
    // One side draining or filling a whole balance leaves the device no number to
    // compare, so this leg can only ever take the guarded collapse.
    if (output_port->is_symbolic || input_port->is_symbolic) {
        PRINTF("classify_junction_leg: symbolic junction leg\n");
        return CS_MERGE_RULE_SYMBOLIC_JUNCTION;
    }
    uint64_t output_amount = 0;
    uint64_t input_amount = 0;
    if (decode_le_amount(output_port->amount_le,
                         output_port->amount_size,
                         output_port->amount_leaf_kind,
                         &output_amount) != 0 ||
        decode_le_amount(input_port->amount_le,
                         input_port->amount_size,
                         input_port->amount_leaf_kind,
                         &input_amount) != 0) {
        PRINTF("classify_junction_leg: amount decode failed, no rule\n");
        return CS_MERGE_RULE_NONE;
    }
    // Both sides name a number. Equal means the upstream leg handed on exactly what it
    // received, so dropping it loses nothing. Unequal means the account kept or gained
    // something in between, which no collapse may hide.
    if (output_amount != input_amount) {
        PRINTF("classify_junction_leg: concrete amounts differ, no rule\n");
        return CS_MERGE_RULE_NONE;
    }
    PRINTF("classify_junction_leg: exact relay leg\n");
    return CS_MERGE_RULE_EXACT_RELAY;
}

// Which rule the junction between two instructions supports, or none at all.
static enum cs_merge_rule determine_junction_rule(const cs_instruction_result_t *upstream,
                                                  const cs_instruction_result_t *downstream) {
    // Legs are paired by position, so the two sides must offer the same number of them.
    // Zero legs is no junction rather than an empty one.
    size_t output_count = count_directional_ports(upstream, CS_PORT_DIRECTION_OUTPUT);
    size_t input_count = count_directional_ports(downstream, CS_PORT_DIRECTION_INPUT);
    if (output_count == 0 || output_count != input_count) {
        PRINTF("determine_junction_rule: leg counts out=%d in=%d\n",
               (int) output_count,
               (int) input_count);
        return CS_MERGE_RULE_NONE;
    }

    enum cs_merge_rule junction_rule = CS_MERGE_RULE_NONE;
    for (size_t leg = 0; leg < output_count; leg++) {
        const cs_resolved_port_t *output_port = nth_directional_port(upstream,
                                                                     CS_PORT_DIRECTION_OUTPUT,
                                                                     leg);
        const cs_resolved_port_t *input_port = nth_directional_port(downstream,
                                                                    CS_PORT_DIRECTION_INPUT,
                                                                    leg);
        if (output_port == NULL || input_port == NULL) {
            PRINTF("determine_junction_rule: leg %d missing\n", (int) leg);
            return CS_MERGE_RULE_NONE;
        }
        if (!junction_pair_matches(output_port, input_port)) {
            PRINTF("determine_junction_rule: leg %d does not line up\n", (int) leg);
            return CS_MERGE_RULE_NONE;
        }
        enum cs_merge_rule leg_rule = classify_junction_leg(output_port, input_port);
        if (leg_rule == CS_MERGE_RULE_NONE) {
            PRINTF("determine_junction_rule: leg %d supports no rule\n", (int) leg);
            return CS_MERGE_RULE_NONE;
        }
        // The junction moves as one thing, so a rule only holds if every leg supports
        // the same one. The first leg proposes it and the rest have to agree.
        if (leg == 0) {
            junction_rule = leg_rule;
        } else if (junction_rule != leg_rule) {
            PRINTF("determine_junction_rule: leg %d disagrees with the earlier legs\n", (int) leg);
            return CS_MERGE_RULE_NONE;
        }
    }
    PRINTF("determine_junction_rule: rule=%d over %d legs\n", junction_rule, (int) output_count);
    return junction_rule;
}

// What an instruction does to the value passing through it, which is what decides
// survivorship. Computed once per item and read by the role assignment.
enum cs_item_role {
    // Both sides pair up one-for-one in the same form: the item only relays value.
    CS_ITEM_ROLE_RELAY = 0,
    // A pair changes value kind or mint, and the item names an amount somewhere, so
    // it can display the movement it performs and must survive a collapse.
    CS_ITEM_ROLE_TRANSFORMER,
    // Changes the form of value while declaring no amount at all. It cannot display
    // the movement, so it must not claim survivorship over a counterpart that can.
    CS_ITEM_ROLE_PASS_THROUGH_TRANSFORMER,
};

// Whether an instruction names no amount anywhere, on either side.
static bool all_ports_symbolic(const cs_instruction_result_t *item) {
    // Both directions count: such an instruction has no number to put on a screen, which
    // is what disqualifies it from surviving a collapse.
    for (size_t p = 0; p < item->resolved_port_count; p++) {
        if (!item->resolved_ports[p].excluded && !item->resolved_ports[p].is_symbolic) {
            PRINTF("all_ports_symbolic: port %d names an amount\n", (int) p);
            return false;
        }
    }
    PRINTF("all_ports_symbolic: every port is symbolic\n");
    return true;
}

// Whether value comes out of one leg pair in a different form than it went in, which is
// what separates an instruction that converts value from one that merely passes it on.
static bool legs_change_form(const cs_resolved_port_t *input_port,
                             const cs_resolved_port_t *output_port,
                             size_t leg) {
    UNUSED(leg);  // read only by the trace logs below
    // Lamports in, SPL balance out is the wrap case.
    if (input_port->value_kind != output_port->value_kind) {
        PRINTF("legs_change_form: leg %d changes value kind\n", (int) leg);
        return true;
    }
    // One token in, another out is the swap case. An unresolved mint asserts nothing, so
    // it is not read as a change.
    if (input_port->mint != NULL && output_port->mint != NULL &&
        memcmp(input_port->mint, output_port->mint, PUBKEY_SIZE) != 0) {
        PRINTF("legs_change_form: leg %d changes mint\n", (int) leg);
        return true;
    }
    PRINTF("legs_change_form: leg %d keeps the same form\n", (int) leg);
    return false;
}

// Work out what an instruction does to the value crossing it. Computed once per
// instruction and read by the role assignment.
static enum cs_item_role classify_item_role(const cs_instruction_result_t *item) {
    // Legs are compared in pairs, so sides of unequal length cannot be read as relaying
    // anything at all. Treat that as converting value: it is the answer that keeps such
    // an instruction on screen.
    size_t input_count = count_directional_ports(item, CS_PORT_DIRECTION_INPUT);
    size_t output_count = count_directional_ports(item, CS_PORT_DIRECTION_OUTPUT);
    if (input_count != output_count) {
        PRINTF("classify_item_role: asymmetric leg counts, transformer\n");
        return CS_ITEM_ROLE_TRANSFORMER;
    }

    // One converting leg makes the whole instruction a converter, so the walk stops at
    // the first one it finds.
    bool changes_form = false;
    for (size_t leg = 0; leg < input_count && !changes_form; leg++) {
        const cs_resolved_port_t *input_port = nth_directional_port(item,
                                                                    CS_PORT_DIRECTION_INPUT,
                                                                    leg);
        const cs_resolved_port_t *output_port = nth_directional_port(item,
                                                                     CS_PORT_DIRECTION_OUTPUT,
                                                                     leg);
        if (input_port == NULL || output_port == NULL) {
            PRINTF("classify_item_role: leg %d missing, treated as a relay\n", (int) leg);
            return CS_ITEM_ROLE_RELAY;
        }
        changes_form = legs_change_form(input_port, output_port, leg);
    }

    if (!changes_form) {
        PRINTF("classify_item_role: every leg relays the same form of value\n");
        return CS_ITEM_ROLE_RELAY;
    }
    // It converts value. Whether it can also state how much decides if it outranks the
    // other side of a merge: a wrap that names no amount has nothing to show.
    if (all_ports_symbolic(item)) {
        PRINTF("classify_item_role: transforms without naming an amount, pass-through\n");
        return CS_ITEM_ROLE_PASS_THROUGH_TRANSFORMER;
    }
    PRINTF("classify_item_role: transforms and names an amount, transformer\n");
    return CS_ITEM_ROLE_TRANSFORMER;
}

// Number of symbolic ports on the side of `item` that faces the junction.
static size_t symbolic_junction_port_count(const cs_instruction_result_t *item, uint8_t direction) {
    // Only the side facing the junction is counted. The far side is what a merge would
    // propagate, not what it has to trust.
    size_t count = 0;
    for (size_t p = 0; p < item->resolved_port_count; p++) {
        if (item->template->ports[p].direction == direction && !item->resolved_ports[p].excluded &&
            item->resolved_ports[p].is_symbolic) {
            count++;
        }
    }
    PRINTF("symbolic_junction_port_count: direction=%d count=%d\n", direction, (int) count);
    return count;
}

// Decide which of the two instructions keeps its screen and which is folded into it.
// Reports the choice through `consumed_is_downstream`. Returns 0, -1 when neither side
// can be picked.
static int assign_merge_roles(const cs_instruction_result_t *upstream,
                              const cs_instruction_result_t *downstream,
                              enum cs_merge_rule rule,
                              bool *consumed_is_downstream) {
    bool upstream_transforms = (classify_item_role(upstream) == CS_ITEM_ROLE_TRANSFORMER);
    bool downstream_transforms = (classify_item_role(downstream) == CS_ITEM_ROLE_TRANSFORMER);
    PRINTF("assign_merge_roles: rule=%d upstream_transforms=%d downstream_transforms=%d\n",
           rule,
           upstream_transforms,
           downstream_transforms);

    // Exactly one side converting the value means that side is the reason the transaction
    // exists, so it keeps its screen whatever the rule would otherwise have chosen. Two
    // converters, or none, settle it by the rule instead.
    if (upstream_transforms && !downstream_transforms) {
        PRINTF("assign_merge_roles: upstream transforms, it survives\n");
        *consumed_is_downstream = true;
    } else if (downstream_transforms && !upstream_transforms) {
        PRINTF("assign_merge_roles: downstream transforms, it survives\n");
        *consumed_is_downstream = false;
    } else if (rule == CS_MERGE_RULE_EXACT_RELAY) {
        // Both legs named the same amount, so the upstream one added nothing the
        // downstream one does not already say.
        PRINTF("assign_merge_roles: exact relay drops the upstream leg\n");
        *consumed_is_downstream = false;
    } else {
        // Over a symbolic junction, the side naming fewer amounts describes the movement
        // less precisely and is the one worth losing.
        size_t upstream_symbolic = symbolic_junction_port_count(upstream, CS_PORT_DIRECTION_OUTPUT);
        size_t downstream_symbolic = symbolic_junction_port_count(downstream,
                                                                  CS_PORT_DIRECTION_INPUT);
        if (upstream_symbolic > downstream_symbolic) {
            PRINTF("assign_merge_roles: upstream more symbolic, it is consumed\n");
            *consumed_is_downstream = false;
        } else if (downstream_symbolic > upstream_symbolic) {
            PRINTF("assign_merge_roles: downstream more symbolic, it is consumed\n");
            *consumed_is_downstream = true;
        } else if (upstream_symbolic > 0) {
            // Equally vague on both sides: keep the later instruction, matching the exact
            // relay's choice so a chain always collapses towards its end.
            PRINTF("assign_merge_roles: equally symbolic, the upstream leg is consumed\n");
            *consumed_is_downstream = false;
        } else {
            // Unreachable: this rule was chosen because a leg was symbolic, and that leg
            // lies on one of the two sides just counted.
            PRINTF("assign_merge_roles: symbolic junction with no symbolic side, no roles\n");
            return -1;
        }
    }
    return 0;
}

// Whether the instruction about to be folded away can be fully represented by the one
// absorbing it.
static bool consumed_is_symmetric(const cs_instruction_result_t *consumed) {
    // The survivor takes on one far leg per junction leg. If the consumed instruction has
    // more of one than the other, some of its value flow would land nowhere and disappear
    // from the review along with its screen.
    bool symmetric = count_directional_ports(consumed, CS_PORT_DIRECTION_INPUT) ==
                     count_directional_ports(consumed, CS_PORT_DIRECTION_OUTPUT);
    if (!symmetric) {
        PRINTF("consumed_is_symmetric: consumed side is asymmetric, refusing\n");
    }
    return symmetric;
}

// ============================================================================
// Known balances and the safe-account set
// ============================================================================

// Whether a reset's preconditions hold, and so whether the engine may believe the
// balance it declares.
static bool reset_is_applicable(const cs_account_reset_t *reset,
                                const cs_resolved_reset_t *resolved) {
    if (resolved->account == NULL) {
        PRINTF("reset_is_applicable: unresolved reset account\n");
        return false;
    }
    // Without this flag the instruction cannot silently succeed on an existing account,
    // so its reset needs nothing corroborated.
    if (!reset->require_pre_balance_zero) {
        return true;
    }
    // An absent descriptor is indistinguishable from one the host withheld, so it
    // attests nothing. The streaming contract requires one for every such reset.
    const cs_token_account_t *state = cs_token_account_cache_find(resolved->account);
    if (state == NULL) {
        PRINTF("reset_is_applicable: no attested state for a pre-balance-zero reset\n");
        return false;
    }
    if (state->pre_balance != 0) {
        PRINTF("reset_is_applicable: attested pre-balance is not zero\n");
        return false;
    }
    return true;
}

// Read out the balance a reset declares for its account.
static void reset_established_balance(const cs_resolved_reset_t *resolved,
                                      const uint8_t **out_amount_le,
                                      size_t *out_amount_size,
                                      uint8_t *out_amount_leaf_kind) {
    // A reset that names no value declares the account emptied, so an absent RESET_VALUE
    // is a zero rather than a missing answer.
    if (resolved->has_amount && resolved->amount_le != NULL) {
        *out_amount_le = resolved->amount_le;
        *out_amount_size = resolved->amount_size;
        *out_amount_leaf_kind = resolved->amount_leaf_kind;
    } else {
        PRINTF("reset_established_balance: absent RESET_VALUE read as zero\n");
        *out_amount_le = G_implicit_zero_reset_le;
        *out_amount_size = sizeof(G_implicit_zero_reset_le);
        *out_amount_leaf_kind = IDL_KIND_U64;
    }
}

// Look up what the device currently knows an account holds. Returns NULL when nothing
// in the transaction so far has established it.
static const known_balance_t *known_balance_find(const merge_scratch_t *scratch,
                                                 const uint8_t *account) {
    for (size_t b = 0; b < scratch->known_balance_count; b++) {
        if (memcmp(scratch->known_balances[b].account, account, PUBKEY_SIZE) == 0) {
            PRINTF("known_balance_find: balance known for this account\n");
            return &scratch->known_balances[b];
        }
    }
    PRINTF("known_balance_find: no balance known for this account\n");
    return NULL;
}

// Forget what an account holds, called when an instruction writes it. Does nothing when
// no balance was known.
static void known_balance_forget(merge_scratch_t *scratch, const uint8_t *account) {
    for (size_t b = 0; b < scratch->known_balance_count; b++) {
        if (memcmp(scratch->known_balances[b].account, account, PUBKEY_SIZE) == 0) {
            PRINTF("known_balance_forget: account written, balance no longer known\n");
            // Order carries no meaning here, so the last entry fills the hole.
            scratch->known_balances[b] = scratch->known_balances[scratch->known_balance_count - 1];
            scratch->known_balance_count--;
            return;
        }
    }
}

// Record what a reset establishes an account holds, replacing anything known before.
static void known_balance_set(merge_scratch_t *scratch,
                              const uint8_t *account,
                              const uint8_t *amount_le,
                              size_t amount_size,
                              uint8_t amount_leaf_kind) {
    // A later reset supersedes an earlier one rather than adding an entry, which is what
    // keeps the array within the total reset count it was sized to.
    for (size_t b = 0; b < scratch->known_balance_count; b++) {
        if (memcmp(scratch->known_balances[b].account, account, PUBKEY_SIZE) == 0) {
            PRINTF("known_balance_set: replacing an earlier reset for this account\n");
            scratch->known_balances[b].amount_le = amount_le;
            scratch->known_balances[b].amount_size = amount_size;
            scratch->known_balances[b].amount_leaf_kind = amount_leaf_kind;
            return;
        }
    }
    PRINTF("known_balance_set: balance now known for one more account\n");
    scratch->known_balances[scratch->known_balance_count].account = account;
    scratch->known_balances[scratch->known_balance_count].amount_le = amount_le;
    scratch->known_balances[scratch->known_balance_count].amount_size = amount_size;
    scratch->known_balances[scratch->known_balance_count].amount_leaf_kind = amount_leaf_kind;
    scratch->known_balance_count++;
}

// Give every whole-balance port an amount where the transaction says what the account
// holds, and mark the rest symbolic. Runs before any merge, so a junction the device can
// read as numbers never reaches the guarded collapse in the first place.
static void resolve_balance_amounts(cs_instruction_result_t *walked_instructions,
                                    size_t count,
                                    merge_scratch_t *scratch) {
    // Walked in execution order: a reset speaks only for the instructions after it, and
    // the three passes below are ordered the way one instruction's effects happen.
    for (size_t i = 0; i < count; i++) {
        // Draining an account the device knows the balance of moves a known amount, so
        // the port stops being symbolic and can be compared as a number.
        for (size_t p = 0; p < walked_instructions[i].resolved_port_count; p++) {
            if (walked_instructions[i].template->ports[p].direction != CS_PORT_DIRECTION_INPUT ||
                walked_instructions[i].resolved_ports[p].excluded ||
                walked_instructions[i].resolved_ports[p].amount_kind != CS_AMOUNT_KIND_BALANCE) {
                continue;
            }
            const known_balance_t *known = known_balance_find(
                scratch,
                walked_instructions[i].resolved_ports[p].account);
            if (known == NULL) {
                PRINTF(
                    "resolve_balance_amounts: instruction %d port %d drains an unknown balance\n",
                    (int) i,
                    (int) p);
                walked_instructions[i].resolved_ports[p].is_symbolic = true;
            } else {
                PRINTF("resolve_balance_amounts: instruction %d port %d drains a known balance\n",
                       (int) i,
                       (int) p);
                walked_instructions[i].resolved_ports[p].amount_le = known->amount_le;
                walked_instructions[i].resolved_ports[p].amount_size = known->amount_size;
                walked_instructions[i].resolved_ports[p].amount_leaf_kind = known->amount_leaf_kind;
                walked_instructions[i].resolved_ports[p].is_symbolic = false;
            }
        }

        // Filling an account is the other way round: how much lands there is decided by
        // the instruction, not by what the account held, so such a port stays symbolic.
        // Either way the write ends what the device knew about that account.
        for (size_t p = 0; p < walked_instructions[i].resolved_port_count; p++) {
            if (walked_instructions[i].template->ports[p].direction != CS_PORT_DIRECTION_OUTPUT ||
                walked_instructions[i].resolved_ports[p].excluded) {
                continue;
            }
            if (walked_instructions[i].resolved_ports[p].amount_kind == CS_AMOUNT_KIND_BALANCE) {
                PRINTF("resolve_balance_amounts: instruction %d port %d fills an unknown amount\n",
                       (int) i,
                       (int) p);
                walked_instructions[i].resolved_ports[p].is_symbolic = true;
            }
            known_balance_forget(scratch, walked_instructions[i].resolved_ports[p].account);
        }

        // The instruction's own resets land last, so a create-then-reset step leaves the
        // balance known even though its write just cleared it.
        for (size_t r = 0; r < walked_instructions[i].resolved_reset_count; r++) {
            if (!reset_is_applicable(&walked_instructions[i].template->account_resets[r],
                                     &walked_instructions[i].resolved_resets[r])) {
                PRINTF("resolve_balance_amounts: instruction %d reset %d not applicable\n",
                       (int) i,
                       (int) r);
                continue;
            }
            const uint8_t *amount_le;
            size_t amount_size;
            uint8_t amount_leaf_kind;
            reset_established_balance(&walked_instructions[i].resolved_resets[r],
                                      &amount_le,
                                      &amount_size,
                                      &amount_leaf_kind);
            known_balance_set(scratch,
                              walked_instructions[i].resolved_resets[r].account,
                              amount_le,
                              amount_size,
                              amount_leaf_kind);
        }
    }
}

// Whether the balance a reset declares is zero, which is what the symbolic-junction
// guard requires of the accounts it trusts.
static bool reset_establishes_empty_account(const cs_resolved_reset_t *resolved) {
    // An absent RESET_VALUE declares an emptied account, so it qualifies without reading
    // any bytes.
    if (!resolved->has_amount) {
        return true;
    }
    uint64_t balance = 0;
    if (decode_le_amount(resolved->amount_le,
                         resolved->amount_size,
                         resolved->amount_leaf_kind,
                         &balance) != 0) {
        PRINTF("reset_establishes_empty_account: reset value undecodable\n");
        return false;
    }
    PRINTF("reset_establishes_empty_account: leaves the account empty=%d\n", balance == 0);
    return balance == 0;
}

// Gather, from every ACCOUNT_RESET in the transaction, the accounts a symbolic junction
// is allowed to sit on. Built once before the scan and read by the guard.
static void build_safe_accounts(const cs_instruction_result_t *walked_instructions,
                                size_t count,
                                merge_scratch_t *scratch) {
    // One account may be reset more than once, and each declaration is recorded on its
    // own: the guard accepts a junction when any single one of them covers it.
    for (size_t i = 0; i < count; i++) {
        for (size_t r = 0; r < walked_instructions[i].resolved_reset_count; r++) {
            if (!reset_is_applicable(&walked_instructions[i].template->account_resets[r],
                                     &walked_instructions[i].resolved_resets[r])) {
                PRINTF("build_safe_accounts: instruction %d reset %d vouches for nothing\n",
                       (int) i,
                       (int) r);
                continue;
            }
            // Only an emptied account qualifies, because then the whole balance crossing
            // the junction is exactly what the chain itself put there. A non-zero reset
            // serves the numeric path instead, and can only arrive here after a write has
            // already invalidated the figure it declared.
            if (!reset_establishes_empty_account(&walked_instructions[i].resolved_resets[r])) {
                PRINTF("build_safe_accounts: instruction %d reset %d leaves a balance behind\n",
                       (int) i,
                       (int) r);
                continue;
            }
            scratch->safe_accounts[scratch->safe_account_count]
                .account = walked_instructions[i].resolved_resets[r].account;
            scratch->safe_accounts[scratch->safe_account_count].declarer_index = i;
            if (walked_instructions[i].template->account_resets[r].has_scope) {
                scratch->safe_accounts[scratch->safe_account_count]
                    .scope = &walked_instructions[i].template->account_resets[r].scope;
            } else {
                scratch->safe_accounts[scratch->safe_account_count].scope = NULL;
            }
            scratch->safe_account_count++;
            PRINTF("build_safe_accounts: instruction %d vouches for an account\n", (int) i);
        }
    }
    PRINTF("build_safe_accounts: %d entries\n", (int) scratch->safe_account_count);
}

// Whether a reset's scope lets this consumer rely on it. Some resets only hold for one
// program's own entry points: a ledger snapshot means nothing to any other program,
// which still sees the account's full balance.
static bool reset_scope_admits(const cs_reset_scope_t *scope,
                               const cs_instruction_result_t *consumer) {
    // An unscoped reset changed the account itself, so it holds for anyone.
    if (scope == NULL) {
        return true;
    }
    // The program is the whole point of a scope, so one without it narrows to nothing.
    if (!scope->has_program_id) {
        PRINTF("reset_scope_admits: scope carries no program id, admits nothing\n");
        return false;
    }
    if (memcmp(scope->scope_program_id, consumer->template->program_id, PUBKEY_SIZE) != 0) {
        PRINTF("reset_scope_admits: consumer program is out of scope\n");
        return false;
    }
    // Naming the program but no instruction admits all of that program's instructions.
    if (scope->discriminator_count == 0) {
        PRINTF("reset_scope_admits: any instruction of the scoped program\n");
        return true;
    }
    // Otherwise the consumer's data has to begin with one of the listed prefixes; the
    // list is alternatives, so the first match settles it.
    for (size_t d = 0; d < scope->discriminator_count; d++) {
        if (consumer->instruction_data_size >= scope->discriminators[d].size &&
            memcmp(consumer->instruction_data,
                   scope->discriminators[d].data,
                   scope->discriminators[d].size) == 0) {
            PRINTF("reset_scope_admits: consumer matches discriminator %d\n", (int) d);
            return true;
        }
    }
    PRINTF("reset_scope_admits: consumer matches no scoped discriminator\n");
    return false;
}

// Whether one reset declaration vouches for this account, towards this consumer, at a
// junction starting on `junction_index`.
static bool safe_account_entry_covers(const safe_account_t *entry,
                                      const uint8_t *account,
                                      const cs_instruction_result_t *consumer,
                                      size_t junction_index) {
    if (memcmp(entry->account, account, PUBKEY_SIZE) != 0) {
        return false;
    }
    // A reset states what the account holds once its own instruction has run. One
    // declared after the junction therefore says nothing about the balance that already
    // crossed it, and the balance this guard exists to neutralise is one the account held
    // before the chain started.
    if (entry->declarer_index > junction_index) {
        PRINTF("safe_account_entry_covers: reset declared at %d is later than junction %d\n",
               (int) entry->declarer_index,
               (int) junction_index);
        return false;
    }
    return reset_scope_admits(entry->scope, consumer);
}

// Whether anything in the transaction vouches for this account at this junction.
static bool safe_account_admits(const merge_scratch_t *scratch,
                                const uint8_t *account,
                                const cs_instruction_result_t *consumer,
                                size_t junction_index) {
    // The declarations are alternatives, so one that covers the junction is enough.
    for (size_t s = 0; s < scratch->safe_account_count; s++) {
        if (safe_account_entry_covers(&scratch->safe_accounts[s],
                                      account,
                                      consumer,
                                      junction_index)) {
            return true;
        }
    }
    PRINTF("safe_account_admits: no reset vouches for this account and consumer\n");
    return false;
}

// Whether one instruction is the very one that vouched for this account. The depositor
// check exempts it: the write it makes to the account *is* the reset that check leans on,
// so counting it as a depositor would leave every create-then-use pair uncollapsible.
static bool declares_admitting_reset(const merge_scratch_t *scratch,
                                     const uint8_t *account,
                                     const cs_instruction_result_t *consumer,
                                     size_t junction_index,
                                     size_t instruction_index) {
    // Reusing the same predicate as the vouching check keeps the two in step: a reset too
    // late or out of scope to vouch is equally too late to exempt its declarer.
    for (size_t s = 0; s < scratch->safe_account_count; s++) {
        if (scratch->safe_accounts[s].declarer_index == instruction_index &&
            safe_account_entry_covers(&scratch->safe_accounts[s],
                                      account,
                                      consumer,
                                      junction_index)) {
            PRINTF("declares_admitting_reset: instruction %d is the reset declarer\n",
                   (int) instruction_index);
            return true;
        }
    }
    return false;
}

// Whether an instruction could have put value into an account. Answers conservatively:
// only a definite no lets a collapse through.
static bool instruction_may_deposit(const cs_instruction_result_t *item, const uint8_t *account) {
    // Two independent signals answer this: what the descriptor declares, and the raw
    // writable list. A port's account is normally writable too, so the zero-amount
    // exemption below only decides the outcome for a caller whose writable list does not
    // name the account.
    for (size_t p = 0; p < item->resolved_port_count; p++) {
        if (item->template->ports[p].direction != CS_PORT_DIRECTION_OUTPUT ||
            item->resolved_ports[p].excluded || item->resolved_ports[p].account == NULL) {
            continue;
        }
        if (memcmp(item->resolved_ports[p].account, account, PUBKEY_SIZE) == 0 &&
            !port_moves_no_value(&item->resolved_ports[p])) {
            PRINTF("instruction_may_deposit: an output port feeds the account\n");
            return true;
        }
    }
    // An unresolved writable account could be this one, and nothing here can prove
    // otherwise.
    if (!item->writable_complete) {
        PRINTF("instruction_may_deposit: writable list incomplete, cannot rule it out\n");
        return true;
    }
    // The raw list catches what no descriptor declared, whether a misdeclared overlay or
    // a legitimate write to an account the descriptor had no reason to mention.
    for (size_t w = 0; w < item->writable_account_count; w++) {
        if (memcmp(item->writable_accounts[w], account, PUBKEY_SIZE) == 0) {
            PRINTF("instruction_may_deposit: the account is writable here\n");
            return true;
        }
    }
    return false;
}

// List the accounts whose balance a collapse would have to take on trust. Writes at
// most one entry per junction leg on either side.
static size_t collect_symbolic_junction_accounts(const cs_instruction_result_t *survivor,
                                                 uint8_t survivor_direction,
                                                 const cs_instruction_result_t *consumed,
                                                 uint8_t consumed_direction,
                                                 const uint8_t **accounts) {
    // Only the sides facing each other are examined, and only the ports naming no amount:
    // a leg with a number needs nothing taken on trust.
    size_t account_count = 0;
    for (size_t p = 0; p < survivor->resolved_port_count; p++) {
        if (survivor->template->ports[p].direction == survivor_direction &&
            !survivor->resolved_ports[p].excluded && survivor->resolved_ports[p].is_symbolic) {
            accounts[account_count] = survivor->resolved_ports[p].account;
            account_count++;
        }
    }
    // The two sides meet on the same accounts, so this pass usually finds them already
    // listed and adds nothing.
    for (size_t p = 0; p < consumed->resolved_port_count; p++) {
        if (consumed->template->ports[p].direction != consumed_direction ||
            consumed->resolved_ports[p].excluded || !consumed->resolved_ports[p].is_symbolic) {
            continue;
        }
        bool already_listed = false;
        for (size_t a = 0; a < account_count && !already_listed; a++) {
            already_listed = (accounts[a] != NULL && consumed->resolved_ports[p].account != NULL &&
                              memcmp(accounts[a],
                                     consumed->resolved_ports[p].account,
                                     PUBKEY_SIZE) == 0);
        }
        if (!already_listed) {
            accounts[account_count] = consumed->resolved_ports[p].account;
            account_count++;
        }
    }
    PRINTF("collect_symbolic_junction_accounts: %d symbolic junction accounts\n",
           (int) account_count);
    return account_count;
}

// Decide whether a collapse may go ahead when the device cannot read how much crosses
// the junction. Such a collapse shows the survivor's amount while the other side moves
// the account's whole balance, so it is only honest if that balance is provably nothing
// more than what the chain itself put there. `symbolic_accounts` is caller-owned scratch
// holding one entry per junction leg on either side.
static bool symbolic_junction_guard(const cs_instruction_result_t *walked_instructions,
                                    const merge_scratch_t *scratch,
                                    size_t survivor_index,
                                    size_t consumed_index,
                                    bool consumed_is_downstream,
                                    const uint8_t **symbolic_accounts) {
    // The two items face each other, so their junction sides are opposite directions.
    uint8_t survivor_direction = CS_PORT_DIRECTION_INPUT;
    uint8_t consumed_direction = CS_PORT_DIRECTION_OUTPUT;
    if (consumed_is_downstream) {
        survivor_direction = CS_PORT_DIRECTION_OUTPUT;
        consumed_direction = CS_PORT_DIRECTION_INPUT;
    }

    size_t account_count = collect_symbolic_junction_accounts(&walked_instructions[survivor_index],
                                                              survivor_direction,
                                                              &walked_instructions[consumed_index],
                                                              consumed_direction,
                                                              symbolic_accounts);
    // Both sides named their amounts, so there is nothing to take on trust and this is an
    // exact relay rather than the case this guard is for.
    if (account_count == 0) {
        PRINTF("symbolic_junction_guard: nothing symbolic to vouch for\n");
        return true;
    }

    // Scratch is absent only when the run allocated none for want of any port; a
    // non-zero count then has nowhere to live, so refuse rather than index a null base.
    if (symbolic_accounts == NULL) {
        PRINTF("symbolic_junction_guard: symbolic account scratch missing\n");
        return false;
    }

    // The chain begins at whichever of the pair runs first, and a reset has to be in place
    // by then to say anything about the balance that crosses.
    size_t junction_index = survivor_index;
    if (consumed_index < junction_index) {
        junction_index = consumed_index;
    }

    for (size_t a = 0; a < account_count; a++) {
        // An account the device cannot even name is one it certainly cannot reason about.
        if (symbolic_accounts[a] == NULL) {
            PRINTF("symbolic_junction_guard: unresolved symbolic junction account\n");
            return false;
        }
        if (!safe_account_admits(scratch,
                                 symbolic_accounts[a],
                                 &walked_instructions[consumed_index],
                                 junction_index)) {
            PRINTF("symbolic_junction_guard: account %d is not vouched for\n", (int) a);
            return false;
        }
        // A reset alone is not enough: it says what the account held when it ran, so
        // anything running between then and the drain could have added more. Every such
        // instruction has to be excused for a reason, or the collapse is refused.
        for (size_t i = 0; i < consumed_index; i++) {
            if (i == survivor_index) {
                continue;
            }
            // Whatever the chain already accounts for is, by definition, on the screen.
            if (scratch->states[survivor_index].merged_from[i] ||
                scratch->states[consumed_index].merged_from[i]) {
                continue;
            }
            if (declares_admitting_reset(scratch,
                                         symbolic_accounts[a],
                                         &walked_instructions[consumed_index],
                                         junction_index,
                                         i)) {
                continue;
            }
            if (instruction_may_deposit(&walked_instructions[i], symbolic_accounts[a])) {
                PRINTF("symbolic_junction_guard: instruction %d is an unaccounted depositor\n",
                       (int) i);
                return false;
            }
        }
    }
    PRINTF("symbolic_junction_guard: junction is sound\n");
    return true;
}

// ============================================================================
// Applying a merge
// ============================================================================

// Move the value one port carries onto another. The destination keeps its own
// accounts-array slot, which is what the renderer keys field overrides on.
static void copy_port_value(cs_resolved_port_t *destination, const cs_resolved_port_t *source) {
    destination->account = source->account;
    destination->value_kind = source->value_kind;
    destination->amount_kind = source->amount_kind;
    destination->amount_le = source->amount_le;
    destination->amount_size = source->amount_size;
    destination->amount_leaf_kind = source->amount_leaf_kind;
    destination->is_symbolic = source->is_symbolic;
    destination->token_kind = source->token_kind;
    destination->mint = source->mint;
    PRINTF("copy_port_value: value moved onto the survivor slot\n");
}

// Move only how much a port moves, leaving its account and token alone.
static void copy_port_amount(cs_resolved_port_t *destination, const cs_resolved_port_t *source) {
    // Whether the amount is readable travels with it, since the bytes mean nothing
    // without it.
    destination->amount_kind = source->amount_kind;
    destination->amount_le = source->amount_le;
    destination->amount_size = source->amount_size;
    destination->amount_leaf_kind = source->amount_leaf_kind;
    destination->is_symbolic = source->is_symbolic;
    PRINTF("copy_port_amount: is_symbolic=%d\n", destination->is_symbolic);
}

// Move only which token a port moves, leaving its account and amount alone.
static void copy_port_token(cs_resolved_port_t *destination, const cs_resolved_port_t *source) {
    destination->token_kind = source->token_kind;
    destination->mint = source->mint;
    PRINTF("copy_port_token: token_kind=%d\n", destination->token_kind);
}

// Repoint one junction leg of the survivor at the real counterparty, read from the
// matching far leg of the instruction being folded away. Without this the survivor would
// still name the intermediate account the value merely passed through.
static void rewrite_junction_leg(cs_resolved_port_t *survivor_port,
                                 const cs_resolved_port_t *replacement,
                                 enum cs_merge_rule rule) {
    if (rule == CS_MERGE_RULE_EXACT_RELAY) {
        // The two legs agreed on the amount, so the far leg is right about everything and
        // can be taken as it stands.
        PRINTF("rewrite_junction_leg: relayed leg replaced whole\n");
        copy_port_value(survivor_port, replacement);
    } else if (survivor_port->is_symbolic) {
        // Over a symbolic junction the sides know different things, so each field is taken
        // from whichever side actually knows it. Here this leg named no amount, so
        // anything the replacement says is an improvement.
        PRINTF("rewrite_junction_leg: symbolic survivor leg adopts the replacement\n");
        survivor_port->account = replacement->account;
        copy_port_amount(survivor_port, replacement);
        if (port_has_token(replacement)) {
            copy_port_token(survivor_port, replacement);
        }
    } else {
        // This leg does name an amount. Build the result from the replacement, then take
        // back whatever this side knew better: a figure is never surrendered for a whole
        // balance, and a creation placeholder's absent token never erases a real one.
        cs_resolved_port_t merged;
        memcpy(&merged, replacement, sizeof(merged));
        if (merged.is_symbolic) {
            PRINTF("rewrite_junction_leg: concrete survivor amount kept over a symbolic one\n");
            copy_port_amount(&merged, survivor_port);
        }
        if (!port_has_token(&merged) && port_has_token(survivor_port)) {
            PRINTF("rewrite_junction_leg: replacement inherits the survivor token\n");
            copy_port_token(&merged, survivor_port);
        }
        copy_port_value(survivor_port, &merged);
    }
}

// Fold the consumed instruction into the survivor.
static void apply_merge(cs_instruction_result_t *survivor,
                        const cs_instruction_result_t *consumed,
                        enum cs_merge_rule rule,
                        bool consumed_is_downstream) {
    // Two different sides, which happen to sit on the same direction: fold a downstream
    // instruction away and the shared account is the survivor's output, while the endpoint
    // worth keeping is that instruction's output as well. Naming both stops the
    // coincidence from reading as one idea.
    uint8_t survivor_junction_direction = CS_PORT_DIRECTION_INPUT;
    uint8_t consumed_far_side_direction = CS_PORT_DIRECTION_INPUT;
    if (consumed_is_downstream) {
        survivor_junction_direction = CS_PORT_DIRECTION_OUTPUT;
        consumed_far_side_direction = CS_PORT_DIRECTION_OUTPUT;
    }
    // The counts are equal by the time this runs, since a junction pairs its legs and the
    // consumed instruction was checked symmetric. The lower bound only keeps the walk
    // inside both arrays.
    size_t leg_count = count_directional_ports(survivor, survivor_junction_direction);
    size_t replacement_count = count_directional_ports(consumed, consumed_far_side_direction);

    for (size_t leg = 0; leg < leg_count && leg < replacement_count; leg++) {
        // Written through the index rather than the port pointer: the survivor's ports are
        // being modified, not read.
        size_t survivor_port_index = nth_directional_port_index(survivor,
                                                                survivor_junction_direction,
                                                                leg);
        size_t replacement_index = nth_directional_port_index(consumed,
                                                              consumed_far_side_direction,
                                                              leg);
        if (survivor_port_index == SIZE_MAX || replacement_index == SIZE_MAX) {
            PRINTF("apply_merge: leg %d missing, left untouched\n", (int) leg);
            continue;
        }
        rewrite_junction_leg(&survivor->resolved_ports[survivor_port_index],
                             &consumed->resolved_ports[replacement_index],
                             rule);
    }
    PRINTF("apply_merge: %d legs rewritten\n", (int) leg_count);
}

// Whether the downstream instruction touches any account the upstream one feeds, which is
// what ends the forward scan.
static bool touches_upstream_outputs(const cs_instruction_result_t *upstream,
                                     const cs_instruction_result_t *downstream) {
    // An unresolved writable account could be any account at all, including this one.
    if (!downstream->writable_complete) {
        PRINTF("touches_upstream_outputs: writable list incomplete, assuming overlap\n");
        return true;
    }
    // Declared ports first, then the raw writable list, so an undeclared write counts too.
    for (size_t up = 0; up < upstream->resolved_port_count; up++) {
        if (upstream->template->ports[up].direction != CS_PORT_DIRECTION_OUTPUT ||
            upstream->resolved_ports[up].excluded || upstream->resolved_ports[up].account == NULL) {
            continue;
        }
        for (size_t down = 0; down < downstream->resolved_port_count; down++) {
            if (!downstream->resolved_ports[down].excluded &&
                downstream->resolved_ports[down].account != NULL &&
                memcmp(upstream->resolved_ports[up].account,
                       downstream->resolved_ports[down].account,
                       PUBKEY_SIZE) == 0) {
                PRINTF("touches_upstream_outputs: a port of the next instruction overlaps\n");
                return true;
            }
        }
        for (size_t w = 0; w < downstream->writable_account_count; w++) {
            if (memcmp(upstream->resolved_ports[up].account,
                       downstream->writable_accounts[w],
                       PUBKEY_SIZE) == 0) {
                PRINTF("touches_upstream_outputs: the junction is writable downstream\n");
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// Scan
// ============================================================================

// Put one pair of instructions through every test a collapse has to pass, and perform it
// if they all hold. Returns true when the pair merged, reporting through
// `consumed_is_downstream` which of the two was folded away.
static bool try_merge_pair(cs_instruction_result_t *walked_instructions,
                           const merge_scratch_t *scratch,
                           size_t upstream_index,
                           size_t downstream_index,
                           const uint8_t **symbolic_accounts,
                           bool *consumed_is_downstream) {
    // The rule comes first because the roles depend on it.
    enum cs_merge_rule rule = determine_junction_rule(&walked_instructions[upstream_index],
                                                      &walked_instructions[downstream_index]);
    if (rule == CS_MERGE_RULE_NONE) {
        return false;
    }
    if (assign_merge_roles(&walked_instructions[upstream_index],
                           &walked_instructions[downstream_index],
                           rule,
                           consumed_is_downstream) != 0) {
        PRINTF("try_merge_pair: no role assignment\n");
        return false;
    }

    // Only now is it known which instruction is about to disappear, which the remaining
    // two checks are both about.
    size_t consumed_index = upstream_index;
    size_t survivor_index = downstream_index;
    if (*consumed_is_downstream) {
        consumed_index = downstream_index;
        survivor_index = upstream_index;
    }
    if (!consumed_is_symmetric(&walked_instructions[consumed_index])) {
        return false;
    }
    if (!symbolic_junction_guard(walked_instructions,
                                 scratch,
                                 survivor_index,
                                 consumed_index,
                                 *consumed_is_downstream,
                                 symbolic_accounts)) {
        PRINTF("try_merge_pair: guard refused instructions %d and %d\n",
               (int) upstream_index,
               (int) downstream_index);
        return false;
    }

    apply_merge(&walked_instructions[survivor_index],
                &walked_instructions[consumed_index],
                rule,
                *consumed_is_downstream);
    PRINTF("try_merge_pair: instruction %d consumed into %d (rule=%d)\n",
           (int) consumed_index,
           (int) survivor_index,
           rule);
    return true;
}

// Hand the consumed instruction's chain history to the survivor.
static void inherit_merge_history(merge_scratch_t *scratch,
                                  size_t count,
                                  size_t survivor_index,
                                  size_t consumed_index) {
    // A later guard has to treat everything the folded instruction stood for as part of the
    // chain, not just the instruction itself, or a chain of three would refuse to close.
    for (size_t i = 0; i < count; i++) {
        if (scratch->states[consumed_index].merged_from[i]) {
            scratch->states[survivor_index].merged_from[i] = true;
        }
    }
    PRINTF("inherit_merge_history: instruction %d now accounts for %d\n",
           (int) survivor_index,
           (int) consumed_index);
}

// Collapse every chain the transaction supports, in one left-to-right pass: each
// instruction with output ports is offered to every later survivor until one of them
// touches its junction.
static void run_merge_scan(cs_instruction_result_t *walked_instructions,
                           size_t count,
                           merge_scratch_t *scratch,
                           const uint8_t **symbolic_accounts) {
    size_t upstream = 0;
    while (upstream < count) {
        // A junction hangs off an output port, so an instruction already folded away or
        // with nothing leaving it can start no chain.
        if (scratch->states[upstream].consumed ||
            count_directional_ports(&walked_instructions[upstream], CS_PORT_DIRECTION_OUTPUT) ==
                0) {
            upstream++;
            continue;
        }

        bool merged_something = false;
        size_t downstream = upstream + 1;
        while (downstream < count) {
            if (scratch->states[downstream].consumed) {
                downstream++;
                continue;
            }

            // Nothing entering means no junction to meet on, though the instruction is
            // still checked below for touching one.
            bool consumed_is_downstream = false;
            bool merged = false;
            if (count_directional_ports(&walked_instructions[downstream], CS_PORT_DIRECTION_INPUT) >
                0) {
                merged = try_merge_pair(walked_instructions,
                                        scratch,
                                        upstream,
                                        downstream,
                                        symbolic_accounts,
                                        &consumed_is_downstream);
            }

            if (merged) {
                size_t consumed_index = upstream;
                size_t survivor_index = downstream;
                if (consumed_is_downstream) {
                    consumed_index = downstream;
                    survivor_index = upstream;
                }
                inherit_merge_history(scratch, count, survivor_index, consumed_index);
                scratch->states[consumed_index].consumed = true;
                if (consumed_is_downstream) {
                    // This instruction took on the far leg of what it absorbed, which may
                    // reach a new account, so the search restarts from it. That is how
                    // transfer, wrap and swap collapse into one screen.
                    merged_something = true;
                    downstream = upstream + 1;
                } else {
                    // The upstream instruction is gone; nothing more to chain from it.
                    downstream = count;
                }
            } else if (touches_upstream_outputs(&walked_instructions[upstream],
                                                &walked_instructions[downstream])) {
                // It may write the junction account, so no later instruction can be assumed
                // to still carry the same value. This has to stop the scan whatever the
                // reason the pair did not merge, the guard's refusal included: the guard
                // only inspects instructions before the consumed one, so where that is the
                // upstream leg, nothing else ever looks at this instruction.
                PRINTF("run_merge_scan: instruction %d touches the junction, stopping the scan\n",
                       (int) downstream);
                downstream = count;
            } else {
                downstream++;
            }
        }

        // Staying put re-runs the whole forward scan for an instruction that just grew a new
        // junction. Anything else moves on, and an instruction folded away always does.
        if (!merged_something || scratch->states[upstream].consumed) {
            upstream++;
        }
    }
}

// ============================================================================
// Condition vocabulary (shared by the Annotate and Hide stages)
// ============================================================================

// Whether the target account is created in the transaction.
static bool condition_created_in_transaction(const cs_instruction_result_t *walked_instructions,
                                             size_t count,
                                             const uint8_t *target) {
    if (target == NULL) {
        PRINTF("condition_created_in_transaction: no target\n");
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        for (size_t p = 0; p < walked_instructions[i].resolved_port_count; p++) {
            if (walked_instructions[i].template->ports[p].direction != CS_PORT_DIRECTION_OUTPUT ||
                walked_instructions[i].resolved_ports[p].excluded ||
                walked_instructions[i].resolved_ports[p].account == NULL) {
                continue;
            }
            // A zero-amount, no-token output is an account brought into existence rather
            // than value moving through it.
            if (memcmp(walked_instructions[i].resolved_ports[p].account, target, PUBKEY_SIZE) ==
                    0 &&
                port_moves_no_value(&walked_instructions[i].resolved_ports[p])) {
                PRINTF("condition_created_in_transaction: instruction %d creates the target\n",
                       (int) i);
                return true;
            }
        }
    }
    PRINTF("condition_created_in_transaction: target never created\n");
    return false;
}

// Whether the target is the device user's own signing key, directly or as a token account
// the device signer owns. Never matches the fee payer or any other transaction signer.
static bool condition_is_device_signer(const uint8_t *target, const cs_merge_context_t *context) {
    if (target == NULL || context->device_signer == NULL) {
        PRINTF("condition_is_device_signer: no target or no device signer\n");
        return false;
    }
    if (memcmp(target, context->device_signer, PUBKEY_SIZE) == 0) {
        PRINTF("condition_is_device_signer: target is the device signer\n");
        return true;
    }
    for (size_t b = 0; b < context->owner_binding_count; b++) {
        if (memcmp(context->owner_bindings[b].token_account, target, PUBKEY_SIZE) == 0 &&
            memcmp(context->owner_bindings[b].owner, context->device_signer, PUBKEY_SIZE) == 0) {
            PRINTF("condition_is_device_signer: target is an ATA the device signer owns\n");
            return true;
        }
    }
    PRINTF("condition_is_device_signer: target is not the device signer\n");
    return false;
}

// Whether the target is a transaction signer that the header declares. The first
// num_required_signatures accounts sign; anything past them is a non-signer.
static bool pubkey_is_transaction_signer(const MessageHeader *header, const uint8_t *pubkey) {
    if (header == NULL || pubkey == NULL) {
        PRINTF("pubkey_is_transaction_signer: no header or no pubkey\n");
        return false;
    }
    for (size_t s = 0; s < header->pubkeys_header.num_required_signatures; s++) {
        if (memcmp(header->pubkeys[s].data, pubkey, PUBKEY_SIZE) == 0) {
            PRINTF("pubkey_is_transaction_signer: signer at index %d\n", (int) s);
            return true;
        }
    }
    PRINTF("pubkey_is_transaction_signer: not a signer\n");
    return false;
}

// Whether the target is a transaction signer other than the device user, so a co-signer or
// fee payer but neither the device signer nor a token account it owns.
static bool condition_is_another_signer(const uint8_t *target, const cs_merge_context_t *context) {
    if (target == NULL) {
        PRINTF("condition_is_another_signer: no target\n");
        return false;
    }
    if (context->device_signer != NULL &&
        memcmp(target, context->device_signer, PUBKEY_SIZE) == 0) {
        PRINTF("condition_is_another_signer: target is the device signer\n");
        return false;
    }
    for (size_t b = 0; b < context->owner_binding_count; b++) {
        if (context->device_signer != NULL &&
            memcmp(context->owner_bindings[b].token_account, target, PUBKEY_SIZE) == 0 &&
            memcmp(context->owner_bindings[b].owner, context->device_signer, PUBKEY_SIZE) == 0) {
            PRINTF("condition_is_another_signer: target is an ATA the device signer owns\n");
            return false;
        }
    }
    return pubkey_is_transaction_signer(context->header, target);
}

// Whether the target appears outside its own instruction: in any other instruction's active
// ports or in its raw resolved account list, so a reference no port declares still counts.
static bool condition_account_used_elsewhere(const cs_instruction_result_t *walked_instructions,
                                             size_t count,
                                             size_t current_index,
                                             const uint8_t *target) {
    if (target == NULL) {
        PRINTF("condition_account_used_elsewhere: no target\n");
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        if (i == current_index) {
            continue;
        }
        for (size_t p = 0; p < walked_instructions[i].resolved_port_count; p++) {
            if (!walked_instructions[i].resolved_ports[p].excluded &&
                walked_instructions[i].resolved_ports[p].account != NULL &&
                memcmp(walked_instructions[i].resolved_ports[p].account, target, PUBKEY_SIZE) ==
                    0) {
                PRINTF("condition_account_used_elsewhere: a port of instruction %d uses it\n",
                       (int) i);
                return true;
            }
        }
        for (size_t a = 0; a < walked_instructions[i].account_count; a++) {
            if (memcmp(walked_instructions[i].accounts[a], target, PUBKEY_SIZE) == 0) {
                PRINTF("condition_account_used_elsewhere: instruction %d lists it raw\n", (int) i);
                return true;
            }
        }
    }
    PRINTF("condition_account_used_elsewhere: target used nowhere else\n");
    return false;
}

// Whether an instruction is a candidate to stand in for a hidden one: not the hidden
// instruction itself, still a survivor (not merged away, not already hidden earlier in the
// pass), and carrying a template so it renders a descriptor.
static bool is_covering_survivor(const bool *survivors,
                                 const cs_instruction_result_t *walked_instructions,
                                 size_t index,
                                 size_t current_index) {
    bool covering = index != current_index && survivors[index] &&
                    walked_instructions[index].template != NULL;
    PRINTF("is_covering_survivor: instruction %d covering=%d\n", (int) index, covering);
    return covering;
}

// Whether the instruction moves value on the account through a live port.
static bool instruction_has_active_port_on(const cs_instruction_result_t *item,
                                           const uint8_t *account) {
    for (size_t p = 0; p < item->resolved_port_count; p++) {
        if (!item->resolved_ports[p].excluded && item->resolved_ports[p].account != NULL &&
            memcmp(item->resolved_ports[p].account, account, PUBKEY_SIZE) == 0) {
            PRINTF("instruction_has_active_port_on: port %d moves value on the account\n", (int) p);
            return true;
        }
    }
    PRINTF("instruction_has_active_port_on: no port moves value on the account\n");
    return false;
}

// Whether the instruction shows the account on screen: a resolved ACCOUNT_PATH field carrying
// its pubkey, which the renderer will not skip.
static bool instruction_displays_account(const cs_instruction_result_t *item,
                                         const uint8_t *account) {
    for (size_t f = 0; f < item->resolved_count; f++) {
        if (item->template->display_fields[f].source == CS_VALUE_SOURCE_ACCOUNT_PATH &&
            item->resolved[f].value != NULL && item->resolved[f].value_size == PUBKEY_SIZE &&
            memcmp(item->resolved[f].value, account, PUBKEY_SIZE) == 0) {
            PRINTF("instruction_displays_account: field %d renders the account\n", (int) f);
            return true;
        }
    }
    PRINTF("instruction_displays_account: no field renders the account\n");
    return false;
}

// Whether the instruction lists the account in its raw resolved account list.
static bool instruction_lists_account_raw(const cs_instruction_result_t *item,
                                          const uint8_t *account) {
    for (size_t a = 0; a < item->account_count; a++) {
        if (memcmp(item->accounts[a], account, PUBKEY_SIZE) == 0) {
            PRINTF("instruction_lists_account_raw: raw slot %d lists the account\n", (int) a);
            return true;
        }
    }
    PRINTF("instruction_lists_account_raw: account not in the raw list\n");
    return false;
}

// Whether a survivor consumes a hidden reset on the target: it lists the account raw and folded
// in an instruction the reset's scope authorises to consume that reset.
static bool survivor_consumes_scoped_reset(size_t current_index,
                                           size_t reset_index,
                                           const cs_instruction_result_t *walked_instructions,
                                           size_t count,
                                           const merge_scratch_t *scratch,
                                           size_t survivor_index,
                                           const uint8_t *target) {
    if (!instruction_lists_account_raw(&walked_instructions[survivor_index], target)) {
        PRINTF("survivor_consumes_scoped_reset: survivor %d does not list the account raw\n",
               (int) survivor_index);
        return false;
    }
    // A scope narrows to one program's own entry points; NULL means the reset changed the
    // account itself, so reset_scope_admits then holds for anyone.
    const cs_reset_scope_t *scope = NULL;
    if (walked_instructions[current_index].template->account_resets[reset_index].has_scope) {
        scope = &walked_instructions[current_index].template->account_resets[reset_index].scope;
    }
    for (size_t k = 0; k < count; k++) {
        if (scratch->states[survivor_index].merged_from[k] &&
            reset_scope_admits(scope, &walked_instructions[k])) {
            PRINTF("survivor_consumes_scoped_reset: survivor %d folded in scoped consumer %d\n",
                   (int) survivor_index,
                   (int) k);
            return true;
        }
    }
    PRINTF("survivor_consumes_scoped_reset: survivor %d folded in no scoped consumer\n",
           (int) survivor_index);
    return false;
}

// Whether a survivor port faithfully re-displays a hidden port's effect on their shared
// account: a concrete amount shown as the same number, under the same token and value kind.
static bool port_effect_is_covered(const cs_resolved_port_t *hidden_port,
                                   const cs_resolved_port_t *visible_port) {
    // A whole-balance hidden leg carries no number, so nothing can be said to re-display it.
    if (hidden_port->is_symbolic) {
        PRINTF("port_effect_is_covered: hidden leg is symbolic, never covered\n");
        return false;
    }
    // The survivor must itself show a concrete amount, or the quantity disappears with the leg.
    if (visible_port->is_symbolic || visible_port->amount_le == NULL) {
        PRINTF("port_effect_is_covered: survivor leg carries no concrete amount\n");
        return false;
    }
    // A hidden leg naming a concrete amount is only covered when the survivor shows the very
    // same number; a hidden leg with no amount bytes puts no quantity constraint on the cover.
    if (hidden_port->amount_le != NULL) {
        uint64_t hidden_amount = 0;
        uint64_t visible_amount = 0;
        if (decode_le_amount(hidden_port->amount_le,
                             hidden_port->amount_size,
                             hidden_port->amount_leaf_kind,
                             &hidden_amount) != 0 ||
            decode_le_amount(visible_port->amount_le,
                             visible_port->amount_size,
                             visible_port->amount_leaf_kind,
                             &visible_amount) != 0) {
            PRINTF("port_effect_is_covered: amount undecodable\n");
            return false;
        }
        if (hidden_amount != visible_amount) {
            PRINTF("port_effect_is_covered: amounts differ\n");
            return false;
        }
    }
    // A hidden mint must be the very mint the survivor shows; a hidden leg with no mint puts no
    // token constraint on the cover.
    if (hidden_port->mint != NULL &&
        (visible_port->mint == NULL ||
         memcmp(hidden_port->mint, visible_port->mint, PUBKEY_SIZE) != 0)) {
        PRINTF("port_effect_is_covered: mints differ\n");
        return false;
    }
    if (hidden_port->value_kind != visible_port->value_kind) {
        PRINTF("port_effect_is_covered: value kinds differ\n");
        return false;
    }
    PRINTF("port_effect_is_covered: survivor port re-displays the hidden effect\n");
    return true;
}

// Whether any survivor re-displays one hidden port's effect on the target.
static bool port_effect_covered_somewhere(const cs_resolved_port_t *hidden_port,
                                          const uint8_t *target,
                                          const bool *survivors,
                                          const cs_instruction_result_t *walked_instructions,
                                          size_t count,
                                          size_t current_index) {
    for (size_t j = 0; j < count; j++) {
        if (!is_covering_survivor(survivors, walked_instructions, j, current_index)) {
            continue;
        }
        for (size_t p = 0; p < walked_instructions[j].resolved_port_count; p++) {
            if (!walked_instructions[j].resolved_ports[p].excluded &&
                walked_instructions[j].resolved_ports[p].account != NULL &&
                memcmp(walked_instructions[j].resolved_ports[p].account, target, PUBKEY_SIZE) ==
                    0 &&
                port_effect_is_covered(hidden_port, &walked_instructions[j].resolved_ports[p])) {
                PRINTF("port_effect_covered_somewhere: survivor %d re-displays the port\n",
                       (int) j);
                return true;
            }
        }
    }
    PRINTF("port_effect_covered_somewhere: no survivor re-displays this port\n");
    return false;
}

// Whether any survivor consumes one hidden reset on the target: it moves value on the account,
// or lists it raw while folding a consumer the reset's scope authorises.
static bool reset_effect_covered_somewhere(size_t current_index,
                                           size_t reset_index,
                                           const uint8_t *target,
                                           const bool *survivors,
                                           const cs_instruction_result_t *walked_instructions,
                                           size_t count,
                                           const merge_scratch_t *scratch) {
    for (size_t j = 0; j < count; j++) {
        if (!is_covering_survivor(survivors, walked_instructions, j, current_index)) {
            continue;
        }
        if (instruction_has_active_port_on(&walked_instructions[j], target) ||
            survivor_consumes_scoped_reset(current_index,
                                           reset_index,
                                           walked_instructions,
                                           count,
                                           scratch,
                                           j,
                                           target)) {
            PRINTF("reset_effect_covered_somewhere: survivor %d consumes the reset\n", (int) j);
            return true;
        }
    }
    PRINTF("reset_effect_covered_somewhere: no survivor consumes this reset\n");
    return false;
}

// Whether any survivor shows the target with the mint the hidden instruction bound it to.
static bool mint_effect_covered_somewhere(const uint8_t *target,
                                          const uint8_t *expected_mint,
                                          const bool *survivors,
                                          const cs_instruction_result_t *walked_instructions,
                                          size_t count,
                                          size_t current_index) {
    for (size_t j = 0; j < count; j++) {
        if (!is_covering_survivor(survivors, walked_instructions, j, current_index)) {
            continue;
        }
        for (size_t p = 0; p < walked_instructions[j].resolved_port_count; p++) {
            if (!walked_instructions[j].resolved_ports[p].excluded &&
                walked_instructions[j].resolved_ports[p].account != NULL &&
                memcmp(walked_instructions[j].resolved_ports[p].account, target, PUBKEY_SIZE) ==
                    0 &&
                walked_instructions[j].resolved_ports[p].mint != NULL &&
                memcmp(walked_instructions[j].resolved_ports[p].mint, expected_mint, PUBKEY_SIZE) ==
                    0) {
                PRINTF("mint_effect_covered_somewhere: survivor %d shows the bound mint\n",
                       (int) j);
                return true;
            }
        }
    }
    PRINTF("mint_effect_covered_somewhere: no survivor shows the bound mint\n");
    return false;
}

// Whether any survivor visibly renders the target, which is what a bound owner reduces to on
// screen.
static bool account_displayed_somewhere(const uint8_t *target,
                                        const bool *survivors,
                                        const cs_instruction_result_t *walked_instructions,
                                        size_t count,
                                        size_t current_index) {
    for (size_t j = 0; j < count; j++) {
        if (is_covering_survivor(survivors, walked_instructions, j, current_index) &&
            instruction_displays_account(&walked_instructions[j], target)) {
            PRINTF("account_displayed_somewhere: survivor %d renders the account\n", (int) j);
            return true;
        }
    }
    PRINTF("account_displayed_somewhere: no survivor renders the account\n");
    return false;
}

// Whether some non-hidden survivor stands in for the account on screen: it moves value on it,
// renders it as a field, or lists it raw while folding a consumer its reset scope authorises.
static bool account_represented_by_survivor(const uint8_t *target,
                                            const bool *survivors,
                                            const cs_instruction_result_t *walked_instructions,
                                            size_t count,
                                            size_t current_index,
                                            const merge_scratch_t *scratch) {
    for (size_t j = 0; j < count; j++) {
        if (!is_covering_survivor(survivors, walked_instructions, j, current_index)) {
            continue;
        }
        if (instruction_has_active_port_on(&walked_instructions[j], target) ||
            instruction_displays_account(&walked_instructions[j], target)) {
            PRINTF("account_represented_by_survivor: survivor %d moves value on or renders it\n",
                   (int) j);
            return true;
        }
        for (size_t r = 0; r < walked_instructions[current_index].resolved_reset_count; r++) {
            if (walked_instructions[current_index].resolved_resets[r].account != NULL &&
                memcmp(walked_instructions[current_index].resolved_resets[r].account,
                       target,
                       PUBKEY_SIZE) == 0 &&
                survivor_consumes_scoped_reset(current_index,
                                               r,
                                               walked_instructions,
                                               count,
                                               scratch,
                                               j,
                                               target)) {
                PRINTF(
                    "account_represented_by_survivor: survivor %d stands in via a scoped reset\n",
                    (int) j);
                return true;
            }
        }
    }
    PRINTF("account_represented_by_survivor: no survivor stands in for the account\n");
    return false;
}

// Whether hiding the instruction loses nothing: a non-hidden survivor stands in for the target
// and re-displays every effect the hidden instruction produced for it. Any doubt leaves it
// visible: no target, no survivor standing in, a symbolic amount, an uncovered mint or owner.
static bool condition_account_effects_displayed_elsewhere(
    const uint8_t *target,
    const bool *survivors,
    const cs_instruction_result_t *walked_instructions,
    size_t count,
    size_t current_index,
    const merge_scratch_t *scratch) {
    if (target == NULL) {
        PRINTF("condition_account_effects_displayed_elsewhere: no target\n");
        return false;
    }

    // Every value-flow port the hidden instruction moves on the target must reappear, faithfully
    // re-displayed, on a survivor.
    bool ports_covered = true;
    for (size_t p = 0; p < walked_instructions[current_index].resolved_port_count; p++) {
        if (walked_instructions[current_index].resolved_ports[p].excluded ||
            walked_instructions[current_index].resolved_ports[p].account == NULL ||
            memcmp(walked_instructions[current_index].resolved_ports[p].account,
                   target,
                   PUBKEY_SIZE) != 0) {
            continue;
        }
        if (!port_effect_covered_somewhere(&walked_instructions[current_index].resolved_ports[p],
                                           target,
                                           survivors,
                                           walked_instructions,
                                           count,
                                           current_index)) {
            ports_covered = false;
        }
    }

    // Every reset the hidden instruction declares on the target must be consumed by a survivor.
    bool resets_covered = true;
    for (size_t r = 0; r < walked_instructions[current_index].resolved_reset_count; r++) {
        if (walked_instructions[current_index].resolved_resets[r].account == NULL ||
            memcmp(walked_instructions[current_index].resolved_resets[r].account,
                   target,
                   PUBKEY_SIZE) != 0) {
            continue;
        }
        if (!reset_effect_covered_somewhere(current_index,
                                            r,
                                            target,
                                            survivors,
                                            walked_instructions,
                                            count,
                                            scratch)) {
            resets_covered = false;
        }
    }

    // A mint the hidden instruction binds the target to must be shown by a survivor's token.
    bool mint_covered = true;
    if (walked_instructions[current_index].has_resolved_mint_assoc &&
        memcmp(walked_instructions[current_index].mint_assoc_token_account, target, PUBKEY_SIZE) ==
            0) {
        mint_covered = mint_effect_covered_somewhere(
            target,
            walked_instructions[current_index].mint_assoc_mint,
            survivors,
            walked_instructions,
            count,
            current_index);
    }

    // An owner the hidden instruction binds the target to reduces on screen to the account being
    // rendered by a survivor.
    bool owner_covered = true;
    if (walked_instructions[current_index].has_resolved_owner_assoc &&
        memcmp(walked_instructions[current_index].owner_assoc_token_account, target, PUBKEY_SIZE) ==
            0) {
        owner_covered = account_displayed_somewhere(target,
                                                    survivors,
                                                    walked_instructions,
                                                    count,
                                                    current_index);
    }

    bool represented = account_represented_by_survivor(target,
                                                       survivors,
                                                       walked_instructions,
                                                       count,
                                                       current_index,
                                                       scratch);
    PRINTF(
        "condition_account_effects_displayed_elsewhere: instruction %d represented=%d ports=%d "
        "resets=%d mint=%d owner=%d\n",
        (int) current_index,
        represented,
        ports_covered,
        resets_covered,
        mint_covered,
        owner_covered);
    return represented && ports_covered && resets_covered && mint_covered && owner_covered;
}

// Evaluate one HIDE_RULE condition against its resolved target.
static bool hide_condition_holds(uint8_t condition,
                                 const uint8_t *target,
                                 const cs_instruction_result_t *walked_instructions,
                                 size_t count,
                                 size_t instruction_index,
                                 const cs_merge_context_t *context,
                                 const bool *survivors,
                                 const merge_scratch_t *scratch) {
    PRINTF("hide_condition_holds: condition=%d\n", condition);
    bool holds = false;
    switch (condition) {
        case CS_HIDE_CONDITION_CREATED_IN_TRANSACTION:
            holds = condition_created_in_transaction(walked_instructions, count, target);
            break;
        case CS_HIDE_CONDITION_IS_SIGNER:
            holds = condition_is_device_signer(target, context);
            break;
        case CS_HIDE_CONDITION_ACCOUNT_USED_ELSEWHERE:
            holds = condition_account_used_elsewhere(walked_instructions,
                                                     count,
                                                     instruction_index,
                                                     target);
            break;
        case CS_HIDE_CONDITION_IS_ANOTHER_SIGNER:
            holds = condition_is_another_signer(target, context);
            break;
        case CS_HIDE_CONDITION_ACCOUNT_EFFECTS_DISPLAYED_ELSEWHERE:
            holds = condition_account_effects_displayed_elsewhere(target,
                                                                  survivors,
                                                                  walked_instructions,
                                                                  count,
                                                                  instruction_index,
                                                                  scratch);
            break;
        default:
            PRINTF("hide_condition_holds: unexpected condition %d, stays false\n", condition);
            holds = false;
            break;
    }
    return holds;
}

// ============================================================================
// Annotate stage
// ============================================================================

// Evaluate one ACTIVE_WHEN predicate against the port it guards. `mint` is the 32-byte
// operand of a MINT_PREDICATE, NULL for the port-account conditions.
static bool active_when_predicate_holds(uint8_t opcode,
                                        const uint8_t *mint,
                                        const cs_resolved_port_t *resolved_port,
                                        const cs_instruction_result_t *walked_instructions,
                                        size_t count,
                                        size_t instruction_index,
                                        const cs_merge_context_t *context) {
    PRINTF("active_when_predicate_holds: opcode=%d\n", opcode);
    bool holds = false;
    switch (opcode) {
        case CS_ACTIVE_WHEN_CREATED_IN_TRANSACTION:
            holds = condition_created_in_transaction(walked_instructions,
                                                     count,
                                                     resolved_port->account);
            break;
        case CS_ACTIVE_WHEN_IS_SIGNER:
            holds = condition_is_device_signer(resolved_port->account, context);
            break;
        case CS_ACTIVE_WHEN_ACCOUNT_USED_ELSEWHERE:
            holds = condition_account_used_elsewhere(walked_instructions,
                                                     count,
                                                     instruction_index,
                                                     resolved_port->account);
            break;
        case CS_ACTIVE_WHEN_MINT_PREDICATE:
            // The port must have resolved a mint, and it must be the one the predicate names.
            holds = (resolved_port->mint != NULL &&
                     memcmp(resolved_port->mint, mint, PUBKEY_SIZE) == 0);
            break;
        case CS_ACTIVE_WHEN_IS_ANOTHER_SIGNER:
            holds = condition_is_another_signer(resolved_port->account, context);
            break;
        default:
            PRINTF("active_when_predicate_holds: unexpected opcode %d\n", opcode);
            holds = false;
            break;
    }
    return holds;
}

// Decode and evaluate one port's ACTIVE_WHEN predicate stream, and exclude the port unless
// every predicate holds. The stream is a sequence of one-byte opcodes; MINT_PREDICATE
// carries a 32-byte operand, the rest none. Returns 0, -1 on a malformed stream.
static int annotate_one_port(cs_resolved_port_t *resolved_port,
                             const cs_value_flow_port_t *template_port,
                             const cs_instruction_result_t *walked_instructions,
                             size_t count,
                             size_t instruction_index,
                             const cs_merge_context_t *context) {
    // A port with no ACTIVE_WHEN keeps the loop below unentered, so it stays included.
    size_t offset = 0;
    bool all_hold = true;
    while (offset < template_port->active_when_size && all_hold) {
        uint8_t opcode = template_port->active_when[offset];
        offset++;
        const uint8_t *mint = NULL;
        if (opcode == CS_ACTIVE_WHEN_MINT_PREDICATE) {
            // The operand is the mint the port's token must resolve to.
            if (template_port->active_when_size - offset < PUBKEY_SIZE) {
                PRINTF("annotate_one_port: truncated MINT_PREDICATE operand\n");
                return -1;
            }
            mint = &template_port->active_when[offset];
            offset += PUBKEY_SIZE;
        } else if (opcode != CS_ACTIVE_WHEN_CREATED_IN_TRANSACTION &&
                   opcode != CS_ACTIVE_WHEN_IS_SIGNER &&
                   opcode != CS_ACTIVE_WHEN_ACCOUNT_USED_ELSEWHERE &&
                   opcode != CS_ACTIVE_WHEN_IS_ANOTHER_SIGNER) {
            PRINTF("annotate_one_port: unknown ACTIVE_WHEN opcode %d\n", opcode);
            return -1;
        }
        if (!active_when_predicate_holds(opcode,
                                         mint,
                                         resolved_port,
                                         walked_instructions,
                                         count,
                                         instruction_index,
                                         context)) {
            all_hold = false;
        }
    }
    resolved_port->excluded = !all_hold;
    PRINTF("annotate_one_port: instruction %d excluded=%d\n", (int) instruction_index, !all_hold);
    return 0;
}

// Evaluate every port's ACTIVE_WHEN predicates so an excluded port is invisible to the merge
// scan and the renderer, as if the descriptor had never declared it. Returns 0, -1 on a
// malformed predicate stream.
static int annotate_ports(cs_instruction_result_t *walked_instructions,
                          size_t count,
                          const cs_merge_context_t *context) {
    // Every port starts included before any predicate runs, so a condition that reads another
    // port's exclusion never depends on evaluation order having reached it yet.
    for (size_t i = 0; i < count; i++) {
        for (size_t p = 0; p < walked_instructions[i].resolved_port_count; p++) {
            walked_instructions[i].resolved_ports[p].excluded = false;
        }
    }
    for (size_t i = 0; i < count; i++) {
        for (size_t p = 0; p < walked_instructions[i].resolved_port_count; p++) {
            if (annotate_one_port(&walked_instructions[i].resolved_ports[p],
                                  &walked_instructions[i].template->ports[p],
                                  walked_instructions,
                                  count,
                                  i,
                                  context) != 0) {
                PRINTF("annotate_ports: instruction %d port %d predicate stream invalid\n",
                       (int) i,
                       (int) p);
                return -1;
            }
        }
    }
    return 0;
}

// ============================================================================
// Hide stage
// ============================================================================

// Whether every HIDE_RULE sharing `set_index` holds, so the rule set passes. The rules of a
// set are ANDed.
static bool hide_rule_set_passes(const cs_instruction_result_t *walked_instructions,
                                 size_t count,
                                 size_t instruction_index,
                                 uint8_t set_index,
                                 const cs_merge_context_t *context,
                                 const bool *survivors,
                                 const merge_scratch_t *scratch) {
    const cs_instruction_template_t *template = walked_instructions[instruction_index].template;
    for (size_t r = 0; r < template->hide_rule_count; r++) {
        if (template->hide_rules[r].rule_set_index != set_index) {
            continue;
        }
        if (!hide_condition_holds(
                template->hide_rules[r].condition,
                walked_instructions[instruction_index].resolved_hide_rules[r].target,
                walked_instructions,
                count,
                instruction_index,
                context,
                survivors,
                scratch)) {
            PRINTF("hide_rule_set_passes: rule %d of set %d fails\n", (int) r, set_index);
            return false;
        }
    }
    PRINTF("hide_rule_set_passes: set %d passes\n", set_index);
    return true;
}

// Whether an instruction's HIDE_RULEs hide it: the rule sets are ORed, so the first set that
// passes hides it. Each set is evaluated once, at the first rule carrying its index.
static bool instruction_is_hidden(const cs_instruction_result_t *walked_instructions,
                                  size_t count,
                                  size_t instruction_index,
                                  const cs_merge_context_t *context,
                                  const bool *survivors,
                                  const merge_scratch_t *scratch) {
    const cs_instruction_template_t *template = walked_instructions[instruction_index].template;
    for (size_t h = 0; h < template->hide_rule_count; h++) {
        uint8_t set_index = template->hide_rules[h].rule_set_index;
        // Skip a set already reached through an earlier rule, so each set is judged once.
        bool first_of_set = true;
        for (size_t k = 0; k < h; k++) {
            if (template->hide_rules[k].rule_set_index == set_index) {
                first_of_set = false;
            }
        }
        if (first_of_set && hide_rule_set_passes(walked_instructions,
                                                 count,
                                                 instruction_index,
                                                 set_index,
                                                 context,
                                                 survivors,
                                                 scratch)) {
            PRINTF("instruction_is_hidden: instruction %d hidden by set %d\n",
                   (int) instruction_index,
                   set_index);
            return true;
        }
    }
    return false;
}

// Drop from the output every merge survivor whose HIDE_RULEs hide it, so its plumbing never
// reaches the screen. Runs after the scan, over survivors, so a merged-away instruction is
// never reconsidered. A rule set is judged against the survivors still standing, so an
// accountEffectsDisplayedElsewhere rule reasons about who is left on screen.
static void apply_hide_rules(const cs_instruction_result_t *walked_instructions,
                             size_t count,
                             const cs_merge_context_t *context,
                             const merge_scratch_t *scratch,
                             bool *survivors) {
    for (size_t i = 0; i < count; i++) {
        // A survivor with no template carries no HIDE_RULEs, so nothing can hide it.
        if (survivors[i] && walked_instructions[i].template != NULL &&
            walked_instructions[i].template->hide_rule_count > 0 &&
            instruction_is_hidden(walked_instructions, count, i, context, survivors, scratch)) {
            PRINTF("apply_hide_rules: instruction %d hidden\n", (int) i);
            survivors[i] = false;
        }
    }
}

// ============================================================================
// Entry point
// ============================================================================

// Count the ACCOUNT_RESET declarations in the whole transaction.
static size_t total_reset_count(const cs_instruction_result_t *walked_instructions, size_t count) {
    // Sizes both reset-derived maps: each declaration adds at most one safe-account entry
    // and claims at most one known-balance slot.
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        total += walked_instructions[i].resolved_reset_count;
    }
    PRINTF("total_reset_count: %d\n", (int) total);
    return total;
}

// Find the largest number of ports any one instruction declares.
static size_t max_port_count(const cs_instruction_result_t *walked_instructions, size_t count) {
    // Sizes the guard's account scratch: a junction reaches across two instructions, and
    // neither can contribute more accounts than it has ports.
    size_t max = 0;
    for (size_t i = 0; i < count; i++) {
        if (walked_instructions[i].resolved_port_count > max) {
            max = walked_instructions[i].resolved_port_count;
        }
    }
    PRINTF("max_port_count: %d\n", (int) max);
    return max;
}

// Allocate the merge scratch: per-instruction state with its own chain history, the
// safe-account set and the known-balance map. Returns 0, -1 on allocation failure
// (the caller frees whatever was allocated).
static int merge_scratch_allocate(merge_scratch_t *scratch, size_t count, size_t reset_count) {
    // The histories are one block rather than an allocation each, so freeing cannot
    // half-succeed and the state array can be handed out with slices already pointing
    // into it.
    if (!APP_MEM_CALLOC((void **) &scratch->states, count * sizeof(*scratch->states)) ||
        !APP_MEM_CALLOC((void **) &scratch->history, count * count * sizeof(*scratch->history))) {
        PRINTF("merge_scratch_allocate: state allocation failed\n");
        return -1;
    }
    // Every instruction starts out accounting for itself, which is what makes the guard
    // skip the two participants of a merge without naming them separately.
    for (size_t i = 0; i < count; i++) {
        scratch->states[i].merged_from = &scratch->history[i * count];
        scratch->states[i].merged_from[i] = true;
    }
    // A transaction with no resets needs neither map, and asking for zero bytes is not
    // worth doing.
    if (reset_count > 0 && (!APP_MEM_CALLOC((void **) &scratch->safe_accounts,
                                            reset_count * sizeof(*scratch->safe_accounts)) ||
                            !APP_MEM_CALLOC((void **) &scratch->known_balances,
                                            reset_count * sizeof(*scratch->known_balances)))) {
        PRINTF("merge_scratch_allocate: reset map allocation failed\n");
        return -1;
    }
    return 0;
}

// Release everything one merge run took.
static void merge_scratch_free(merge_scratch_t *scratch) {
    // Reverse order of allocation, and every pointer is tested: an allocation that
    // short-circuited half way leaves some of these NULL.
    PRINTF("merge_scratch_free: releasing the merge scratch\n");
    if (scratch->known_balances != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &scratch->known_balances);
    }
    if (scratch->safe_accounts != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &scratch->safe_accounts);
    }
    if (scratch->history != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &scratch->history);
    }
    if (scratch->states != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &scratch->states);
    }
}

// Run the merge itself, with the scratch already allocated. Returns 0, -1 on failure.
static int merge_engine_run_inner(cs_instruction_result_t *walked_instructions,
                                  size_t count,
                                  merge_scratch_t *scratch,
                                  const uint8_t **symbolic_accounts,
                                  const cs_merge_context_t *context,
                                  bool *survivors) {
    // Annotate first: excluding a port changes the balances the next pass reads and the
    // junctions the scan meets, so it has to settle the port set before either runs.
    if (annotate_ports(walked_instructions, count, context) != 0) {
        PRINTF("merge_engine_run_inner: port annotation failed\n");
        return -1;
    }
    // The order of the next two is forced. Balances have to settle before the scan, because
    // whether a leg reads as a number decides which rule its junction takes; the safe-account
    // set has to exist before the first guard runs.
    resolve_balance_amounts(walked_instructions, count, scratch);
    build_safe_accounts(walked_instructions, count, scratch);
    run_merge_scan(walked_instructions, count, scratch, symbolic_accounts);

    // The scan marks what disappeared; the renderer is told what remains.
    for (size_t i = 0; i < count; i++) {
        survivors[i] = !scratch->states[i].consumed;
        PRINTF("merge_engine_run_inner: instruction %d survives=%d\n", (int) i, survivors[i]);
    }

    // Hide last, over survivors only: a HIDE_RULE reasons about the post-merge account set,
    // and a merged-away instruction has no screen to remove.
    apply_hide_rules(walked_instructions, count, context, scratch, survivors);
    return 0;
}

int cs_merge_engine_run(cs_instruction_result_t *walked_instructions,
                        size_t walked_instructions_count,
                        const cs_merge_context_t *context,
                        bool *survivors) {
    PRINTF("cs_merge_engine_run: %d instructions\n", (int) walked_instructions_count);
    if (walked_instructions == NULL && walked_instructions_count > 0) {
        PRINTF("cs_merge_engine_run: NULL input with non-zero count\n");
        return -1;
    }
    if (survivors == NULL && walked_instructions_count > 0) {
        PRINTF("cs_merge_engine_run: NULL survivors output\n");
        return -1;
    }
    // An empty transaction is not an error, and returning here keeps every allocation
    // below away from a zero size.
    if (walked_instructions_count == 0) {
        PRINTF("cs_merge_engine_run: nothing to merge\n");
        return 0;
    }

    // Zeroed up front so the free path can run over a partly-built scratch.
    merge_scratch_t scratch;
    memset(&scratch, 0, sizeof(scratch));
    const uint8_t **symbolic_accounts = NULL;
    int rc = merge_scratch_allocate(
        &scratch,
        walked_instructions_count,
        total_reset_count(walked_instructions, walked_instructions_count));
    if (rc == 0) {
        // Allocated once for the whole run rather than per guard call: the guard fills it
        // and reads the count back, so nothing carries over between calls.
        size_t symbolic_capacity = 2 *
                                   max_port_count(walked_instructions, walked_instructions_count);
        if (symbolic_capacity > 0 &&
            !APP_MEM_CALLOC((void **) &symbolic_accounts,
                            symbolic_capacity * sizeof(*symbolic_accounts))) {
            PRINTF("cs_merge_engine_run: symbolic account scratch allocation failed\n");
            rc = -1;
        }
    }
    if (rc == 0) {
        rc = merge_engine_run_inner(walked_instructions,
                                    walked_instructions_count,
                                    &scratch,
                                    symbolic_accounts,
                                    context,
                                    survivors);
    }

    if (symbolic_accounts != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &symbolic_accounts);
    }
    merge_scratch_free(&scratch);

    PRINTF("cs_merge_engine_run: done rc=%d\n", rc);
    return rc;
}
