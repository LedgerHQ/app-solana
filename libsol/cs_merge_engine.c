#include <stdint.h>
#include <string.h>

#include "cs_merge_engine.h"
#include "cs_instruction_template.h"
#include "idl_kinds.h"
#include "os_print.h"
#include "util.h"

// Index into `resolved_ports` of the nth port whose template direction matches,
// or SIZE_MAX when the item has fewer than n+1 ports of that direction.
static size_t nth_directional_port_index(const cs_instruction_result_t *item,
                                         uint8_t direction,
                                         size_t n) {
    PRINTF("nth_directional_port_index: direction=%d n=%zu\n", direction, n);
    size_t seen = 0;
    for (size_t p = 0; p < item->resolved_port_count; p++) {
        if (item->template->ports[p].direction == direction) {
            if (seen == n) {
                PRINTF("nth_directional_port_index: found at p=%zu\n", p);
                return p;
            }
            seen++;
        }
    }
    PRINTF("nth_directional_port_index: no port #%zu of direction %d\n", n, direction);
    return SIZE_MAX;
}

// The nth resolved port of a given direction, or NULL when out of range.
static const cs_resolved_port_t *nth_directional_port(const cs_instruction_result_t *item,
                                                      uint8_t direction,
                                                      size_t n) {
    size_t index = nth_directional_port_index(item, direction, n);
    if (index == SIZE_MAX) {
        PRINTF("nth_directional_port: out of range\n");
        return NULL;
    }
    PRINTF("nth_directional_port: index=%zu\n", index);
    return &item->resolved_ports[index];
}

// Number of resolved ports of a given direction.
static size_t count_directional_ports(const cs_instruction_result_t *item, uint8_t direction) {
    size_t count = 0;
    for (size_t p = 0; p < item->resolved_port_count; p++) {
        if (item->template->ports[p].direction == direction) {
            count++;
        }
    }
    PRINTF("count_directional_ports: direction=%d count=%zu\n", direction, count);
    return count;
}

// Decode a little-endian unsigned amount (u8/u16/u32/u64) into a u64. Returns 0,
// -1 on an unsupported leaf kind or truncated bytes.
static int decode_le_amount(const uint8_t *amount_le,
                            size_t amount_size,
                            uint8_t leaf_kind,
                            uint64_t *out) {
    size_t width = 0;
    switch (leaf_kind) {
        case IDL_KIND_U8:
            width = 1;
            break;
        case IDL_KIND_U16:
            width = 2;
            break;
        case IDL_KIND_U32:
            width = 4;
            break;
        case IDL_KIND_U64:
            width = 8;
            break;
        default:
            PRINTF("decode_le_amount: unsupported leaf kind=%d\n", leaf_kind);
            return -1;
    }
    if (amount_le == NULL || amount_size < width) {
        PRINTF("decode_le_amount: truncated (size=%zu width=%zu)\n", amount_size, width);
        return -1;
    }
    *out = 0;
    for (size_t i = 0; i < width; i++) {
        *out |= (uint64_t) amount_le[i] << (8 * i);
    }
    PRINTF("decode_le_amount: width=%zu ok\n", width);
    return 0;
}

// Two junction tokens are compatible when they name the same mint, or either
// side has no resolved mint (unknown token identity).
static bool tokens_compatible(const cs_resolved_port_t *output_port,
                              const cs_resolved_port_t *input_port) {
    if (output_port->mint == NULL || input_port->mint == NULL) {
        PRINTF("tokens_compatible: a mint unresolved, treated compatible\n");
        return true;
    }
    if (memcmp(output_port->mint, input_port->mint, 32) != 0) {
        PRINTF("tokens_compatible: mint mismatch\n");
        return false;
    }
    PRINTF("tokens_compatible: same mint\n");
    return true;
}

// A junction pair lines up when both legs resolved to the same account, carry the
// same value kind, and reference compatible tokens. Requiring identical value
// kinds excludes form-changing transformers (e.g. native -> SPL), whose handling
// is a later addition.
static bool junction_pair_matches(const cs_resolved_port_t *output_port,
                                  const cs_resolved_port_t *input_port) {
    if (!output_port->resolved || !input_port->resolved) {
        PRINTF("junction_pair_matches: unresolved port\n");
        return false;
    }
    if (output_port->account == NULL || input_port->account == NULL) {
        PRINTF("junction_pair_matches: missing account\n");
        return false;
    }
    if (memcmp(output_port->account, input_port->account, 32) != 0) {
        PRINTF("junction_pair_matches: accounts differ\n");
        return false;
    }
    if (output_port->value_kind != input_port->value_kind) {
        PRINTF("junction_pair_matches: value kinds differ (%d vs %d)\n",
               output_port->value_kind,
               input_port->value_kind);
        return false;
    }
    PRINTF("junction_pair_matches: account and kind match, checking tokens\n");
    return tokens_compatible(output_port, input_port);
}

// Rule 1 junction: both legs carry a concrete NUMERIC amount and those amounts
// are equal, so the upstream leg provably relays its value untouched.
static bool junction_pair_is_exact_relay(const cs_resolved_port_t *output_port,
                                         const cs_resolved_port_t *input_port) {
    if (output_port->amount_kind != CS_AMOUNT_KIND_NUMERIC ||
        input_port->amount_kind != CS_AMOUNT_KIND_NUMERIC) {
        PRINTF("junction_pair_is_exact_relay: not NUMERIC on both sides\n");
        return false;
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
        PRINTF("junction_pair_is_exact_relay: amount decode failed\n");
        return false;
    }
    if (output_amount != input_amount) {
        PRINTF("junction_pair_is_exact_relay: amounts differ\n");
        return false;
    }
    PRINTF("junction_pair_is_exact_relay: exact relay\n");
    return true;
}

// Whether `upstream`'s outputs form an exact numeric pass-through into
// `downstream`'s inputs: equal, non-empty leg count with matching accounts,
// kinds, tokens and equal amounts on every leg, and `upstream` a pure conduit
// (equal input/output leg count). Such an `upstream` only relays value and can
// be dropped, leaving `downstream` to carry the intent.
static bool is_exact_pass_through(const cs_instruction_result_t *upstream,
                                  const cs_instruction_result_t *downstream) {
    size_t output_count = count_directional_ports(upstream, CS_PORT_DIRECTION_OUTPUT);
    size_t input_count = count_directional_ports(downstream, CS_PORT_DIRECTION_INPUT);
    if (output_count == 0 || output_count != input_count) {
        PRINTF("is_exact_pass_through: rejected, out=%zu in=%zu\n", output_count, input_count);
        return false;
    }
    if (count_directional_ports(upstream, CS_PORT_DIRECTION_INPUT) != output_count) {
        PRINTF("is_exact_pass_through: rejected, upstream not a pure conduit\n");
        return false;
    }
    for (size_t leg = 0; leg < output_count; leg++) {
        const cs_resolved_port_t *output_port =
            nth_directional_port(upstream, CS_PORT_DIRECTION_OUTPUT, leg);
        const cs_resolved_port_t *input_port =
            nth_directional_port(downstream, CS_PORT_DIRECTION_INPUT, leg);
        if (output_port == NULL || input_port == NULL) {
            PRINTF("is_exact_pass_through: rejected, leg %zu unresolved\n", leg);
            return false;
        }
        if (!junction_pair_matches(output_port, input_port)) {
            PRINTF("is_exact_pass_through: rejected, leg %zu mismatch\n", leg);
            return false;
        }
        if (!junction_pair_is_exact_relay(output_port, input_port)) {
            PRINTF("is_exact_pass_through: rejected, leg %zu not an exact relay\n", leg);
            return false;
        }
    }
    PRINTF("is_exact_pass_through: confirmed over %zu legs\n", output_count);
    return true;
}

int cs_merge_engine_run(const cs_instruction_result_t *walked_instructions,
                        size_t walked_instructions_count,
                        const cs_merge_context_t *context,
                        bool *survivors) {
    UNUSED(context);
    PRINTF("cs_merge_engine_run: %zu instructions\n", walked_instructions_count);
    if (walked_instructions == NULL && walked_instructions_count > 0) {
        PRINTF("cs_merge_engine_run: NULL input with non-zero count\n");
        return -1;
    }
    if (survivors == NULL && walked_instructions_count > 0) {
        PRINTF("cs_merge_engine_run: NULL survivors output\n");
        return -1;
    }

    for (size_t i = 0; i < walked_instructions_count; i++) {
        survivors[i] = true;
    }

    // Rule 1 over physically adjacent instructions: when the upstream one is a
    // pure conduit relaying an exact numeric amount into the next, drop it so the
    // downstream instruction carries the intent. Restricting to adjacent pairs
    // means no dropped instruction can hide an intervening writer; non-adjacent
    // chains and the writable-overlap guard are a later addition.
    for (size_t upstream = 0; upstream + 1 < walked_instructions_count; upstream++) {
        size_t downstream = upstream + 1;
        if (is_exact_pass_through(&walked_instructions[upstream],
                                  &walked_instructions[downstream])) {
            survivors[upstream] = false;
            PRINTF("cs_merge_engine_run: instruction %zu relays into %zu, dropped (rule 1)\n",
                   upstream,
                   downstream);
        } else {
            PRINTF("cs_merge_engine_run: instruction %zu kept\n", upstream);
        }
    }

    PRINTF("cs_merge_engine_run: done\n");
    return 0;
}
