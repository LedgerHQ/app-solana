// Unit tests for cs_merge_engine.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cs_merge_engine.h"
#include "cs_instruction_template.h"
#include "cs_token_account_cache.h"
#include "app_mem_utils.h"
#include "idl_kinds.h"

#define MAX_TEST_PORTS    4
#define MAX_TEST_RESETS   2
#define MAX_TEST_WRITABLE 4

// An item plus its backing template and substructure storage. Production
// heap-allocates these; tests back them with fixed local storage and wire the
// pointers.
typedef struct test_item_s {
    cs_instruction_result_t result;
    cs_instruction_template_t template;
    cs_value_flow_port_t ports[MAX_TEST_PORTS];
    cs_resolved_port_t resolved_ports[MAX_TEST_PORTS];
    cs_account_reset_t resets[MAX_TEST_RESETS];
    cs_resolved_reset_t resolved_resets[MAX_TEST_RESETS];
    const uint8_t *writable_accounts[MAX_TEST_WRITABLE];
} test_item_t;

static void item_init(test_item_t *item) {
    memset(item, 0, sizeof(*item));
    item->template.ports = item->ports;
    item->template.account_resets = item->resets;
    item->result.template = &item->template;
    item->result.resolved_ports = item->resolved_ports;
    item->result.resolved_resets = item->resolved_resets;
    item->result.writable_accounts = item->writable_accounts;
    // What the finalize walk reports when every writable account resolved, which is
    // always the case for a legacy transaction and for a completely attested v0 one.
    // Tests that exercise an unresolved writable account clear it explicitly.
    item->result.writable_complete = true;
}

// Append a resolved port carrying a concrete little-endian u64 amount and no token
// identity: the shape of a plain native transfer leg.
static void item_add_port(test_item_t *item,
                          uint8_t direction,
                          const uint8_t *account,
                          const uint8_t *amount_le) {
    size_t p = item->template.port_count;
    assert(p < MAX_TEST_PORTS);
    item->ports[p].direction = direction;
    item->resolved_ports[p].resolved = true;
    item->resolved_ports[p].account = account;
    item->resolved_ports[p].account_index = (uint8_t) p;
    item->resolved_ports[p].value_kind = CS_PORT_VALUE_KIND_NATIVE;
    item->resolved_ports[p].amount_kind = CS_AMOUNT_KIND_NUMERIC;
    item->resolved_ports[p].amount_le = amount_le;
    item->resolved_ports[p].amount_size = 8;
    item->resolved_ports[p].amount_leaf_kind = IDL_KIND_U64;
    item->resolved_ports[p].token_kind = CS_TOKEN_KIND_NULL;
    item->template.port_count++;
    item->result.resolved_port_count = item->template.port_count;
}

// Append a resolved port that drains or fills the whole balance of an account, the
// amount the instruction data does not carry.
static void item_add_balance_port(test_item_t *item, uint8_t direction, const uint8_t *account) {
    item_add_port(item, direction, account, NULL);
    size_t p = item->template.port_count - 1;
    item->ports[p].amount.kind = CS_AMOUNT_KIND_BALANCE;
    item->resolved_ports[p].amount_kind = CS_AMOUNT_KIND_BALANCE;
    item->resolved_ports[p].amount_size = 0;
}

// Give one port a token identity.
static void item_set_port_mint(test_item_t *item, size_t port_index, const uint8_t *mint) {
    assert(port_index < item->template.port_count);
    item->resolved_ports[port_index].token_kind = CS_TOKEN_KIND_DIRECT;
    item->resolved_ports[port_index].mint = mint;
}

static void item_set_port_value_kind(test_item_t *item, size_t port_index, uint8_t value_kind) {
    assert(port_index < item->template.port_count);
    item->resolved_ports[port_index].value_kind = value_kind;
}

// Append an ACCOUNT_RESET establishing a balance for an account. A NULL amount
// stands for an absent RESET_VALUE, which the spec reads as an implicit zero.
static void item_add_reset(test_item_t *item, const uint8_t *account, const uint8_t *amount_le) {
    size_t r = item->template.account_reset_count;
    assert(r < MAX_TEST_RESETS);
    item->resolved_resets[r].account = account;
    if (amount_le != NULL) {
        item->resolved_resets[r].has_amount = true;
        item->resolved_resets[r].amount_le = amount_le;
        item->resolved_resets[r].amount_size = 8;
        item->resolved_resets[r].amount_leaf_kind = IDL_KIND_U64;
        item->resets[r].has_reset_value = true;
    }
    item->template.account_reset_count++;
    item->result.resolved_reset_count = item->template.account_reset_count;
}

static void item_set_last_reset_requires_zero_pre_balance(test_item_t *item) {
    assert(item->template.account_reset_count > 0);
    item->resets[item->template.account_reset_count - 1].require_pre_balance_zero = true;
}

// Restrict the last reset to consumers of one program, optionally to instructions
// whose data starts with one of the given discriminator prefixes.
static void item_set_last_reset_scope(test_item_t *item,
                                      const uint8_t *program_id,
                                      cs_reset_discriminator_t *discriminators,
                                      size_t discriminator_count) {
    assert(item->template.account_reset_count > 0);
    size_t r = item->template.account_reset_count - 1;
    item->resets[r].has_scope = true;
    item->resets[r].scope.has_program_id = true;
    memcpy(item->resets[r].scope.scope_program_id, program_id, 32);
    item->resets[r].scope.discriminators = discriminators;
    item->resets[r].scope.discriminator_count = discriminator_count;
}

// Identify the instruction the way the finalize walk does, so a reset scope can
// match (or refuse) it.
static void item_set_identity(test_item_t *item,
                              const uint8_t *program_id,
                              const uint8_t *instruction_data,
                              size_t instruction_data_size) {
    memcpy(item->template.program_id, program_id, 32);
    item->result.instruction_data = instruction_data;
    item->result.instruction_data_size = instruction_data_size;
}

static void item_add_writable(test_item_t *item, const uint8_t *account) {
    assert(item->result.writable_account_count < MAX_TEST_WRITABLE);
    item->writable_accounts[item->result.writable_account_count] = account;
    item->result.writable_account_count++;
}

// 32-byte pubkey fixtures, distinguished by their first byte.
static const uint8_t ACCT_SOURCE[32] = {0xA0};
static const uint8_t ACCT_JUNCTION[32] = {0xB0};
static const uint8_t ACCT_DEST[32] = {0xC0};
static const uint8_t ACCT_OTHER[32] = {0xD0};
static const uint8_t ACCT_FAR[32] = {0xE0};

static const uint8_t MINT_X[32] = {0x11};
static const uint8_t MINT_Y[32] = {0x22};
static const uint8_t MINT_Z[32] = {0x33};

static const uint8_t PROGRAM_TOKEN[32] = {0x51};
static const uint8_t PROGRAM_OTHER[32] = {0x52};

// Little-endian u64 amount fixtures.
static const uint8_t AMT_0[8] = {0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t AMT_50[8] = {50, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t AMT_100[8] = {100, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t AMT_101[8] = {101, 0, 0, 0, 0, 0, 0, 0};

// Instruction data of the wrap instruction used by the symbolic-junction fixtures.
static const uint8_t WRAP_DATA[4] = {0x11, 0x22, 0x33, 0x44};

// ---- Fixtures shared by the symbolic-junction tests -------------------------

// The wrap shape: a lamport transfer whose destination the next instruction reads
// as a token balance, converting the form of the value without naming an amount.
//
//   create      out (junction, 0, no token) + reset(junction)
//   transfer    in (source, 100)   -> out (junction, 100)
//   wrap        in (junction, all) -> out (junction, all as MINT_X)
//
// The reset is what lets the device trust the junction balance; every test below
// varies one part of that trust and checks the collapse follows.
static void build_wrap_chain(test_item_t *create, test_item_t *transfer, test_item_t *wrap) {
    item_init(create);
    item_init(transfer);
    item_init(wrap);

    item_add_port(create, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_0);
    item_add_reset(create, ACCT_JUNCTION, NULL);

    item_add_port(transfer, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(transfer, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);

    item_add_balance_port(wrap, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION);
    item_add_balance_port(wrap, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION);
    item_set_port_value_kind(wrap, 1, CS_PORT_VALUE_KIND_SPL_TOKEN);
    item_set_port_mint(wrap, 1, MINT_X);
    item_set_identity(wrap, PROGRAM_TOKEN, WRAP_DATA, sizeof(WRAP_DATA));
}

// ---- Entry-point guards -----------------------------------------------------

// Instructions that declare no value flow at all cannot form a junction.
static void test_no_ports_all_survive(void) {
    printf("  test_no_ports_all_survive\n");
    mock_mem_reset();

    cs_instruction_result_t instrs[3];
    memset(instrs, 0, sizeof(instrs));
    bool survivors[3] = {false, false, false};

    assert(cs_merge_engine_run(instrs, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    assert(mock_mem_outstanding() == 0);
}

static void test_zero_instructions(void) {
    printf("  test_zero_instructions\n");
    mock_mem_reset();

    assert(cs_merge_engine_run(NULL, 0, NULL, NULL) == 0);
    assert(mock_mem_outstanding() == 0);
}

static void test_null_with_nonzero_count(void) {
    printf("  test_null_with_nonzero_count\n");

    bool survivors[1];
    assert(cs_merge_engine_run(NULL, 3, NULL, survivors) == -1);
}

static void test_null_survivors_with_nonzero_count(void) {
    printf("  test_null_survivors_with_nonzero_count\n");

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    assert(cs_merge_engine_run(&instr, 1, NULL, NULL) == -1);
}

static void test_single_instruction(void) {
    printf("  test_single_instruction\n");
    mock_mem_reset();

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    bool survivor = false;

    assert(cs_merge_engine_run(&instr, 1, NULL, &survivor) == 0);
    assert(survivor == true);
    assert(mock_mem_outstanding() == 0);
}

// The scratch allocation cannot be satisfied: the run reports failure and leaks
// nothing.
static void test_scratch_allocation_failure(void) {
    printf("  test_scratch_allocation_failure\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {true, true};

    mock_mem_fail_after(0);
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == -1);
    mock_mem_fail_after(-1);
    assert(mock_mem_outstanding() == 0);
}

// The first scratch allocation succeeds and a later one fails: the free path must
// still release what was taken.
static void test_partial_allocation_failure(void) {
    printf("  test_partial_allocation_failure\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {true, true};

    mock_mem_fail_after(1);
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == -1);
    mock_mem_fail_after(-1);
    assert(mock_mem_outstanding() == 0);
}

// ---- Exact relay ------------------------------------------------------------

// A -> junction -> B relaying the exact same amount: A is dropped, and B's input
// leg takes on A's source so the review names the real origin.
static void test_exact_relay_collapses_and_propagates(void) {
    printf("  test_exact_relay_collapses_and_propagates\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == false);
    assert(survivors[1] == true);
    assert(items[1].resolved_ports[0].account == ACCT_SOURCE);
    // The rewritten leg keeps the survivor's own accounts-array slot, which is what
    // the display renderer matches a field override against.
    assert(items[1].resolved_ports[0].account_index == 0);
    assert(mock_mem_outstanding() == 0);
}

// Junction amounts differ: not a relay, both survive.
static void test_exact_relay_amount_mismatch(void) {
    printf("  test_exact_relay_amount_mismatch\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_101);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_101);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(mock_mem_outstanding() == 0);
}

// Upstream output and downstream input name different accounts: no junction.
static void test_account_mismatch(void) {
    printf("  test_account_mismatch\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_OTHER, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(mock_mem_outstanding() == 0);
}

// Same junction account and amount but incompatible mints: no merge.
static void test_token_mismatch(void) {
    printf("  test_token_mismatch\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);
    item_set_port_mint(&a, 1, MINT_X);
    item_set_port_mint(&b, 0, MINT_Y);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(mock_mem_outstanding() == 0);
}

// A junction may change the form of value: lamports land in an account the next
// instruction reads as an SPL balance. Both legs still declare the same concrete
// amount, so the relay collapses into the form-changing instruction, which is the
// one that carries the intent.
static void test_value_kind_change_collapses(void) {
    printf("  test_value_kind_change_collapses\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);
    item_set_port_value_kind(&b, 0, CS_PORT_VALUE_KIND_SPL_TOKEN);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == false);
    assert(survivors[1] == true);
    assert(items[1].resolved_ports[0].account == ACCT_SOURCE);
    assert(mock_mem_outstanding() == 0);
}

// The instruction to be folded away must pair its own sides one-for-one: an
// asymmetric one carries value the survivor could not account for.
static void test_asymmetric_consumed_refused(void) {
    printf("  test_asymmetric_consumed_refused\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_OTHER, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_OTHER, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(mock_mem_outstanding() == 0);
}

// A -> B -> C, each an exact relay: A and B drop, and C's input leg carries the
// origin propagated the whole way down the chain.
static void test_three_link_chain(void) {
    printf("  test_three_link_chain\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    test_item_t c;
    item_init(&a);
    item_init(&b);
    item_init(&c);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_OTHER, AMT_100);
    item_add_port(&c, CS_PORT_DIRECTION_INPUT, ACCT_OTHER, AMT_100);
    item_add_port(&c, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[3] = {a.result, b.result, c.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == false);
    assert(survivors[1] == false);
    assert(survivors[2] == true);
    assert(items[2].resolved_ports[0].account == ACCT_SOURCE);
    assert(mock_mem_outstanding() == 0);
}

// An instruction with no output ports never feeds a junction and always survives.
static void test_no_output_ports(void) {
    printf("  test_no_output_ports\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(mock_mem_outstanding() == 0);
}

// Legs of one junction that support different rules do not agree, so the junction
// supports none of them.
static void test_legs_disagree_on_rule(void) {
    printf("  test_legs_disagree_on_rule\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_balance_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_OTHER);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_OTHER, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(mock_mem_outstanding() == 0);
}

// ---- Scan reach -------------------------------------------------------------

// An unrelated instruction between the two legs of a chain does not prevent the
// collapse: it touches none of the junction accounts.
static void test_non_adjacent_chain_collapses(void) {
    printf("  test_non_adjacent_chain_collapses\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t unrelated;
    test_item_t b;
    item_init(&a);
    item_init(&unrelated);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&unrelated, CS_PORT_DIRECTION_INPUT, ACCT_OTHER, AMT_50);
    item_add_port(&unrelated, CS_PORT_DIRECTION_OUTPUT, ACCT_FAR, AMT_50);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[3] = {a.result, unrelated.result, b.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == false);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    assert(items[2].resolved_ports[0].account == ACCT_SOURCE);
    assert(mock_mem_outstanding() == 0);
}

// An instruction that may write the junction stops the scan: what it leaves in the
// account is unknown, so a later leg cannot be assumed to carry the same value.
static void test_writable_overlap_stops_the_scan(void) {
    printf("  test_writable_overlap_stops_the_scan\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t toucher;
    test_item_t b;
    item_init(&a);
    item_init(&toucher);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&toucher, CS_PORT_DIRECTION_INPUT, ACCT_OTHER, AMT_50);
    item_add_port(&toucher, CS_PORT_DIRECTION_OUTPUT, ACCT_FAR, AMT_50);
    item_add_writable(&toucher, ACCT_JUNCTION);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[3] = {a.result, toucher.result, b.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    assert(mock_mem_outstanding() == 0);
}

// An intervening instruction whose writable accounts could not all be resolved
// might write the junction, so the scan stops there too.
static void test_incomplete_writable_list_stops_the_scan(void) {
    printf("  test_incomplete_writable_list_stops_the_scan\n");
    mock_mem_reset();

    test_item_t a;
    test_item_t unresolved;
    test_item_t b;
    item_init(&a);
    item_init(&unresolved);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&unresolved, CS_PORT_DIRECTION_INPUT, ACCT_OTHER, AMT_50);
    item_add_port(&unresolved, CS_PORT_DIRECTION_OUTPUT, ACCT_FAR, AMT_50);
    unresolved.result.writable_complete = false;
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[3] = {a.result, unresolved.result, b.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    assert(mock_mem_outstanding() == 0);
}

// ---- Roles ------------------------------------------------------------------

// A transformer states what the movement achieves, so it survives even where the
// rule default would have folded it away. Without this the swap's intent would
// vanish behind the plain transfer that follows it.
static void test_transformer_survives_over_rule_default(void) {
    printf("  test_transformer_survives_over_rule_default\n");
    mock_mem_reset();

    test_item_t swap;
    test_item_t transfer;
    item_init(&swap);
    item_init(&transfer);
    item_add_port(&swap, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&swap, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_50);
    item_set_port_mint(&swap, 0, MINT_X);
    item_set_port_mint(&swap, 1, MINT_Y);
    item_add_port(&transfer, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_50);
    item_add_port(&transfer, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_50);
    item_set_port_mint(&transfer, 0, MINT_Y);
    item_set_port_mint(&transfer, 1, MINT_Y);

    cs_instruction_result_t items[2] = {swap.result, transfer.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == false);
    // The swap now names the final destination instead of the intermediate account.
    assert(items[0].resolved_ports[1].account == ACCT_DEST);
    assert(mock_mem_outstanding() == 0);
}

// ---- Symbolic junction ------------------------------------------------------

// The wrap chain collapses: the reset vouches for the junction balance, no other
// instruction could have fed it, and the surviving transfer takes on the token the
// wrap produced while keeping its own concrete amount.
static void test_symbolic_junction_collapses(void) {
    printf("  test_symbolic_junction_collapses\n");
    mock_mem_reset();

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == false);

    // The transfer's output leg now describes the wrapped token, at the amount the
    // transfer itself declared.
    assert(items[1].resolved_ports[1].account == ACCT_JUNCTION);
    assert(items[1].resolved_ports[1].value_kind == CS_PORT_VALUE_KIND_SPL_TOKEN);
    assert(items[1].resolved_ports[1].mint == MINT_X);
    assert(items[1].resolved_ports[1].amount_le == AMT_100);
    assert(items[1].resolved_ports[1].is_symbolic == false);
    assert(mock_mem_outstanding() == 0);
}

// Without an ACCOUNT_RESET nothing vouches for the junction balance, so the device
// cannot tell what the wrap moves and both instructions are shown.
static void test_symbolic_junction_without_reset_refused(void) {
    printf("  test_symbolic_junction_without_reset_refused\n");
    mock_mem_reset();

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);
    create.template.account_reset_count = 0;
    create.result.resolved_reset_count = 0;

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    assert(mock_mem_outstanding() == 0);
}

// A reset scoped to another program does not vouch for this consumer.
static void test_reset_scope_program_mismatch_refused(void) {
    printf("  test_reset_scope_program_mismatch_refused\n");
    mock_mem_reset();

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);
    item_set_last_reset_scope(&create, PROGRAM_OTHER, NULL, 0);

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    assert(mock_mem_outstanding() == 0);
}

// A reset scoped to the consumer's program with no discriminator list vouches for
// every instruction of that program.
static void test_reset_scope_program_only_admits(void) {
    printf("  test_reset_scope_program_only_admits\n");
    mock_mem_reset();

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);
    item_set_last_reset_scope(&create, PROGRAM_TOKEN, NULL, 0);

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[2] == false);
    assert(mock_mem_outstanding() == 0);
}

// A discriminator prefix the consumer's instruction data starts with vouches for it.
static void test_reset_scope_discriminator_admits(void) {
    printf("  test_reset_scope_discriminator_admits\n");
    mock_mem_reset();

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);
    uint8_t other_prefix[2] = {0xEE, 0xFF};
    uint8_t wrap_prefix[2] = {0x11, 0x22};
    cs_reset_discriminator_t discriminators[2] = {
        {other_prefix, sizeof(other_prefix)},
        {wrap_prefix, sizeof(wrap_prefix)},
    };
    item_set_last_reset_scope(&create, PROGRAM_TOKEN, discriminators, 2);

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[2] == false);
    assert(mock_mem_outstanding() == 0);
}

// The consumer's instruction data starts with none of the scoped prefixes.
static void test_reset_scope_discriminator_mismatch_refused(void) {
    printf("  test_reset_scope_discriminator_mismatch_refused\n");
    mock_mem_reset();

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);
    uint8_t other_prefix[2] = {0xEE, 0xFF};
    cs_reset_discriminator_t discriminators[1] = {{other_prefix, sizeof(other_prefix)}};
    item_set_last_reset_scope(&create, PROGRAM_TOKEN, discriminators, 1);

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[2] == true);
    assert(mock_mem_outstanding() == 0);
}

// REQUIRE_PRE_BALANCE_ZERO with no attested state: the device has no pre-balance to
// read, so the reset establishes nothing and the junction is not collapsed.
static void test_pre_balance_zero_without_attestation_refused(void) {
    printf("  test_pre_balance_zero_without_attestation_refused\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);
    item_set_last_reset_requires_zero_pre_balance(&create);

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[2] == true);
    assert(mock_mem_outstanding() == 0);
}

// REQUIRE_PRE_BALANCE_ZERO with an attested zero pre-balance: the reset applies.
static void test_pre_balance_zero_attested_admits(void) {
    printf("  test_pre_balance_zero_attested_admits\n");
    mock_mem_reset();
    cs_token_account_cache_reset();
    assert(cs_token_account_cache_add(ACCT_JUNCTION, MINT_X, ACCT_SOURCE, 0) == 0);

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);
    item_set_last_reset_requires_zero_pre_balance(&create);

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[2] == false);

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// REQUIRE_PRE_BALANCE_ZERO contradicted by an attested non-zero pre-balance: the
// account already held value the reset does not account for.
static void test_pre_balance_non_zero_refused(void) {
    printf("  test_pre_balance_non_zero_refused\n");
    mock_mem_reset();
    cs_token_account_cache_reset();
    assert(cs_token_account_cache_add(ACCT_JUNCTION, MINT_X, ACCT_SOURCE, 7) == 0);

    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    build_wrap_chain(&create, &transfer, &wrap);
    item_set_last_reset_requires_zero_pre_balance(&create);

    cs_instruction_result_t items[3] = {create.result, transfer.result, wrap.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[2] == true);

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// An earlier instruction outside the chain fed the junction through a declared
// output port: the reset no longer accounts for everything the account holds.
static void test_unaccounted_depositor_port_refused(void) {
    printf("  test_unaccounted_depositor_port_refused\n");
    mock_mem_reset();

    test_item_t depositor;
    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    item_init(&depositor);
    item_add_port(&depositor, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_50);
    item_set_port_mint(&depositor, 0, MINT_X);
    build_wrap_chain(&create, &transfer, &wrap);

    cs_instruction_result_t items[4] = {depositor.result,
                                       create.result,
                                       transfer.result,
                                       wrap.result};
    bool survivors[4] = {false, false, false, false};
    assert(cs_merge_engine_run(items, 4, NULL, survivors) == 0);
    assert(survivors[3] == true);
    assert(mock_mem_outstanding() == 0);
}

// The same shape where the earlier instruction only declares the junction coming
// into existence: it moves no value, so the collapse stands.
static void test_zero_amount_port_is_not_a_depositor(void) {
    printf("  test_zero_amount_port_is_not_a_depositor\n");
    mock_mem_reset();

    test_item_t placeholder;
    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    item_init(&placeholder);
    item_add_port(&placeholder, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_0);
    build_wrap_chain(&create, &transfer, &wrap);

    cs_instruction_result_t items[4] = {placeholder.result,
                                       create.result,
                                       transfer.result,
                                       wrap.result};
    bool survivors[4] = {false, false, false, false};
    assert(cs_merge_engine_run(items, 4, NULL, survivors) == 0);
    assert(survivors[3] == false);
    assert(mock_mem_outstanding() == 0);
}

// An earlier instruction lists the junction as writable without declaring any port
// for it: an undeclared write is still a write.
static void test_unaccounted_depositor_writable_refused(void) {
    printf("  test_unaccounted_depositor_writable_refused\n");
    mock_mem_reset();

    test_item_t toucher;
    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    item_init(&toucher);
    item_add_writable(&toucher, ACCT_JUNCTION);
    build_wrap_chain(&create, &transfer, &wrap);

    cs_instruction_result_t items[4] = {toucher.result,
                                       create.result,
                                       transfer.result,
                                       wrap.result};
    bool survivors[4] = {false, false, false, false};
    assert(cs_merge_engine_run(items, 4, NULL, survivors) == 0);
    assert(survivors[3] == true);
    assert(mock_mem_outstanding() == 0);
}

// An earlier instruction whose writable accounts could not all be resolved cannot
// be ruled out as a depositor.
static void test_incomplete_writable_list_refused(void) {
    printf("  test_incomplete_writable_list_refused\n");
    mock_mem_reset();

    test_item_t unresolved;
    test_item_t create;
    test_item_t transfer;
    test_item_t wrap;
    item_init(&unresolved);
    unresolved.result.writable_complete = false;
    build_wrap_chain(&create, &transfer, &wrap);

    cs_instruction_result_t items[4] = {unresolved.result,
                                       create.result,
                                       transfer.result,
                                       wrap.result};
    bool survivors[4] = {false, false, false, false};
    assert(cs_merge_engine_run(items, 4, NULL, survivors) == 0);
    assert(survivors[3] == true);
    assert(mock_mem_outstanding() == 0);
}

// An instruction that sits between the two ends of a candidate chain and touches the
// junction must stop the scan, whatever the reason the device declined to merge with
// it. Here the reset is scoped to the producer's program, so the interloper's own
// junction is declined for lack of a vouching reset; that verdict must not let the
// scan look past it, because nothing else examines it: the guard only reaches
// instructions before the consumed one, and the consumed one here is the producer,
// which executes first.
//
//   create       out (junction, 0) + reset(junction) scoped to the producer's program
//   producer     in (source, MINT_X, 100) -> out (junction, MINT_Y, all)
//   interloper   in (junction, MINT_Y, 100) -> out (other, MINT_Y, 100)
//   consumer     in (junction, MINT_Y, 100) -> out (dest, MINT_Z, 100)
//
// The producer and the consumer both change the form of value, so the roles fall to
// the rule default and the producer is the side folded away. The interloper does not,
// so it survives the role assignment and is the side folded away in its own pairing,
// which is what makes the two guard verdicts differ.
static void test_declined_junction_stops_the_scan(void) {
    printf("  test_declined_junction_stops_the_scan\n");
    mock_mem_reset();

    test_item_t create;
    test_item_t producer;
    test_item_t interloper;
    test_item_t consumer;
    item_init(&create);
    item_init(&producer);
    item_init(&interloper);
    item_init(&consumer);

    item_add_port(&create, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_0);
    item_add_reset(&create, ACCT_JUNCTION, NULL);
    item_set_last_reset_scope(&create, PROGRAM_TOKEN, NULL, 0);

    item_add_port(&producer, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_balance_port(&producer, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION);
    item_set_port_mint(&producer, 0, MINT_X);
    item_set_port_mint(&producer, 1, MINT_Y);
    item_set_identity(&producer, PROGRAM_TOKEN, WRAP_DATA, sizeof(WRAP_DATA));

    item_add_port(&interloper, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&interloper, CS_PORT_DIRECTION_OUTPUT, ACCT_OTHER, AMT_100);
    item_set_port_mint(&interloper, 0, MINT_Y);
    item_set_port_mint(&interloper, 1, MINT_Y);
    item_set_identity(&interloper, PROGRAM_OTHER, WRAP_DATA, sizeof(WRAP_DATA));

    item_add_port(&consumer, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&consumer, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);
    item_set_port_mint(&consumer, 0, MINT_Y);
    item_set_port_mint(&consumer, 1, MINT_Z);
    item_set_identity(&consumer, PROGRAM_OTHER, WRAP_DATA, sizeof(WRAP_DATA));

    cs_instruction_result_t items[4] = {create.result,
                                       producer.result,
                                       interloper.result,
                                       consumer.result};
    bool survivors[4] = {false, false, false, false};
    assert(cs_merge_engine_run(items, 4, NULL, survivors) == 0);

    // The producer must keep its own screen: the interloper stands between it and the
    // consumer, so the consumer cannot claim to carry the producer's value.
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    assert(survivors[3] == true);
    // Nothing was propagated onto the consumer either.
    assert(items[3].resolved_ports[0].account == ACCT_JUNCTION);
    assert(mock_mem_outstanding() == 0);
}

// A reset states what an account holds once its own instruction has run, so one
// declared after the junction says nothing about the balance crossing that junction.
// Here a drain of the whole balance follows a deposit, and only afterwards does an
// instruction declare the account empty. Trusting that reset would let the collapse
// present the deposited amount as the whole movement, while the drain in fact carries
// away whatever the account already held.
static void test_reset_after_the_junction_refused(void) {
    printf("  test_reset_after_the_junction_refused\n");
    mock_mem_reset();

    test_item_t producer;
    test_item_t drain;
    test_item_t closer;
    item_init(&producer);
    item_init(&drain);
    item_init(&closer);

    item_add_port(&producer, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&producer, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);

    item_add_balance_port(&drain, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION);
    item_add_balance_port(&drain, CS_PORT_DIRECTION_OUTPUT, ACCT_OTHER);

    item_add_reset(&closer, ACCT_JUNCTION, NULL);

    cs_instruction_result_t items[3] = {producer.result, drain.result, closer.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    // The deposit still names the account it fed, not the drain's destination.
    assert(items[0].resolved_ports[1].account == ACCT_JUNCTION);
    assert(mock_mem_outstanding() == 0);
}

// The same three instructions with the reset declared before the deposit: now it does
// establish what the account held when the chain started, and the drain collapses.
static void test_reset_before_the_junction_admits(void) {
    printf("  test_reset_before_the_junction_admits\n");
    mock_mem_reset();

    test_item_t opener;
    test_item_t producer;
    test_item_t drain;
    item_init(&opener);
    item_init(&producer);
    item_init(&drain);

    item_add_reset(&opener, ACCT_JUNCTION, NULL);

    item_add_port(&producer, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&producer, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);

    item_add_balance_port(&drain, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION);
    item_add_balance_port(&drain, CS_PORT_DIRECTION_OUTPUT, ACCT_OTHER);

    cs_instruction_result_t items[3] = {opener.result, producer.result, drain.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == false);
    // The deposit now carries the drain's destination.
    assert(items[1].resolved_ports[1].account == ACCT_OTHER);
    assert(mock_mem_outstanding() == 0);
}

// ---- Known balances ---------------------------------------------------------

// A reset states what the account holds, so the next instruction draining it moves
// a known amount: the junction is numeric and collapses as an exact relay, with no
// trust placed in the guard at all.
static void test_reset_makes_a_drain_concrete(void) {
    printf("  test_reset_makes_a_drain_concrete\n");
    mock_mem_reset();

    test_item_t deposit;
    test_item_t drain;
    item_init(&deposit);
    item_init(&drain);
    item_add_port(&deposit, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&deposit, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_reset(&deposit, ACCT_JUNCTION, AMT_100);
    item_add_balance_port(&drain, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION);
    item_add_port(&drain, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[2] = {deposit.result, drain.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == false);
    assert(survivors[1] == true);
    // The drain's input leg resolved to the reset amount, then took on the origin.
    assert(items[1].resolved_ports[0].is_symbolic == false);
    assert(items[1].resolved_ports[0].account == ACCT_SOURCE);
    assert(mock_mem_outstanding() == 0);
}

// An instruction writing the account between the reset and the drain invalidates
// the known balance: the drain moves an amount the device can no longer name.
static void test_intervening_write_invalidates_a_known_balance(void) {
    printf("  test_intervening_write_invalidates_a_known_balance\n");
    mock_mem_reset();

    test_item_t deposit;
    test_item_t writer;
    test_item_t drain;
    item_init(&deposit);
    item_init(&writer);
    item_init(&drain);
    item_add_port(&deposit, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_reset(&deposit, ACCT_JUNCTION, AMT_100);
    item_add_port(&writer, CS_PORT_DIRECTION_INPUT, ACCT_OTHER, AMT_50);
    item_add_port(&writer, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_50);
    item_add_balance_port(&drain, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION);
    item_add_port(&drain, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);

    cs_instruction_result_t items[3] = {deposit.result, writer.result, drain.result};
    bool survivors[3] = {false, false, false};
    assert(cs_merge_engine_run(items, 3, NULL, survivors) == 0);
    assert(items[2].resolved_ports[0].is_symbolic == true);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
    assert(mock_mem_outstanding() == 0);
}

// A reset carrying no RESET_VALUE states the account is emptied, and a drain of an
// empty account moves nothing.
static void test_absent_reset_value_reads_as_zero(void) {
    printf("  test_absent_reset_value_reads_as_zero\n");
    mock_mem_reset();

    test_item_t close;
    test_item_t drain;
    item_init(&close);
    item_init(&drain);
    item_add_port(&close, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_0);
    item_add_port(&close, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_0);
    item_add_reset(&close, ACCT_JUNCTION, NULL);
    item_add_balance_port(&drain, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION);
    item_add_port(&drain, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_0);

    cs_instruction_result_t items[2] = {close.result, drain.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    // Zero on both sides of the junction is an exact relay, not a symbolic one.
    assert(items[1].resolved_ports[0].is_symbolic == false);
    assert(items[1].resolved_ports[0].account == ACCT_SOURCE);
    assert(survivors[0] == false);
    assert(survivors[1] == true);
    assert(mock_mem_outstanding() == 0);
}

// An output port filling an account cannot be predicted from a reset: what lands
// there is decided by the instruction, not by the balance before it.
static void test_output_balance_port_stays_symbolic(void) {
    printf("  test_output_balance_port_stays_symbolic\n");
    mock_mem_reset();

    test_item_t deposit;
    test_item_t filler;
    item_init(&deposit);
    item_init(&filler);
    item_add_port(&deposit, CS_PORT_DIRECTION_OUTPUT, ACCT_OTHER, AMT_100);
    item_add_reset(&deposit, ACCT_JUNCTION, AMT_100);
    item_add_port(&filler, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_balance_port(&filler, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION);

    cs_instruction_result_t items[2] = {deposit.result, filler.result};
    bool survivors[2] = {true, true};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(items[1].resolved_ports[1].is_symbolic == true);
    assert(mock_mem_outstanding() == 0);
}

int main(void) {
    printf("cs_merge_engine_test\n");
    test_no_ports_all_survive();
    test_zero_instructions();
    test_null_with_nonzero_count();
    test_null_survivors_with_nonzero_count();
    test_single_instruction();
    test_scratch_allocation_failure();
    test_partial_allocation_failure();

    test_exact_relay_collapses_and_propagates();
    test_exact_relay_amount_mismatch();
    test_account_mismatch();
    test_token_mismatch();
    test_value_kind_change_collapses();
    test_asymmetric_consumed_refused();
    test_three_link_chain();
    test_no_output_ports();
    test_legs_disagree_on_rule();

    test_non_adjacent_chain_collapses();
    test_writable_overlap_stops_the_scan();
    test_incomplete_writable_list_stops_the_scan();

    test_transformer_survives_over_rule_default();

    test_symbolic_junction_collapses();
    test_symbolic_junction_without_reset_refused();
    test_reset_scope_program_mismatch_refused();
    test_reset_scope_program_only_admits();
    test_reset_scope_discriminator_admits();
    test_reset_scope_discriminator_mismatch_refused();
    test_pre_balance_zero_without_attestation_refused();
    test_pre_balance_zero_attested_admits();
    test_pre_balance_non_zero_refused();
    test_unaccounted_depositor_port_refused();
    test_zero_amount_port_is_not_a_depositor();
    test_unaccounted_depositor_writable_refused();
    test_incomplete_writable_list_refused();
    test_declined_junction_stops_the_scan();
    test_reset_after_the_junction_refused();
    test_reset_before_the_junction_admits();

    test_reset_makes_a_drain_concrete();
    test_intervening_write_invalidates_a_known_balance();
    test_absent_reset_value_reads_as_zero();
    test_output_balance_port_stays_symbolic();
    printf("  All passed!\n");
    return 0;
}
