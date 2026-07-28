// Unit tests for cs_merge_engine.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cs_merge_engine.h"
#include "cs_instruction_template.h"
#include "idl_kinds.h"

#define MAX_TEST_PORTS 4

// An item plus its backing template and port storage. Production heap-allocates
// these; tests back them with fixed local storage and wire the pointers.
typedef struct test_item_s {
    cs_instruction_result_t result;
    cs_instruction_template_t template;
    cs_value_flow_port_t ports[MAX_TEST_PORTS];
    cs_resolved_port_t resolved_ports[MAX_TEST_PORTS];
} test_item_t;

static void item_init(test_item_t *item) {
    memset(item, 0, sizeof(*item));
    item->template.ports = item->ports;
    item->result.template = &item->template;
    item->result.resolved_ports = item->resolved_ports;
}

// Append one resolved NUMERIC/native port carrying a u64 amount to an item.
static void item_add_port(test_item_t *item,
                          uint8_t direction,
                          const uint8_t *account,
                          const uint8_t *amount_le) {
    size_t p = item->template.port_count;
    assert(p < MAX_TEST_PORTS);
    item->ports[p].direction = direction;
    item->resolved_ports[p].resolved = true;
    item->resolved_ports[p].account = account;
    item->resolved_ports[p].value_kind = CS_PORT_VALUE_KIND_NATIVE;
    item->resolved_ports[p].amount_kind = CS_AMOUNT_KIND_NUMERIC;
    item->resolved_ports[p].amount_le = amount_le;
    item->resolved_ports[p].amount_size = 8;
    item->resolved_ports[p].amount_leaf_kind = IDL_KIND_U64;
    item->template.port_count++;
    item->result.resolved_port_count = item->template.port_count;
}

// 32-byte pubkey fixtures, distinguished by their first byte.
static const uint8_t ACCT_SOURCE[32] = {0xA0};
static const uint8_t ACCT_JUNCTION[32] = {0xB0};
static const uint8_t ACCT_DEST[32] = {0xC0};
static const uint8_t ACCT_OTHER[32] = {0xD0};

static const uint8_t MINT_X[32] = {0x11};
static const uint8_t MINT_Y[32] = {0x22};

// Little-endian u64 amount fixtures.
static const uint8_t AMT_100[8] = {100, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t AMT_101[8] = {101, 0, 0, 0, 0, 0, 0, 0};

static void test_all_survive_mvp(void) {
    printf("  test_all_survive_mvp\n");

    cs_instruction_result_t instrs[3];
    memset(instrs, 0, sizeof(instrs));
    bool survivors[3] = {false, false, false};

    assert(cs_merge_engine_run(instrs, 3, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
}

static void test_zero_instructions(void) {
    printf("  test_zero_instructions\n");

    assert(cs_merge_engine_run(NULL, 0, NULL, NULL) == 0);
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

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    bool survivor = false;

    assert(cs_merge_engine_run(&instr, 1, NULL, &survivor) == 0);
    assert(survivor == true);
}

// A -> junction -> B relaying the exact same amount: A is dropped, B survives.
static void test_rule1_exact_pass_through(void) {
    printf("  test_rule1_exact_pass_through\n");

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
}

// Junction amounts differ: not a relay, both survive.
static void test_rule1_amount_mismatch(void) {
    printf("  test_rule1_amount_mismatch\n");

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
}

// Upstream output and downstream input name different accounts: no junction.
static void test_rule1_account_mismatch(void) {
    printf("  test_rule1_account_mismatch\n");

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
}

// Same junction account and amount but incompatible mints: no merge.
static void test_rule1_token_mismatch(void) {
    printf("  test_rule1_token_mismatch\n");

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);
    a.resolved_ports[1].mint = MINT_X;
    b.resolved_ports[0].mint = MINT_Y;

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
}

// Junction value kinds differ (form-changing transformer): deferred, no merge.
static void test_rule1_value_kind_mismatch(void) {
    printf("  test_rule1_value_kind_mismatch\n");

    test_item_t a;
    test_item_t b;
    item_init(&a);
    item_init(&b);
    item_add_port(&a, CS_PORT_DIRECTION_INPUT, ACCT_SOURCE, AMT_100);
    item_add_port(&a, CS_PORT_DIRECTION_OUTPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_INPUT, ACCT_JUNCTION, AMT_100);
    item_add_port(&b, CS_PORT_DIRECTION_OUTPUT, ACCT_DEST, AMT_100);
    b.resolved_ports[0].value_kind = CS_PORT_VALUE_KIND_SPL_TOKEN;

    cs_instruction_result_t items[2] = {a.result, b.result};
    bool survivors[2] = {false, false};
    assert(cs_merge_engine_run(items, 2, NULL, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
}

// Upstream is not a pure conduit (2 outputs, 1 input): cannot be dropped.
static void test_rule1_upstream_not_symmetric(void) {
    printf("  test_rule1_upstream_not_symmetric\n");

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
}

// A -> B -> C, each an exact relay: A and B drop, only C survives.
static void test_rule1_three_link_chain(void) {
    printf("  test_rule1_three_link_chain\n");

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
}

// An instruction with no output ports never relays and always survives.
static void test_rule1_no_output_ports(void) {
    printf("  test_rule1_no_output_ports\n");

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
}

int main(void) {
    printf("cs_merge_engine_test\n");
    test_all_survive_mvp();
    test_zero_instructions();
    test_null_with_nonzero_count();
    test_null_survivors_with_nonzero_count();
    test_single_instruction();
    test_rule1_exact_pass_through();
    test_rule1_amount_mismatch();
    test_rule1_account_mismatch();
    test_rule1_token_mismatch();
    test_rule1_value_kind_mismatch();
    test_rule1_upstream_not_symmetric();
    test_rule1_three_link_chain();
    test_rule1_no_output_ports();
    printf("  All passed!\n");
    return 0;
}
