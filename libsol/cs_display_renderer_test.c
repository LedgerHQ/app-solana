// Unit tests for cs_display_renderer.

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "cs_display_renderer.h"
#include "cs_instruction_template.h"
#include "idl_kinds.h"
#include "app_mem_utils.h"
#include "dynamic_token_info.h"
#include "cs_trusted_name_cache.h"
#include "sol/printer.h"

#define TN_TYPE_TOKEN          0x04
#define TN_TYPE_SMART_CONTRACT 0x02

// display_fields, resolved and field_mint are dynamic in production. The renderer
// only reads them, so tests back them with fixed local storage sized to the
// largest fixture any renderer test builds, and bind the struct pointers to it.
#define TEST_RENDER_MAX_FIELDS 4

#define RENDER_TEST_TEMPLATE(tpl)                            \
    cs_instruction_template_t tpl;                           \
    cs_display_field_t tpl##_fields[TEST_RENDER_MAX_FIELDS]; \
    memset(&(tpl), 0, sizeof(tpl));                          \
    memset(tpl##_fields, 0, sizeof(tpl##_fields));           \
    (tpl).display_fields = tpl##_fields

#define RENDER_TEST_RESULT(res)                                 \
    cs_instruction_result_t res;                                \
    idl_resolved_leaf_t res##_resolved[TEST_RENDER_MAX_FIELDS]; \
    const uint8_t *res##_field_mint[TEST_RENDER_MAX_FIELDS];    \
    memset(&(res), 0, sizeof(res));                             \
    memset(res##_resolved, 0, sizeof(res##_resolved));          \
    memset(res##_field_mint, 0, sizeof(res##_field_mint));      \
    (res).resolved = res##_resolved;                            \
    (res).field_mint = res##_field_mint

// Fetch a flat element by index, asserting that it exists.
// Returns a pointer to a static: valid until the next call.
static const cs_display_flat_element_t *get_flat(size_t index) {
    static cs_display_flat_element_t flat;
    assert(cs_display_renderer_flat_element(index, &flat) == 0);
    return &flat;
}

// Dummy template used by tests that don't care about operation_type/names.
static cs_instruction_template_t G_dummy_template;
static cs_display_field_t G_dummy_fields[TEST_RENDER_MAX_FIELDS];

static void init_dummy_template(void) {
    memset(&G_dummy_template, 0, sizeof(G_dummy_template));
    memset(G_dummy_fields, 0, sizeof(G_dummy_fields));
    G_dummy_template.display_fields = G_dummy_fields;
    G_dummy_template.operation_type = "Transfer";
    G_dummy_template.display_fields[0].name = "Amount";
    G_dummy_template.display_fields[1].name = "Recipient";
}

static void test_initial_state(void) {
    printf("  test_initial_state\n");
    cs_display_renderer_reset();
    assert(cs_display_renderer_flat_count() == 0);
    assert(cs_display_renderer_instruction_count() == 0);
}

static void test_render_u64_leaf(void) {
    printf("  test_render_u64_leaf\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    // 1000000 in little-endian
    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // 1 intent field + 1 data field = 2 elements (no program field: system is native)
    assert(cs_display_renderer_flat_count() == 2);

    const cs_display_flat_element_t *header = get_flat(0);
    assert(header != NULL);
    assert(strcmp(header->title, "Instruction intent") == 0);
    assert(strcmp(header->value, "Transfer") == 0);

    const cs_display_flat_element_t *elem = get_flat(1);
    assert(elem != NULL);
    assert(strcmp(elem->title, "Amount") == 0);
    assert(strcmp(elem->value, "1000000") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A u32 with the high bit set must render as an unsigned value, not sign-extended into 64 bits.
static void test_render_u32_high_bit_leaf(void) {
    printf("  test_render_u32_high_bit_leaf\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    // 0x80000000 (2147483648) little-endian: high bit of the u32 set.
    uint8_t value[] = {0x00, 0x00, 0x00, 0x80};
    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);

    const cs_display_flat_element_t *elem = get_flat(1);
    assert(elem != NULL);
    assert(strcmp(elem->title, "Amount") == 0);
    assert(strcmp(elem->value, "2147483648") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_bool_leaf(void) {
    printf("  test_render_bool_leaf\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    uint8_t val_true = 1;
    uint8_t val_false = 0;

    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_BOOL_U8;
    instr.resolved[0].value = &val_true;
    instr.resolved[0].value_size = 1;
    instr.resolved[1].kind = IDL_KIND_BOOL_U8;
    instr.resolved[1].value = &val_false;
    instr.resolved[1].value_size = 1;
    instr.resolved_count = 2;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // 1 intent + 2 fields = 3 elements (no program field: system is native)
    assert(cs_display_renderer_flat_count() == 3);
    assert(strcmp(get_flat(0)->title, "Instruction intent") == 0);
    assert(strcmp(get_flat(0)->value, "Transfer") == 0);
    assert(strcmp(get_flat(1)->title, "Amount") == 0);
    assert(strcmp(get_flat(1)->value, "True") == 0);
    assert(strcmp(get_flat(2)->title, "Recipient") == 0);
    assert(strcmp(get_flat(2)->value, "False") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_skips_null_value(void) {
    printf("  test_render_skips_null_value\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_U8;
    instr.resolved[0].value = NULL;
    instr.resolved[0].value_size = 0;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // Intent emitted, but the NULL-valued field is skipped (no program: native)
    assert(cs_display_renderer_flat_count() == 1);
    assert(strcmp(get_flat(0)->title, "Instruction intent") == 0);
    assert(strcmp(get_flat(0)->value, "Transfer") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_empty_input(void) {
    printf("  test_render_empty_input\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    assert(cs_display_renderer_run(NULL, 0, NULL) == 0);
    assert(cs_display_renderer_flat_count() == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_alloc_failure(void) {
    printf("  test_alloc_failure\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    // The very first allocation (instruction array) fails before any instruction
    // is appended, so the run returns -1 with the renderer still empty.
    mock_mem_fail_after(0);
    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);
    assert(cs_display_renderer_flat_count() == 0);

    mock_mem_reset();
    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// The intent builds fully, then the field array allocation fails: the run
// returns -1 keeping the partial instruction, which the session teardown frees.
static void test_partial_alloc_failure(void) {
    printf("  test_partial_alloc_failure\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    // instruction array(1), intent dup(2) succeed; the 3rd allocation (field
    // array) fails.
    mock_mem_fail_after(2);
    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);
    // The intent built before the failure is retained, not self-dropped.
    assert(cs_display_renderer_flat_count() == 1);

    // The session teardown releases the partial table with no leak.
    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// An allocation failure during the intent string: the run fails, the partial
// instruction is retained for the session teardown.
static void test_shrink_failure(void) {
    printf("  test_shrink_failure\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    // instruction array(1) succeeds; the 2nd allocation (intent string) fails.
    mock_mem_fail_after(1);
    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_header_value_with_program_name(void) {
    printf("  test_header_value_with_program_name\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();
    G_dummy_template.program_name = "Jupiter";
    // Non-native program_id so the "Program" field is shown
    memset(G_dummy_template.program_id, 0xAA, PUBKEY_SIZE);

    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved_count = 0;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // intent + program = 2 elements
    assert(cs_display_renderer_flat_count() == 2);

    const cs_display_flat_element_t *intent = get_flat(0);
    assert(strcmp(intent->title, "Instruction intent") == 0);
    assert(strcmp(intent->value, "Transfer") == 0);

    const cs_display_flat_element_t *program = get_flat(1);
    assert(strcmp(program->title, "Program") == 0);
    assert(strcmp(program->value, "Jupiter") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_header_value_fallback_to_program_address(void) {
    printf("  test_header_value_fallback_to_program_address\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();
    // program_name left empty (zeroed by init_dummy_template)
    // Set a known program_id: all-ones gives a deterministic base58 (non-native)
    memset(G_dummy_template.program_id, 1, 32);

    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved_count = 0;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // intent + program = 2 elements
    assert(cs_display_renderer_flat_count() == 2);

    const cs_display_flat_element_t *intent = get_flat(0);
    assert(strcmp(intent->title, "Instruction intent") == 0);
    assert(strcmp(intent->value, "Transfer") == 0);

    const cs_display_flat_element_t *program = get_flat(1);
    assert(strcmp(program->title, "Program") == 0);
    // The value should be a base58 address (non-empty)
    assert(strlen(program->value) > 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_mixed_argument_and_account_fields(void) {
    printf("  test_render_mixed_argument_and_account_fields\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Swap";
    template.program_name = "Jupiter";
    // Non-native program_id so the "Program" field is shown
    memset(template.program_id, 0xAA, PUBKEY_SIZE);

    // Field 0: ACCOUNT_PATH (resolved to pubkey externally)
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[0].account.index = 2;
    template.display_fields[0].name = "Destination";

    // Field 1: ARGUMENT_PATH (resolved by walker to u32)
    template.display_fields[1].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[1].name = "Amount";

    template.display_field_count = 2;

    // Build the resolved array as walk_transaction would produce it
    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    uint8_t amount_bytes[] = {0xE8, 0x03, 0x00, 0x00};  // 1000

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved_count = 2;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = pubkey;
    instr.resolved[0].value_size = 32;
    instr.resolved[1].kind = IDL_KIND_U32;
    instr.resolved[1].value = amount_bytes;
    instr.resolved[1].value_size = 4;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // 1 intent + 1 program + 2 content fields = 4 elements
    assert(cs_display_renderer_flat_count() == 4);

    const cs_display_flat_element_t *intent = get_flat(0);
    assert(strcmp(intent->title, "Instruction intent") == 0);
    assert(strcmp(intent->value, "Swap") == 0);

    const cs_display_flat_element_t *program = get_flat(1);
    assert(strcmp(program->title, "Program") == 0);
    assert(strcmp(program->value, "Jupiter") == 0);

    const cs_display_flat_element_t *dest = get_flat(2);
    assert(strcmp(dest->title, "Destination") == 0);
    // Value should be a base58-encoded pubkey (all 0x42 bytes)
    assert(strlen(dest->value) > 0);

    const cs_display_flat_element_t *amount = get_flat(3);
    assert(strcmp(amount->title, "Amount") == 0);
    assert(strcmp(amount->value, "1000") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_amount_with_decimals(void) {
    printf("  test_render_amount_with_decimals\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 9;
    template.display_field_count = 1;

    // 1_000_000_000 lamports = 1 SOL (9 decimals)
    uint8_t value[] = {0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->title, "Amount") == 0);
    assert(strcmp(get_flat(1)->value, "1") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_amount_zero_decimals(void) {
    printf("  test_render_amount_zero_decimals\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Count";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 0;
    template.display_field_count = 1;

    uint8_t value[] = {0xE8, 0x03, 0x00, 0x00};  // 1000 in u32 LE
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "1000") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A PARAM_AMOUNT whose leaf is at the u64 maximum renders its MAX_LABEL instead
// of the scaled number.
static void test_render_amount_max_label(void) {
    printf("  test_render_amount_max_label\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Approve";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 9;
    template.display_fields[0].argument.format.amount.max_label = "Unlimited";
    template.display_field_count = 1;

    uint8_t value[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // u64 max
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "Unlimited") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A MAX_LABEL present but the leaf below its type maximum renders the number.
static void test_render_amount_max_label_below_max(void) {
    printf("  test_render_amount_max_label_below_max\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Approve";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 0;
    template.display_fields[0].argument.format.amount.max_label = "Unlimited";
    template.display_field_count = 1;

    uint8_t value[] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // u64 max - 1
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "18446744073709551614") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// MAX_LABEL applies to the leaf's own IDL width: a u8 leaf at 0xFF is at max even
// though it is far below the u64 maximum.
static void test_render_amount_max_label_u8_width(void) {
    printf("  test_render_amount_max_label_u8_width\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Approve";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 0;
    template.display_fields[0].argument.format.amount.max_label = "Max";
    template.display_field_count = 1;

    uint8_t value[] = {0xFF};  // u8 max
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U8;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 1;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "Max") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A PARAM_TOKEN_AMOUNT at its type maximum renders MAX_LABEL instead of the
// amount + ticker.
static void test_render_token_amount_max_label(void) {
    printf("  test_render_token_amount_max_label\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Approve";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_NATIVE;
    template.display_fields[0].argument.format.token_amount.max_label = "Unlimited";
    template.display_field_count = 1;

    uint8_t value[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // u64 max
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "Unlimited") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A MAX_LABEL that does not fit the render working buffer is refused, not
// truncated: a shortened label would misrepresent the amount.
static void test_render_amount_max_label_too_long_refused(void) {
    printf("  test_render_amount_max_label_too_long_refused\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    char long_label[200];
    memset(long_label, 'x', sizeof(long_label) - 1);
    long_label[sizeof(long_label) - 1] = '\0';

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Approve";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 0;
    template.display_fields[0].argument.format.amount.max_label = long_label;
    template.display_field_count = 1;

    uint8_t value[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // u64 max
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A MAX_LABEL present but the token amount below its type maximum renders the
// normal amount + ticker, not the label.
static void test_render_token_amount_below_max_with_label(void) {
    printf("  test_render_token_amount_below_max_with_label\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Approve";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_NATIVE;
    template.display_fields[0].argument.format.token_amount.max_label = "Unlimited";
    template.display_field_count = 1;

    // 1_000_000_000 lamports = 1 SOL, well below the u64 maximum.
    uint8_t value[] = {0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "1 SOL") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_token_amount_native(void) {
    printf("  test_render_token_amount_native\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_NATIVE;
    template.display_field_count = 1;

    // 1_000_000_000 lamports = 1 SOL
    uint8_t value[] = {0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "1 SOL") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A descriptor that declares no mint (NONE) renders the amount bare, with no
// ticker and no decimal scaling.
static void test_render_token_amount_none(void) {
    printf("  test_render_token_amount_none\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_NONE;
    template.display_field_count = 1;

    // 1000000 in u64 LE
    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "1000000") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A descriptor that references a mint (CONSTANT here) which the registry does
// not recognize renders with a "???" ticker and no decimal scaling.
static void test_render_token_amount_unknown(void) {
    printf("  test_render_token_amount_unknown\n");
    mock_mem_reset();
    mock_dynamic_token_info_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_CONSTANT;
    template.display_field_count = 1;

    // 1000000 in u64 LE
    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t unknown_mint[32];
    memset(unknown_mint, 0x55, 32);
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;
    instr.field_mint[0] = unknown_mint;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "1000000 ???") == 0);

    cs_display_renderer_reset();
    mock_dynamic_token_info_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_account_full_address(void) {
    printf("  test_render_account_full_address\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "To";
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_field_count = 1;

    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = pubkey;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);

    const char *val = get_flat(1)->value;
    // Full base58 address (32 bytes all-0x42 encodes to a ~44 char string)
    assert(strlen(val) > 30);
    // Must not be truncated short form
    assert(val[7] != '.' || val[8] != '.');

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_enum_variant_name(void) {
    printf("  test_render_enum_variant_name\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Test";
    template.display_fields[0].name = "Kind";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_ENUM;
    template.display_field_count = 1;

    // The walker resolves an enum leaf to the selected variant's display name.
    const char *variant_name = "Withdraw";
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_ENUM;
    instr.resolved[0].value = (const uint8_t *) variant_name;
    instr.resolved[0].value_size = strlen(variant_name);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "Withdraw") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_too_long_refused(void) {
    printf("  test_render_string_too_long_refused\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Test";
    template.display_fields[0].name = "Kind";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_ENUM;
    template.display_field_count = 1;

    // A value larger than the render working buffer must be refused, not truncated.
    uint8_t oversized[256];
    memset(oversized, 'x', sizeof(oversized));
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_ENUM;
    instr.resolved[0].value = oversized;
    instr.resolved[0].value_size = sizeof(oversized);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_long_now_renders(void) {
    printf("  test_render_string_long_now_renders\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Test";
    template.display_fields[0].name = "Kind";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_ENUM;
    template.display_field_count = 1;

    // 100 chars is past the old 65-char cap but within the working buffer, so it
    // must now render in full rather than be refused.
    char long_value[101];
    memset(long_value, 'y', 100);
    long_value[100] = '\0';
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_ENUM;
    instr.resolved[0].value = (uint8_t *) long_value;
    instr.resolved[0].value_size = 100;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strlen(get_flat(1)->value) == 100);
    assert(strcmp(get_flat(1)->value, long_value) == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_unsupported_param_type(void) {
    printf("  test_render_unsupported_param_type\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Test";
    template.display_fields[0].name = "Field";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = 0xFF;  // no such param type
    template.display_field_count = 1;

    uint8_t value = 1;
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U8;
    instr.resolved[0].value = &value;
    instr.resolved[0].value_size = 1;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_token_amount_resolved_mint(void) {
    printf("  test_render_token_amount_resolved_mint\n");
    mock_mem_reset();
    mock_dynamic_token_info_reset();
    cs_display_renderer_reset();

    // Register a mock token: USDC with 6 decimals
    uint8_t usdc_mint[32];
    memset(usdc_mint, 0xAA, 32);
    mock_dynamic_token_info_set(usdc_mint, "USDC", 6);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0]
        .argument.format.token_amount.mint_source = CS_TOKEN_MINT_ACCOUNT_INDEX;
    template.display_field_count = 1;

    // 1_500_000 = 1.5 USDC (6 decimals)
    uint8_t value[] = {0x60, 0xE3, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;
    instr.field_mint[0] = usdc_mint;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "1.5 USDC") == 0);

    cs_display_renderer_reset();
    mock_dynamic_token_info_reset();
    assert(mock_mem_outstanding() == 0);
}

// Helper: build a single-field template rooted at an ARGUMENT_PATH.
static void init_argument_template(cs_instruction_template_t *template,
                                   char *field_name,
                                   uint8_t param_type) {
    // Backing for the caller's template; one such template is live at a time.
    static cs_display_field_t fields[TEST_RENDER_MAX_FIELDS];
    memset(template, 0, sizeof(*template));
    memset(fields, 0, sizeof(fields));
    template->display_fields = fields;
    template->operation_type = "Test";
    template->display_fields[0].name = field_name;
    template->display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template->display_fields[0].argument.param_type = param_type;
    template->display_field_count = 1;
}

static void test_render_datetime(void) {
    printf("  test_render_datetime\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "When", CS_PARAM_TYPE_DATETIME);
    template.display_fields[0].argument.format.datetime.ticks_per_second = 1;

    // 1700000000 seconds since Unix epoch -> 2023-11-14T22:13:20+00:00
    // 1700000000 == 0x6553F100
    uint8_t value[] = {0x00, 0xF1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00};

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 2);
    assert(strcmp(get_flat(1)->value, "2023-11-14T22:13:20+00:00") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_datetime_ticks_scaling(void) {
    printf("  test_render_datetime_ticks_scaling\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "When", CS_PARAM_TYPE_DATETIME);
    // Milliseconds: 1000 ticks per second.
    template.display_fields[0].argument.format.datetime.ticks_per_second = 1000;

    // 1700000000000 ms = 0x18BC33FDE00 -> 1700000000 seconds
    uint64_t ticks = 1700000000000ULL;
    uint8_t value[8];
    for (size_t i = 0; i < 8; i++) {
        value[i] = (uint8_t) (ticks >> (8 * i));
    }

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "2023-11-14T22:13:20+00:00") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A Solana UnixTimestamp is an i64: a DATETIME field over a signed leaf must
// render, not be refused.
static void test_render_datetime_signed_i64(void) {
    printf("  test_render_datetime_signed_i64\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "When", CS_PARAM_TYPE_DATETIME);
    template.display_fields[0].argument.format.datetime.ticks_per_second = 1;

    // 1700000000 seconds -> 2023-11-14T22:13:20+00:00, stored as i64.
    uint8_t value[] = {0x00, 0xF1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_I64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "2023-11-14T22:13:20+00:00");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A negative i64 timestamp is a valid pre-1970 date.
static void test_render_datetime_negative_i64(void) {
    printf("  test_render_datetime_negative_i64\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "When", CS_PARAM_TYPE_DATETIME);
    template.display_fields[0].argument.format.datetime.ticks_per_second = 1;

    // -1 second -> 1969-12-31T23:59:59+00:00.
    uint8_t value[8];
    memset(value, 0xFF, sizeof(value));
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_I64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "1969-12-31T23:59:59+00:00");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_duration(void) {
    printf("  test_render_duration\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Duration", CS_PARAM_TYPE_DURATION);

    // 3661 seconds = 01:01:01
    uint8_t value[] = {0x4D, 0x0E, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "01:01:01") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_duration_zero(void) {
    printf("  test_render_duration_zero\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Duration", CS_PARAM_TYPE_DURATION);

    uint8_t value = 0;
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U8;
    instr.resolved[0].value = &value;
    instr.resolved[0].value_size = 1;
    instr.resolved_count = 1;

    bool survivor = true;
    // A zero value is a valid duration of no elapsed time.
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "00:00:00") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A duration held in a signed integer renders like the unsigned form.
static void test_render_duration_signed(void) {
    printf("  test_render_duration_signed\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Duration", CS_PARAM_TYPE_DURATION);

    // 3661 seconds = 01:01:01, encoded as a little-endian i64.
    uint8_t value[] = {0x4D, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_I64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "01:01:01") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A negative signed duration has no meaning and must be refused.
static void test_render_duration_negative(void) {
    printf("  test_render_duration_negative\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Duration", CS_PARAM_TYPE_DURATION);

    // -1 as a little-endian i64.
    uint8_t value[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_I64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_unit_suffix(void) {
    printf("  test_render_unit_suffix\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Rate", CS_PARAM_TYPE_UNIT);
    template.display_fields[0].argument.format.unit.symbol = "%";
    template.display_fields[0].argument.format.unit.decimals = 2;
    template.display_fields[0].argument.format.unit.prefix = false;

    // 1250 with 2 decimals -> "12.5"
    uint8_t value[] = {0xE2, 0x04, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "12.5 %") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_unit_prefix(void) {
    printf("  test_render_unit_prefix\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Price", CS_PARAM_TYPE_UNIT);
    template.display_fields[0].argument.format.unit.symbol = "$";
    template.display_fields[0].argument.format.unit.decimals = 0;
    template.display_fields[0].argument.format.unit.prefix = true;

    uint8_t value[] = {0x2A, 0x00, 0x00, 0x00};  // 42
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "$ 42") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A symbol-less unit must render the bare number with no dangling separator.
static void test_render_unit_no_symbol(void) {
    printf("  test_render_unit_no_symbol\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Count", CS_PARAM_TYPE_UNIT);
    template.display_fields[0].argument.format.unit.symbol = NULL;
    template.display_fields[0].argument.format.unit.decimals = 0;
    template.display_fields[0].argument.format.unit.prefix = false;

    uint8_t value[] = {0x2A, 0x00, 0x00, 0x00};  // 42
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "42") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A transaction-level field appended after a normal run becomes the last element.
static void test_display_renderer_append(void) {
    printf("  test_display_renderer_append\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // A NULL title or value is refused and appends nothing.
    assert(cs_display_renderer_append_transaction_field(NULL, "value") == -1);
    assert(cs_display_renderer_append_transaction_field("title", NULL) == -1);
    assert(cs_display_renderer_flat_count() == 0);

    cs_instruction_template_t template;
    init_argument_template(&template, "Count", CS_PARAM_TYPE_UNIT);
    template.display_fields[0].argument.format.unit.symbol = NULL;

    uint8_t value[] = {0x2A, 0x00, 0x00, 0x00};  // 42
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    size_t before = cs_display_renderer_flat_count();
    assert(before >= 1);

    assert(cs_display_renderer_append_transaction_field("Max fees", "0.001 SOL") == 0);
    assert(cs_display_renderer_flat_count() == before + 1);
    assert(strcmp(get_flat(before)->title, "Max fees") == 0);
    assert(strcmp(get_flat(before)->value, "0.001 SOL") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_account_short_form(void) {
    printf("  test_render_account_short_form\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Owner", CS_PARAM_TYPE_ACCOUNT);

    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = pubkey;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    const char *val = get_flat(1)->value;
    // Short form: 7 chars + ".." + 7 chars.
    assert(strlen(val) == (size_t) (SUMMARY_LENGTH + 2 + SUMMARY_LENGTH));
    assert(val[SUMMARY_LENGTH] == '.');
    assert(val[SUMMARY_LENGTH + 1] == '.');

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A cached trusted name whose (type, source) satisfy the field allow-list is
// rendered as the human-readable name.
static void test_render_trusted_name_resolved(void) {
    printf("  test_render_trusted_name_resolved\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    assert(cs_trusted_name_cache_add(pubkey, "CODE", TN_TYPE_TOKEN) == 0);

    cs_instruction_template_t template;
    init_argument_template(&template, "Token", CS_PARAM_TYPE_TRUSTED_NAME);
    template.display_fields[0]
        .argument.format.trusted_name.allowed_types_mask = (uint8_t) (1 << TN_TYPE_TOKEN);

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = pubkey;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "CODE") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A maximum-length trusted name (CS_TRUSTED_NAME_MAX_LEN chars) is displayed in
// full: the display value buffer must accommodate the spec-max name without
// truncation.
static void test_render_trusted_name_max_length(void) {
    printf("  test_render_trusted_name_max_length\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    char max_name[CS_TRUSTED_NAME_MAX_LEN + 1];
    memset(max_name, 'A', CS_TRUSTED_NAME_MAX_LEN);
    max_name[CS_TRUSTED_NAME_MAX_LEN] = '\0';

    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    assert(cs_trusted_name_cache_add(pubkey, max_name, TN_TYPE_TOKEN) == 0);

    cs_instruction_template_t template;
    init_argument_template(&template, "Token", CS_PARAM_TYPE_TRUSTED_NAME);

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = pubkey;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // The full name is rendered, not truncated.
    assert(strlen(get_flat(1)->value) == CS_TRUSTED_NAME_MAX_LEN);
    assert(strcmp(get_flat(1)->value, max_name) == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// No cached descriptor for the address: fall back to the short base58 address.
static void test_render_trusted_name_cache_miss(void) {
    printf("  test_render_trusted_name_cache_miss\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Token", CS_PARAM_TYPE_TRUSTED_NAME);

    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = pubkey;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    const char *val = get_flat(1)->value;
    // Short address form: 7 + ".." + 7.
    assert(strlen(val) == (size_t) (SUMMARY_LENGTH + 2 + SUMMARY_LENGTH));
    assert(val[SUMMARY_LENGTH] == '.' && val[SUMMARY_LENGTH + 1] == '.');

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A cached name whose type is outside the field's allow-list is not used; the
// short base58 address is shown instead.
static void test_render_trusted_name_type_not_allowed(void) {
    printf("  test_render_trusted_name_type_not_allowed\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    // Cached as SMART_CONTRACT, but the field only permits TOKEN.
    assert(cs_trusted_name_cache_add(pubkey, "Jupiter", TN_TYPE_SMART_CONTRACT) == 0);

    cs_instruction_template_t template;
    init_argument_template(&template, "Token", CS_PARAM_TYPE_TRUSTED_NAME);
    template.display_fields[0]
        .argument.format.trusted_name.allowed_types_mask = (uint8_t) (1 << TN_TYPE_TOKEN);

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = pubkey;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    const char *val = get_flat(1)->value;
    assert(strcmp(val, "Jupiter") != 0);
    assert(strlen(val) == (size_t) (SUMMARY_LENGTH + 2 + SUMMARY_LENGTH));

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A zero allow-list mask means "no constraint": any cached (type, source) resolves.
static void test_render_trusted_name_unconstrained_mask(void) {
    printf("  test_render_trusted_name_unconstrained_mask\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    assert(cs_trusted_name_cache_add(pubkey, "Jupiter", TN_TYPE_SMART_CONTRACT) == 0);

    cs_instruction_template_t template;
    init_argument_template(&template, "Program", CS_PARAM_TYPE_TRUSTED_NAME);
    // Masks left at 0 (unconstrained).

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = pubkey;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "Jupiter") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A plain PARAM_ACCOUNT field (e.g. a mint) is labelled with its trusted name
// when the CAL provided one, even though the field carries no allow-list.
static void test_render_account_resolves_trusted_name(void) {
    printf("  test_render_account_resolves_trusted_name\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t mint[32];
    memset(mint, 0x55, 32);
    assert(cs_trusted_name_cache_add(mint, "USDC", TN_TYPE_TOKEN) == 0);

    cs_instruction_template_t template;
    init_argument_template(&template, "Mint", CS_PARAM_TYPE_ACCOUNT);

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = mint;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "USDC") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_ascii(void) {
    printf("  test_render_string_ascii\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Memo", CS_PARAM_TYPE_STRING);
    template.display_fields[0].argument.format.string.encoding = CS_STRING_ENCODING_ASCII;
    template.display_fields[0].argument.format.string.has_slice = false;

    const char *text = "hello";
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_STRING_PREFIXED;
    instr.resolved[0].value = (const uint8_t *) text;
    instr.resolved[0].value_size = strlen(text);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "hello") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_ascii_rejects_nonprintable(void) {
    printf("  test_render_string_ascii_rejects_nonprintable\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Memo", CS_PARAM_TYPE_STRING);
    template.display_fields[0].argument.format.string.encoding = CS_STRING_ENCODING_ASCII;
    template.display_fields[0].argument.format.string.has_slice = false;

    uint8_t bytes[] = {'h', 'i', 0x01};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_STRING_PREFIXED;
    instr.resolved[0].value = bytes;
    instr.resolved[0].value_size = sizeof(bytes);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_hex(void) {
    printf("  test_render_string_hex\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Data", CS_PARAM_TYPE_STRING);
    template.display_fields[0].argument.format.string.encoding = CS_STRING_ENCODING_HEX;
    template.display_fields[0].argument.format.string.has_slice = false;

    uint8_t bytes[] = {0xDE, 0xAD, 0xBE, 0xEF};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_STRING_PREFIXED;
    instr.resolved[0].value = bytes;
    instr.resolved[0].value_size = sizeof(bytes);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "deadbeef") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_base64(void) {
    printf("  test_render_string_base64\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Data", CS_PARAM_TYPE_STRING);
    template.display_fields[0].argument.format.string.encoding = CS_STRING_ENCODING_BASE64;
    template.display_fields[0].argument.format.string.has_slice = false;

    // "Man" -> "TWFu"; "Ma" -> "TWE="
    const char *text = "Man";
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_STRING_PREFIXED;
    instr.resolved[0].value = (const uint8_t *) text;
    instr.resolved[0].value_size = strlen(text);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "TWFu") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_base64_padding(void) {
    printf("  test_render_string_base64_padding\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Data", CS_PARAM_TYPE_STRING);
    template.display_fields[0].argument.format.string.encoding = CS_STRING_ENCODING_BASE64;
    template.display_fields[0].argument.format.string.has_slice = false;

    const char *text = "Ma";
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_STRING_PREFIXED;
    instr.resolved[0].value = (const uint8_t *) text;
    instr.resolved[0].value_size = strlen(text);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "TWE=") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_slice_source_bounded(void) {
    printf("  test_render_string_slice_source_bounded\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Slice", CS_PARAM_TYPE_STRING);
    template.display_fields[0].argument.format.string.encoding = CS_STRING_ENCODING_ASCII;
    template.display_fields[0].argument.format.string.has_slice = true;
    template.display_fields[0].argument.format.string.slice_kind = CS_SLICE_KIND_BOUNDED;
    template.display_fields[0].argument.format.string.slice_start = 1;
    template.display_fields[0].argument.format.string.slice.bounded.end = 4;
    template.display_fields[0].argument.format.string.slice_applies_to = CS_SLICE_APPLIES_TO_SOURCE;

    const char *text = "abcdef";
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_STRING_PREFIXED;
    instr.resolved[0].value = (const uint8_t *) text;
    instr.resolved[0].value_size = strlen(text);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // Bytes [1,4) = "bcd"
    assert(strcmp(get_flat(1)->value, "bcd") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_string_slice_formatted_sized_reversed(void) {
    printf("  test_render_string_slice_formatted_sized_reversed\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Tail", CS_PARAM_TYPE_STRING);
    template.display_fields[0].argument.format.string.encoding = CS_STRING_ENCODING_HEX;
    template.display_fields[0].argument.format.string.has_slice = true;
    template.display_fields[0].argument.format.string.slice_kind = CS_SLICE_KIND_SIZED;
    template.display_fields[0].argument.format.string.slice.sized.size = 4;
    template.display_fields[0].argument.format.string.slice.sized.reversed = true;
    template.display_fields[0]
        .argument.format.string.slice_applies_to = CS_SLICE_APPLIES_TO_FORMATTED;

    uint8_t bytes[] = {0xDE, 0xAD, 0xBE, 0xEF};  // hex "deadbeef", last 4 chars "beef"
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_STRING_PREFIXED;
    instr.resolved[0].value = bytes;
    instr.resolved[0].value_size = sizeof(bytes);
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "beef") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// Helper: run a single RAW-typed leaf and return its rendered value, or NULL on
// a render failure. The caller supplies the leaf kind and raw bytes.
static void run_raw_leaf(uint8_t kind,
                         const uint8_t *value,
                         size_t value_size,
                         cs_instruction_result_t *instr,
                         cs_instruction_template_t *template) {
    // Backing for the caller's result; one such result is live at a time.
    static idl_resolved_leaf_t resolved[TEST_RENDER_MAX_FIELDS];
    static const uint8_t *field_mint[TEST_RENDER_MAX_FIELDS];
    init_argument_template(template, "Raw", CS_PARAM_TYPE_RAW);
    memset(instr, 0, sizeof(*instr));
    memset(resolved, 0, sizeof(resolved));
    memset(field_mint, 0, sizeof(field_mint));
    instr->resolved = resolved;
    instr->field_mint = field_mint;
    instr->template = template;
    instr->resolved[0].kind = kind;
    instr->resolved[0].value = value;
    instr->resolved[0].value_size = value_size;
    instr->resolved_count = 1;
}

static void test_render_raw_i64_negative(void) {
    printf("  test_render_raw_i64_negative\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    int64_t signed_value = -1000000;
    uint8_t value[8];
    for (size_t i = 0; i < 8; i++) {
        value[i] = (uint8_t) ((uint64_t) signed_value >> (8 * i));
    }
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_I64, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "-1000000");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_i32_negative(void) {
    printf("  test_render_raw_i32_negative\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // -42 in 4-byte little-endian, must sign-extend correctly.
    uint8_t value[] = {0xD6, 0xFF, 0xFF, 0xFF};
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_I32, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "-42");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_u128(void) {
    printf("  test_render_raw_u128\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // 2^64 = 18446744073709551616 (byte 8 set).
    uint8_t value[16] = {0};
    value[8] = 1;
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_U128, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "18446744073709551616");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_i128_negative(void) {
    printf("  test_render_raw_i128_negative\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // -1: all bytes 0xFF.
    uint8_t value[16];
    memset(value, 0xFF, sizeof(value));
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_I128, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "-1");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_short_u16_multibyte(void) {
    printf("  test_render_raw_short_u16_multibyte\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // 300 as compact-u16: 0xAC 0x02.
    uint8_t value[] = {0xAC, 0x02};
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_SHORT_U16, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "300");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_bool_u16_high_byte(void) {
    printf("  test_render_raw_bool_u16_high_byte\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // Only the high byte is set: still True.
    uint8_t value[] = {0x00, 0x01};
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_BOOL_U16, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "True");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_bytes_fixed_hex(void) {
    printf("  test_render_raw_bytes_fixed_hex\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    uint8_t value[] = {0x01, 0x02, 0xAB};
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_BYTES_FIXED, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "0102ab");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_bytes_too_long_refused(void) {
    printf("  test_render_raw_bytes_too_long_refused\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // 64 bytes -> 128 hex chars + NUL (129) overruns the 128-byte working buffer.
    uint8_t value[64];
    memset(value, 0xAB, sizeof(value));
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_BYTES_REMAINDER, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_bytes_long_now_renders(void) {
    printf("  test_render_raw_bytes_long_now_renders\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // 33 bytes -> 66 hex chars, past the old 65-char cap but within the working
    // buffer: it must now render in full rather than be refused.
    uint8_t value[33];
    memset(value, 0xAB, sizeof(value));
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_BYTES_REMAINDER, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strlen(get_flat(1)->value) == 66);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_f32(void) {
    printf("  test_render_raw_f32\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    float f = 1.5f;
    uint8_t value[4];
    memcpy(value, &f, sizeof(value));
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_F32, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "1.5");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_raw_f64(void) {
    printf("  test_render_raw_f64\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    double d = -2.5;
    uint8_t value[8];
    memcpy(value, &d, sizeof(value));
    cs_instruction_result_t instr;
    cs_instruction_template_t template;
    run_raw_leaf(IDL_KIND_F64, value, sizeof(value), &instr, &template);

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(get_flat(1)->value, "-2.5");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A resolved port covering the field's account slot substitutes the displayed
// address. The port's (post-merge) account differs from the field's own leaf, so
// the rendered name is the port's, proving the override fires.
static void test_override_account_address(void) {
    printf("  test_override_account_address\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t field_account[32];
    memset(field_account, 0x11, 32);
    uint8_t port_account[32];
    memset(port_account, 0x22, 32);
    assert(cs_trusted_name_cache_add(field_account, "FIELD_ACCT", TN_TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(port_account, "PORT_ACCT", TN_TYPE_TOKEN) == 0);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[0].account.index = 2;
    template.display_fields[0].name = "Source";
    template.display_field_count = 1;

    cs_value_flow_port_t ports[1];
    memset(ports, 0, sizeof(ports));
    ports[0].direction = CS_PORT_DIRECTION_INPUT;
    template.ports = ports;
    template.port_count = 1;

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = field_account;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    cs_resolved_port_t resolved_ports[1];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].account = port_account;
    resolved_ports[0].account_index = 2;  // same slot the field references
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "PORT_ACCT") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A port resolving to a different account slot than the field does not override
// it: the field keeps its own resolved address.
static void test_override_account_no_match(void) {
    printf("  test_override_account_no_match\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t field_account[32];
    memset(field_account, 0x11, 32);
    uint8_t port_account[32];
    memset(port_account, 0x22, 32);
    assert(cs_trusted_name_cache_add(field_account, "FIELD_ACCT", TN_TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(port_account, "PORT_ACCT", TN_TYPE_TOKEN) == 0);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[0].account.index = 2;
    template.display_fields[0].name = "Source";
    template.display_field_count = 1;

    cs_value_flow_port_t ports[1];
    memset(ports, 0, sizeof(ports));
    template.ports = ports;
    template.port_count = 1;

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = field_account;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    cs_resolved_port_t resolved_ports[1];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].account = port_account;
    resolved_ports[0].account_index = 5;  // different slot: no override
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "FIELD_ACCT") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A port whose amount is sourced from the same ARGUMENT_PATH as the field
// substitutes the displayed amount with the port's (post-merge) value.
static void test_override_amount_argument_path(void) {
    printf("  test_override_amount_argument_path\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    uint8_t path[] = {0x00};

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 0;
    template.display_fields[0].argument.path = path;
    template.display_fields[0].argument.path_size = sizeof(path);
    template.display_field_count = 1;

    cs_value_flow_port_t ports[1];
    memset(ports, 0, sizeof(ports));
    ports[0].amount.kind = CS_AMOUNT_KIND_NUMERIC;
    ports[0].amount.has_value = true;
    ports[0].amount.value.source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    ports[0].amount.value.payload = path;  // same path the field reads
    ports[0].amount.value.payload_size = sizeof(path);
    template.ports = ports;
    template.port_count = 1;

    uint8_t field_amount[] = {0x64, 0x00, 0x00, 0x00};  // 100
    uint8_t port_amount[] = {0xFA, 0x00, 0x00, 0x00};   // 250
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = field_amount;
    instr.resolved[0].value_size = sizeof(field_amount);
    instr.resolved_count = 1;

    cs_resolved_port_t resolved_ports[1];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].amount_kind = CS_AMOUNT_KIND_NUMERIC;
    resolved_ports[0].amount_le = port_amount;
    resolved_ports[0].amount_size = sizeof(port_amount);
    resolved_ports[0].amount_leaf_kind = IDL_KIND_U32;
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "250") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A TOKEN_AMOUNT whose mint comes from an account slot a port covers uses the
// port's (post-merge) mint for the ticker and decimals.
static void test_override_token_mint(void) {
    printf("  test_override_token_mint\n");
    mock_mem_reset();
    mock_dynamic_token_info_reset();
    cs_display_renderer_reset();

    uint8_t field_mint[32];
    memset(field_mint, 0xAA, 32);
    mock_dynamic_token_info_set(field_mint, "AAA", 6);
    uint8_t port_mint[32];
    memset(port_mint, 0xBB, 32);
    mock_dynamic_token_info_set(port_mint, "BBB", 6);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0]
        .argument.format.token_amount.mint_source = CS_TOKEN_MINT_ACCOUNT_INDEX;
    template.display_fields[0].argument.format.token_amount.ref.account_index = 3;
    template.display_field_count = 1;

    cs_value_flow_port_t ports[1];
    memset(ports, 0, sizeof(ports));
    template.ports = ports;
    template.port_count = 1;

    // 1_500_000 = 1.5 at 6 decimals
    uint8_t value[] = {0x60, 0xE3, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;
    instr.field_mint[0] = field_mint;

    cs_resolved_port_t resolved_ports[1];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].account_index = 3;  // same slot as the mint reference
    resolved_ports[0].mint = port_mint;
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "1.5 BBB") == 0);

    cs_display_renderer_reset();
    mock_dynamic_token_info_reset();
    assert(mock_mem_outstanding() == 0);
}

// A port covering the field but carrying the same value the field resolved to
// leaves the output unchanged: the pre-merge identity the all-survive path relies on.
static void test_override_identity_when_value_matches(void) {
    printf("  test_override_identity_when_value_matches\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t account[32];
    memset(account, 0x33, 32);
    assert(cs_trusted_name_cache_add(account, "SAME_ACCT", TN_TYPE_TOKEN) == 0);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[0].account.index = 1;
    template.display_fields[0].name = "Source";
    template.display_field_count = 1;

    cs_value_flow_port_t ports[1];
    memset(ports, 0, sizeof(ports));
    template.ports = ports;
    template.port_count = 1;

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = account;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    cs_resolved_port_t resolved_ports[1];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].account = account;  // identical to the field's own account
    resolved_ports[0].account_index = 1;
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "SAME_ACCT") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// When one account slot is covered by both an input and an output port (a
// transformer touches its token account as both), the output port's account
// wins the display override, matching the POC build order. Streamed input-first.
static void test_override_output_port_wins(void) {
    printf("  test_override_output_port_wins\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t field_account[32];
    memset(field_account, 0x11, 32);
    uint8_t input_account[32];
    memset(input_account, 0x22, 32);
    uint8_t output_account[32];
    memset(output_account, 0x33, 32);
    assert(cs_trusted_name_cache_add(field_account, "FIELD_ACCT", TN_TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(input_account, "INPUT_ACCT", TN_TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(output_account, "OUTPUT_ACCT", TN_TYPE_TOKEN) == 0);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Wrap";
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[0].account.index = 2;
    template.display_fields[0].name = "Account";
    template.display_field_count = 1;

    cs_value_flow_port_t ports[2];
    memset(ports, 0, sizeof(ports));
    ports[0].direction = CS_PORT_DIRECTION_INPUT;
    ports[1].direction = CS_PORT_DIRECTION_OUTPUT;
    template.ports = ports;
    template.port_count = 2;

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = field_account;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    cs_resolved_port_t resolved_ports[2];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].account = input_account;
    resolved_ports[0].account_index = 2;
    resolved_ports[1].resolved = true;
    resolved_ports[1].account = output_account;
    resolved_ports[1].account_index = 2;
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 2;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "OUTPUT_ACCT") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// Same as above but the output port is streamed first: the output must still win,
// proving the precedence is by direction, not array order.
static void test_override_output_port_wins_output_streamed_first(void) {
    printf("  test_override_output_port_wins_output_streamed_first\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t input_account[32];
    memset(input_account, 0x22, 32);
    uint8_t output_account[32];
    memset(output_account, 0x33, 32);
    assert(cs_trusted_name_cache_add(input_account, "INPUT_ACCT", TN_TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(output_account, "OUTPUT_ACCT", TN_TYPE_TOKEN) == 0);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Wrap";
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[0].account.index = 2;
    template.display_fields[0].name = "Account";
    template.display_field_count = 1;

    cs_value_flow_port_t ports[2];
    memset(ports, 0, sizeof(ports));
    ports[0].direction = CS_PORT_DIRECTION_OUTPUT;
    ports[1].direction = CS_PORT_DIRECTION_INPUT;
    template.ports = ports;
    template.port_count = 2;

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = input_account;
    instr.resolved[0].value_size = 32;
    instr.resolved_count = 1;

    cs_resolved_port_t resolved_ports[2];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].account = output_account;
    resolved_ports[0].account_index = 2;
    resolved_ports[1].resolved = true;
    resolved_ports[1].account = input_account;
    resolved_ports[1].account_index = 2;
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 2;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "OUTPUT_ACCT") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A port resolving to a different slot than a TOKEN_AMOUNT's mint reference does
// not override the mint: the field keeps its own resolved mint.
static void test_override_token_mint_no_match(void) {
    printf("  test_override_token_mint_no_match\n");
    mock_mem_reset();
    mock_dynamic_token_info_reset();
    cs_display_renderer_reset();

    uint8_t field_mint[32];
    memset(field_mint, 0xAA, 32);
    mock_dynamic_token_info_set(field_mint, "AAA", 6);
    uint8_t port_mint[32];
    memset(port_mint, 0xBB, 32);
    mock_dynamic_token_info_set(port_mint, "BBB", 6);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0]
        .argument.format.token_amount.mint_source = CS_TOKEN_MINT_ACCOUNT_INDEX;
    template.display_fields[0].argument.format.token_amount.ref.account_index = 3;
    template.display_field_count = 1;

    cs_value_flow_port_t ports[1];
    memset(ports, 0, sizeof(ports));
    template.ports = ports;
    template.port_count = 1;

    // 1_500_000 = 1.5 at 6 decimals
    uint8_t value[] = {0x60, 0xE3, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;
    instr.field_mint[0] = field_mint;

    cs_resolved_port_t resolved_ports[1];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].account_index = 7;  // different slot: no override
    resolved_ports[0].mint = port_mint;
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "1.5 AAA") == 0);

    cs_display_renderer_reset();
    mock_dynamic_token_info_reset();
    assert(mock_mem_outstanding() == 0);
}

// The amount override also applies to a TOKEN_AMOUNT field, not only PARAM_AMOUNT.
static void test_override_amount_on_token_amount_field(void) {
    printf("  test_override_amount_on_token_amount_field\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    uint8_t path[] = {0x00};

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_NATIVE;
    template.display_fields[0].argument.path = path;
    template.display_fields[0].argument.path_size = sizeof(path);
    template.display_field_count = 1;

    cs_value_flow_port_t ports[1];
    memset(ports, 0, sizeof(ports));
    ports[0].amount.kind = CS_AMOUNT_KIND_NUMERIC;
    ports[0].amount.has_value = true;
    ports[0].amount.value.source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    ports[0].amount.value.payload = path;
    ports[0].amount.value.payload_size = sizeof(path);
    template.ports = ports;
    template.port_count = 1;

    uint8_t field_amount[] = {0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00};  // 1 SOL
    uint8_t port_amount[] = {0x00, 0x94, 0x35, 0x77, 0x00, 0x00, 0x00, 0x00};   // 2 SOL
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = field_amount;
    instr.resolved[0].value_size = sizeof(field_amount);
    instr.resolved_count = 1;

    cs_resolved_port_t resolved_ports[1];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].amount_kind = CS_AMOUNT_KIND_NUMERIC;
    resolved_ports[0].amount_le = port_amount;
    resolved_ports[0].amount_size = sizeof(port_amount);
    resolved_ports[0].amount_leaf_kind = IDL_KIND_U64;
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(get_flat(1)->value, "2 SOL") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// Two fields each covered by a distinct port: each field takes its own port's
// value with no cross-contamination between fields.
static void test_override_multi_field_isolation(void) {
    printf("  test_override_multi_field_isolation\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();
    cs_display_renderer_reset();

    uint8_t raw_one[32];
    memset(raw_one, 0x11, 32);
    uint8_t raw_two[32];
    memset(raw_two, 0x22, 32);
    uint8_t port_one[32];
    memset(port_one, 0x33, 32);
    uint8_t port_two[32];
    memset(port_two, 0x44, 32);
    assert(cs_trusted_name_cache_add(raw_one, "RAW_ONE", TN_TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(raw_two, "RAW_TWO", TN_TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(port_one, "PORT_ONE", TN_TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(port_two, "PORT_TWO", TN_TYPE_TOKEN) == 0);

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[0].account.index = 1;
    template.display_fields[0].name = "First";
    template.display_fields[1].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[1].account.index = 2;
    template.display_fields[1].name = "Second";
    template.display_field_count = 2;

    cs_value_flow_port_t ports[2];
    memset(ports, 0, sizeof(ports));
    template.ports = ports;
    template.port_count = 2;

    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[0].value = raw_one;
    instr.resolved[0].value_size = 32;
    instr.resolved[1].kind = IDL_KIND_PUBKEY_32;
    instr.resolved[1].value = raw_two;
    instr.resolved[1].value_size = 32;
    instr.resolved_count = 2;

    cs_resolved_port_t resolved_ports[2];
    memset(resolved_ports, 0, sizeof(resolved_ports));
    resolved_ports[0].resolved = true;
    resolved_ports[0].account = port_one;
    resolved_ports[0].account_index = 1;
    resolved_ports[1].resolved = true;
    resolved_ports[1].account = port_two;
    resolved_ports[1].account_index = 2;
    instr.resolved_ports = resolved_ports;
    instr.resolved_port_count = 2;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_flat_count() == 3);
    assert(strcmp(get_flat(1)->value, "PORT_ONE") == 0);
    assert(strcmp(get_flat(2)->value, "PORT_TWO") == 0);

    cs_display_renderer_reset();
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// Two instructions (one native, one non-native) with no transaction fields:
// the flat layout inserts separator screens before each instruction group.
static void test_multi_instruction_flat_layout(void) {
    printf("  test_multi_instruction_flat_layout\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // Instruction A: native program (system), one field.
    RENDER_TEST_TEMPLATE(template_a);
    template_a.operation_type = "Transfer";
    template_a.display_fields[0].name = "Amount";
    template_a.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template_a.display_field_count = 1;

    uint8_t value_a[] = {0x64, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr_a);
    instr_a.template = &template_a;
    instr_a.resolved[0].kind = IDL_KIND_U32;
    instr_a.resolved[0].value = value_a;
    instr_a.resolved[0].value_size = 4;
    instr_a.resolved_count = 1;

    // Instruction B: non-native program with a program name, one field.
    RENDER_TEST_TEMPLATE(template_b);
    template_b.operation_type = "Swap";
    template_b.program_name = "Jupiter";
    memset(template_b.program_id, 0xAA, PUBKEY_SIZE);
    template_b.display_fields[0].name = "Min out";
    template_b.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template_b.display_field_count = 1;

    uint8_t value_b[] = {0xE8, 0x03, 0x00, 0x00};
    RENDER_TEST_RESULT(instr_b);
    instr_b.template = &template_b;
    instr_b.resolved[0].kind = IDL_KIND_U32;
    instr_b.resolved[0].value = value_b;
    instr_b.resolved[0].value_size = 4;
    instr_b.resolved_count = 1;

    cs_instruction_result_t instructions[2] = {instr_a, instr_b};
    bool survivors[2] = {true, true};
    assert(cs_display_renderer_run(instructions, 2, survivors) == 0);
    assert(cs_display_renderer_instruction_count() == 2);

    // Multi-instruction layout:
    //  0: separator "Review instruction" / "1 of 2"  (centered, no force_page_start)
    //  1: intent "Transfer"
    //  2: field "Amount" = "100"
    //  3: separator "Review instruction" / "2 of 2"  (centered, force_page_start)
    //  4: intent "Swap"
    //  5: program "Jupiter"
    //  6: field "Min out" = "1000"
    assert(cs_display_renderer_flat_count() == 7);

    const cs_display_flat_element_t *sep0 = get_flat(0);
    assert(strcmp(sep0->title, "Review instruction") == 0);
    assert(strcmp(sep0->value, "1 of 2") == 0);
    assert(sep0->centered_info == true);
    assert(sep0->force_page_start == false);

    assert(strcmp(get_flat(1)->title, "Instruction intent") == 0);
    assert(strcmp(get_flat(1)->value, "Transfer") == 0);
    assert(get_flat(1)->centered_info == false);

    assert(strcmp(get_flat(2)->title, "Amount") == 0);
    assert(strcmp(get_flat(2)->value, "100") == 0);

    const cs_display_flat_element_t *sep1 = get_flat(3);
    assert(strcmp(sep1->title, "Review instruction") == 0);
    assert(strcmp(sep1->value, "2 of 2") == 0);
    assert(sep1->centered_info == true);
    assert(sep1->force_page_start == true);

    assert(strcmp(get_flat(4)->title, "Instruction intent") == 0);
    assert(strcmp(get_flat(4)->value, "Swap") == 0);

    assert(strcmp(get_flat(5)->title, "Program") == 0);
    assert(strcmp(get_flat(5)->value, "Jupiter") == 0);

    assert(strcmp(get_flat(6)->title, "Min out") == 0);
    assert(strcmp(get_flat(6)->value, "1000") == 0);

    // Out of range returns -1.
    cs_display_flat_element_t out_of_range;
    assert(cs_display_renderer_flat_element(7, &out_of_range) == -1);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// Two instructions with a transaction-level fee field: the flat layout includes
// a "Review fees" separator screen before the fee section.
static void test_multi_instruction_flat_layout_with_fees(void) {
    printf("  test_multi_instruction_flat_layout_with_fees\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template_a);
    template_a.operation_type = "Transfer";
    template_a.display_fields[0].name = "Amount";
    template_a.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template_a.display_field_count = 1;

    uint8_t value_a[] = {0x01, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr_a);
    instr_a.template = &template_a;
    instr_a.resolved[0].kind = IDL_KIND_U32;
    instr_a.resolved[0].value = value_a;
    instr_a.resolved[0].value_size = 4;
    instr_a.resolved_count = 1;

    RENDER_TEST_TEMPLATE(template_b);
    template_b.operation_type = "Stake";
    template_b.display_fields[0].name = "Validator";
    template_b.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template_b.display_field_count = 1;

    uint8_t value_b[] = {0x02, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr_b);
    instr_b.template = &template_b;
    instr_b.resolved[0].kind = IDL_KIND_U32;
    instr_b.resolved[0].value = value_b;
    instr_b.resolved[0].value_size = 4;
    instr_b.resolved_count = 1;

    cs_instruction_result_t instructions[2] = {instr_a, instr_b};
    bool survivors[2] = {true, true};
    assert(cs_display_renderer_run(instructions, 2, survivors) == 0);
    assert(cs_display_renderer_append_transaction_field("Max fees", "0.001 SOL") == 0);

    // Multi-instruction with fees:
    //  0: separator "1 of 2"
    //  1: intent "Transfer"
    //  2: field "Amount"
    //  3: separator "2 of 2"
    //  4: intent "Stake"
    //  5: field "Validator"
    //  6: separator "Review fees" (centered, force_page_start)
    //  7: field "Max fees"
    assert(cs_display_renderer_flat_count() == 8);

    // Verify the fee separator
    const cs_display_flat_element_t *fee_sep = get_flat(6);
    assert(strcmp(fee_sep->title, "Review fees") == 0);
    assert(strcmp(fee_sep->value, "") == 0);
    assert(fee_sep->centered_info == true);
    assert(fee_sep->force_page_start == true);

    // Verify the fee field
    assert(strcmp(get_flat(7)->title, "Max fees") == 0);
    assert(strcmp(get_flat(7)->value, "0.001 SOL") == 0);
    assert(get_flat(7)->centered_info == false);
    assert(get_flat(7)->force_page_start == false);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A single instruction with a transaction-level field: no separators at all.
static void test_single_instruction_with_fees_no_separators(void) {
    printf("  test_single_instruction_with_fees_no_separators\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    RENDER_TEST_TEMPLATE(template);
    template.operation_type = "Transfer";
    template.display_fields[0].name = "Amount";
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_field_count = 1;

    uint8_t value[] = {0x01, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_append_transaction_field("Max fees", "0.001 SOL") == 0);

    // Single instruction: intent + field + fee field, no separators.
    assert(cs_display_renderer_flat_count() == 3);

    assert(strcmp(get_flat(0)->title, "Instruction intent") == 0);
    assert(get_flat(0)->centered_info == false);
    assert(get_flat(0)->force_page_start == false);

    assert(strcmp(get_flat(1)->title, "Amount") == 0);
    assert(strcmp(get_flat(2)->title, "Max fees") == 0);
    assert(strcmp(get_flat(2)->value, "0.001 SOL") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

int main(void) {
    printf("cs_display_renderer_test\n");
    test_initial_state();
    test_render_u64_leaf();
    test_render_u32_high_bit_leaf();
    test_render_bool_leaf();
    test_render_skips_null_value();
    test_render_empty_input();
    test_alloc_failure();
    test_partial_alloc_failure();
    test_shrink_failure();
    test_header_value_with_program_name();
    test_header_value_fallback_to_program_address();
    test_render_mixed_argument_and_account_fields();
    test_render_amount_with_decimals();
    test_render_amount_zero_decimals();
    test_render_amount_max_label();
    test_render_amount_max_label_below_max();
    test_render_amount_max_label_u8_width();
    test_render_amount_max_label_too_long_refused();
    test_render_token_amount_max_label();
    test_render_token_amount_below_max_with_label();
    test_render_token_amount_native();
    test_render_token_amount_none();
    test_render_token_amount_unknown();
    test_render_token_amount_resolved_mint();
    test_render_account_full_address();
    test_render_enum_variant_name();
    test_render_string_too_long_refused();
    test_render_string_long_now_renders();
    test_render_unsupported_param_type();
    test_render_datetime();
    test_render_datetime_ticks_scaling();
    test_render_datetime_signed_i64();
    test_render_datetime_negative_i64();
    test_render_duration();
    test_render_duration_zero();
    test_render_duration_signed();
    test_render_duration_negative();
    test_render_unit_suffix();
    test_render_unit_prefix();
    test_render_unit_no_symbol();
    test_display_renderer_append();
    test_render_account_short_form();
    test_render_trusted_name_resolved();
    test_render_trusted_name_max_length();
    test_render_trusted_name_cache_miss();
    test_render_trusted_name_type_not_allowed();
    test_render_trusted_name_unconstrained_mask();
    test_render_account_resolves_trusted_name();
    test_render_string_ascii();
    test_render_string_ascii_rejects_nonprintable();
    test_render_string_hex();
    test_render_string_base64();
    test_render_string_base64_padding();
    test_render_string_slice_source_bounded();
    test_render_string_slice_formatted_sized_reversed();
    test_render_raw_i64_negative();
    test_render_raw_i32_negative();
    test_render_raw_u128();
    test_render_raw_i128_negative();
    test_render_raw_short_u16_multibyte();
    test_render_raw_bool_u16_high_byte();
    test_render_raw_bytes_fixed_hex();
    test_render_raw_bytes_too_long_refused();
    test_render_raw_bytes_long_now_renders();
    test_render_raw_f32();
    test_render_raw_f64();
    test_override_account_address();
    test_override_account_no_match();
    test_override_amount_argument_path();
    test_override_token_mint();
    test_override_identity_when_value_matches();
    test_override_output_port_wins();
    test_override_output_port_wins_output_streamed_first();
    test_override_token_mint_no_match();
    test_override_amount_on_token_amount_field();
    test_override_multi_field_isolation();
    test_multi_instruction_flat_layout();
    test_multi_instruction_flat_layout_with_fees();
    test_single_instruction_with_fees_no_separators();
    printf("  All passed!\n");
    return 0;
}
