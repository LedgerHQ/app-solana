// Unit tests for cs_display_renderer.

#include <assert.h>
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

#define RENDER_TEST_RESULT(res)                                  \
    cs_instruction_result_t res;                                 \
    idl_resolved_leaf_t res##_resolved[TEST_RENDER_MAX_FIELDS];  \
    const uint8_t *res##_field_mint[TEST_RENDER_MAX_FIELDS];     \
    memset(&(res), 0, sizeof(res));                              \
    memset(res##_resolved, 0, sizeof(res##_resolved));           \
    memset(res##_field_mint, 0, sizeof(res##_field_mint));       \
    (res).resolved = res##_resolved;                             \
    (res).field_mint = res##_field_mint

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
    assert(cs_display_renderer_element_count() == 0);
    assert(cs_display_renderer_element(0) == NULL);
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
    // 1 header + 1 field = 2 elements
    assert(cs_display_renderer_element_count() == 2);

    const cs_display_element_t *header = cs_display_renderer_element(0);
    assert(header != NULL);
    assert(strcmp(header->title, "[1/1] Transfer") == 0);

    const cs_display_element_t *elem = cs_display_renderer_element(1);
    assert(elem != NULL);
    assert(strcmp(elem->title, "Amount") == 0);
    assert(strcmp(elem->value, "1000000") == 0);

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
    // 1 header + 2 fields = 3 elements
    assert(cs_display_renderer_element_count() == 3);
    assert(strcmp(cs_display_renderer_element(0)->title, "[1/1] Transfer") == 0);
    assert(strcmp(cs_display_renderer_element(1)->title, "Amount") == 0);
    assert(strcmp(cs_display_renderer_element(1)->value, "True") == 0);
    assert(strcmp(cs_display_renderer_element(2)->title, "Recipient") == 0);
    assert(strcmp(cs_display_renderer_element(2)->value, "False") == 0);

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
    // Header emitted, but the NULL-valued field is skipped
    assert(cs_display_renderer_element_count() == 1);
    assert(strcmp(cs_display_renderer_element(0)->title, "[1/1] Transfer") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_empty_input(void) {
    printf("  test_render_empty_input\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    assert(cs_display_renderer_run(NULL, 0, NULL) == 0);
    assert(cs_display_renderer_element_count() == 0);

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

    // The very first allocation (the pointer table) fails before any element is
    // appended, so the run returns -1 with the renderer still empty.
    mock_mem_fail_after(0);
    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);
    assert(cs_display_renderer_element_count() == 0);

    mock_mem_reset();
    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// The header element allocates, then a field element allocation fails: the run
// returns -1 keeping the partial table, which the session teardown then frees.
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

    // The header is fully built first: table, header struct, then its title and
    // value buffers each allocated and shrunk (6 allocations). The 7th allocation,
    // the field element struct, fails.
    mock_mem_fail_after(6);
    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == -1);
    // The header element built before the failure is retained, not self-dropped.
    assert(cs_display_renderer_element_count() == 1);

    // The session teardown releases the partial table with no leak.
    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

// A value buffer allocates but its shrink (realloc) fails: the working buffer
// must be released and nothing retained.
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

    // Table, header struct, header title buffer (3 allocs) succeed; the 4th
    // operation, shrinking the header title, fails.
    mock_mem_fail_after(3);
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

    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved_count = 0;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_element_count() == 1);

    const cs_display_element_t *header = cs_display_renderer_element(0);
    assert(strcmp(header->title, "[1/1] Transfer") == 0);
    assert(strcmp(header->value, "Program: Jupiter") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_header_value_fallback_to_program_address(void) {
    printf("  test_header_value_fallback_to_program_address\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();
    // program_name left empty (zeroed by init_dummy_template)
    // Set a known program_id: all-ones gives a deterministic base58
    memset(G_dummy_template.program_id, 1, 32);

    RENDER_TEST_RESULT(instr);
    instr.template = &G_dummy_template;
    instr.resolved_count = 0;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_element_count() == 1);

    const cs_display_element_t *header = cs_display_renderer_element(0);
    assert(strcmp(header->title, "[1/1] Transfer") == 0);
    // Verify it starts with "Program: " and contains a base58 address
    assert(strncmp(header->value, "Program: ", 9) == 0);
    // The address part should be non-empty
    assert(strlen(header->value) > 9);

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
    // 1 header + 2 content fields = 3 elements
    assert(cs_display_renderer_element_count() == 3);

    const cs_display_element_t *header = cs_display_renderer_element(0);
    assert(strcmp(header->title, "[1/1] Swap") == 0);
    assert(strcmp(header->value, "Program: Jupiter") == 0);

    const cs_display_element_t *dest = cs_display_renderer_element(1);
    assert(strcmp(dest->title, "Destination") == 0);
    // Value should be a base58-encoded pubkey (all 0x42 bytes)
    assert(strlen(dest->value) > 0);

    const cs_display_element_t *amount = cs_display_renderer_element(2);
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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->title, "Amount") == 0);
    assert(strcmp(cs_display_renderer_element(1)->value, "1") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "1000") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "Unlimited") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "18446744073709551614") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "Max") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "Unlimited") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "1 SOL") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "1 SOL") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "1000000") == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "1000000 ???") == 0);

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
    assert(cs_display_renderer_element_count() == 2);

    const char *val = cs_display_renderer_element(1)->value;
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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "Withdraw") == 0);

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
    assert(strlen(cs_display_renderer_element(1)->value) == 100);
    assert(strcmp(cs_display_renderer_element(1)->value, long_value) == 0);

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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "1.5 USDC") == 0);

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

    // 1700000000 seconds since Unix epoch -> 2023-11-14 22:13:20
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
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(1)->value, "2023-11-14 22:13:20") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "2023-11-14 22:13:20") == 0);

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

    // 1700000000 seconds -> 2023-11-14 22:13:20, stored as i64.
    uint8_t value[] = {0x00, 0xF1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_I64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert_string_equal(cs_display_renderer_element(1)->value, "2023-11-14 22:13:20");

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

    // -1 second -> 1969-12-31 23:59:59.
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
    assert_string_equal(cs_display_renderer_element(1)->value, "1969-12-31 23:59:59");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_duration(void) {
    printf("  test_render_duration\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    init_argument_template(&template, "Duration", CS_PARAM_TYPE_DURATION);

    // 3661 seconds = 1:01:01
    uint8_t value[] = {0x4D, 0x0E, 0x00, 0x00};
    RENDER_TEST_RESULT(instr);
    instr.template = &template;
    instr.resolved[0].kind = IDL_KIND_U32;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 4;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(strcmp(cs_display_renderer_element(1)->value, "1:01:01") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "0:00:00") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "12.5%") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "$42") == 0);

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
    const char *val = cs_display_renderer_element(1)->value;
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
    assert(strcmp(cs_display_renderer_element(1)->value, "CODE") == 0);

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
    assert(strlen(cs_display_renderer_element(1)->value) == CS_TRUSTED_NAME_MAX_LEN);
    assert(strcmp(cs_display_renderer_element(1)->value, max_name) == 0);

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
    const char *val = cs_display_renderer_element(1)->value;
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
    const char *val = cs_display_renderer_element(1)->value;
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
    assert(strcmp(cs_display_renderer_element(1)->value, "Jupiter") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "USDC") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "hello") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "deadbeef") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "TWFu") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "TWE=") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "bcd") == 0);

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
    assert(strcmp(cs_display_renderer_element(1)->value, "beef") == 0);

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
    assert_string_equal(cs_display_renderer_element(1)->value, "-1000000");

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
    assert_string_equal(cs_display_renderer_element(1)->value, "-42");

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
    assert_string_equal(cs_display_renderer_element(1)->value, "18446744073709551616");

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
    assert_string_equal(cs_display_renderer_element(1)->value, "-1");

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
    assert_string_equal(cs_display_renderer_element(1)->value, "300");

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
    assert_string_equal(cs_display_renderer_element(1)->value, "True");

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
    assert_string_equal(cs_display_renderer_element(1)->value, "0102ab");

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
    assert(strlen(cs_display_renderer_element(1)->value) == 66);

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
    assert_string_equal(cs_display_renderer_element(1)->value, "1.5");

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
    assert_string_equal(cs_display_renderer_element(1)->value, "-2.5");

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

int main(void) {
    printf("cs_display_renderer_test\n");
    test_initial_state();
    test_render_u64_leaf();
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
    test_render_unit_suffix();
    test_render_unit_prefix();
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
    printf("  All passed!\n");
    return 0;
}
