// Unit tests for cs_display_renderer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_display_renderer.h"
#include "cs_instruction_template.h"
#include "idl_kinds.h"
#include "app_mem_utils.h"
#include "dynamic_token_info.h"

// Dummy template used by tests that don't care about operation_type/names.
static cs_instruction_template_t G_dummy_template;

static void init_dummy_template(void) {
    memset(&G_dummy_template, 0, sizeof(G_dummy_template));
    strlcpy(G_dummy_template.operation_type, "Transfer", sizeof(G_dummy_template.operation_type));
    strlcpy(G_dummy_template.display_fields[0].name,
            "Amount",
            sizeof(G_dummy_template.display_fields[0].name));
    strlcpy(G_dummy_template.display_fields[1].name,
            "Recipient",
            sizeof(G_dummy_template.display_fields[1].name));
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
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    mock_mem_fail_after(0);
    bool survivor = true;
    assert(cs_display_renderer_run(NULL, 0, &survivor) == -1);
    assert(cs_display_renderer_element_count() == 0);

    mock_mem_reset();
    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_header_value_with_program_name(void) {
    printf("  test_header_value_with_program_name\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();
    strlcpy(G_dummy_template.program_name, "Jupiter", sizeof(G_dummy_template.program_name));

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Swap", sizeof(template.operation_type));
    strlcpy(template.program_name, "Jupiter", sizeof(template.program_name));

    // Field 0: ACCOUNT_PATH (resolved to pubkey externally)
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_fields[0].account.index = 2;
    strlcpy(template.display_fields[0].name,
            "Destination",
            sizeof(template.display_fields[0].name));

    // Field 1: ARGUMENT_PATH (resolved by walker to u32)
    template.display_fields[1].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    strlcpy(template.display_fields[1].name, "Amount", sizeof(template.display_fields[1].name));

    template.display_field_count = 2;

    // Build the resolved array as walk_transaction would produce it
    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    uint8_t amount_bytes[] = {0xE8, 0x03, 0x00, 0x00};  // 1000

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Transfer", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Amount", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 9;
    template.display_field_count = 1;

    // 1_000_000_000 lamports = 1 SOL (9 decimals)
    uint8_t value[] = {0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00};
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Transfer", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Count", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_AMOUNT;
    template.display_fields[0].argument.format.amount.decimals = 0;
    template.display_field_count = 1;

    uint8_t value[] = {0xE8, 0x03, 0x00, 0x00};  // 1000 in u32 LE
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

static void test_render_token_amount_native(void) {
    printf("  test_render_token_amount_native\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Transfer", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Amount", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_NATIVE;
    template.display_field_count = 1;

    // 1_000_000_000 lamports = 1 SOL
    uint8_t value[] = {0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00};
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Transfer", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Amount", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_NONE;
    template.display_field_count = 1;

    // 1000000 in u64 LE
    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Transfer", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Amount", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source = CS_TOKEN_MINT_CONSTANT;
    template.display_field_count = 1;

    // 1000000 in u64 LE
    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t unknown_mint[32];
    memset(unknown_mint, 0x55, 32);
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Transfer", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "To", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ACCOUNT_PATH;
    template.display_field_count = 1;

    uint8_t pubkey[32];
    memset(pubkey, 0x42, 32);
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Test", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Kind", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_ENUM;
    template.display_field_count = 1;

    // The walker resolves an enum leaf to the selected variant's display name.
    const char *variant_name = "Withdraw";
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Test", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Kind", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_ENUM;
    template.display_field_count = 1;

    // A value that cannot fit the display buffer must be refused, not truncated.
    uint8_t oversized[CS_DISPLAY_VALUE_SIZE];
    memset(oversized, 'x', sizeof(oversized));
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

static void test_render_unsupported_param_type(void) {
    printf("  test_render_unsupported_param_type\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Test", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Field", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_DATETIME;  // not rendered yet
    template.display_field_count = 1;

    uint8_t value = 1;
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

    cs_instruction_template_t template;
    memset(&template, 0, sizeof(template));
    strlcpy(template.operation_type, "Transfer", sizeof(template.operation_type));
    strlcpy(template.display_fields[0].name, "Amount", sizeof(template.display_fields[0].name));
    template.display_fields[0].source = CS_VALUE_SOURCE_ARGUMENT_PATH;
    template.display_fields[0].argument.param_type = CS_PARAM_TYPE_TOKEN_AMOUNT;
    template.display_fields[0].argument.format.token_amount.mint_source =
        CS_TOKEN_MINT_ACCOUNT_INDEX;
    template.display_field_count = 1;

    // 1_500_000 = 1.5 USDC (6 decimals)
    uint8_t value[] = {0x60, 0xE3, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00};
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
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

int main(void) {
    printf("cs_display_renderer_test\n");
    test_initial_state();
    test_render_u64_leaf();
    test_render_bool_leaf();
    test_render_skips_null_value();
    test_render_empty_input();
    test_alloc_failure();
    test_header_value_with_program_name();
    test_header_value_fallback_to_program_address();
    test_render_mixed_argument_and_account_fields();
    test_render_amount_with_decimals();
    test_render_amount_zero_decimals();
    test_render_token_amount_native();
    test_render_token_amount_none();
    test_render_token_amount_unknown();
    test_render_token_amount_resolved_mint();
    test_render_account_full_address();
    test_render_enum_variant_name();
    test_render_string_too_long_refused();
    test_render_unsupported_param_type();
    printf("  All passed!\n");
    return 0;
}
