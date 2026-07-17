// Unit tests for cs_instruction_template (template table management).

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_instruction_template.h"
#include "app_mem_utils.h"
#include "idl_kinds.h"

// A dummy 32-byte program ID and target hash for tests.
static const uint8_t PROGRAM_A[32] = {0xAA};
static const uint8_t PROGRAM_B[32] = {0xBB};
static const uint8_t TARGET_HASH[32] = {0};

// A dummy discriminator.
static const uint8_t DISC_A[] = {0x01, 0x02, 0x03, 0x04};
static const uint8_t DISC_B[] = {0x05, 0x06};

// A dummy IDL type pool payload.
static const uint8_t IDL_POOL[] = {0x10, 0x20, 0x30, 0x40, 0x50};

// Helper: open a builder, fill it with program_id + discriminator, commit.
static void commit_template(const uint8_t program_id[32], const uint8_t *disc, size_t disc_size) {
    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);
    memcpy(builder->program_id, program_id, 32);
    memcpy(builder->discriminator, disc, disc_size);
    builder->discriminator_size = (uint8_t) disc_size;
    assert(cs_instruction_template_commit() == 0);
}

// ---- Tests ------------------------------------------------------------------

static void test_empty_table(void) {
    printf("  test_empty_table\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    assert(cs_instruction_template_committed_count() == 0);
    assert(cs_instruction_template_pending() == false);
    assert(cs_instruction_template_current() == NULL);
    assert(cs_instruction_template_find(PROGRAM_A, DISC_A, sizeof(DISC_A)) == NULL);
    assert(mock_mem_outstanding() == 0);
}

static void test_open_and_commit(void) {
    printf("  test_open_and_commit\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);
    assert(cs_instruction_template_pending() == true);
    assert(cs_instruction_template_committed_count() == 0);

    memcpy(builder->program_id, PROGRAM_A, 32);
    memcpy(builder->discriminator, DISC_A, sizeof(DISC_A));
    builder->discriminator_size = sizeof(DISC_A);
    assert(cs_instruction_template_set_idl_type_pool(IDL_POOL, sizeof(IDL_POOL)) == 0);

    assert(cs_instruction_template_commit() == 0);
    assert(cs_instruction_template_pending() == false);
    assert(cs_instruction_template_committed_count() == 1);

    // The IDL pool buffer survives the commit with its content intact.
    const cs_instruction_template_t *found =
        cs_instruction_template_find(PROGRAM_A, DISC_A, sizeof(DISC_A));
    assert(found != NULL);
    assert(found->idl_type_pool_size == sizeof(IDL_POOL));
    assert(memcmp(found->idl_type_pool, IDL_POOL, sizeof(IDL_POOL)) == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_find_by_program_and_discriminator(void) {
    printf("  test_find_by_program_and_discriminator\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    commit_template(PROGRAM_A, DISC_A, sizeof(DISC_A));
    commit_template(PROGRAM_B, DISC_B, sizeof(DISC_B));
    assert(cs_instruction_template_committed_count() == 2);

    // Data that starts with DISC_A should match PROGRAM_A
    const uint8_t data_a[] = {0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF};
    const cs_instruction_template_t *found_a = cs_instruction_template_find(PROGRAM_A,
                                                                            data_a,
                                                                            sizeof(data_a));
    assert(found_a != NULL);
    assert(memcmp(found_a->program_id, PROGRAM_A, 32) == 0);

    // Data that starts with DISC_B should match PROGRAM_B
    const uint8_t data_b[] = {0x05, 0x06, 0xAA, 0xBB};
    const cs_instruction_template_t *found_b = cs_instruction_template_find(PROGRAM_B,
                                                                            data_b,
                                                                            sizeof(data_b));
    assert(found_b != NULL);
    assert(memcmp(found_b->program_id, PROGRAM_B, 32) == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_find_wrong_program(void) {
    printf("  test_find_wrong_program\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    commit_template(PROGRAM_A, DISC_A, sizeof(DISC_A));

    // Right discriminator, wrong program
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    assert(cs_instruction_template_find(PROGRAM_B, data, sizeof(data)) == NULL);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_find_wrong_discriminator(void) {
    printf("  test_find_wrong_discriminator\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    commit_template(PROGRAM_A, DISC_A, sizeof(DISC_A));

    // Right program, wrong discriminator
    const uint8_t data[] = {0xFF, 0x02, 0x03, 0x04};
    assert(cs_instruction_template_find(PROGRAM_A, data, sizeof(data)) == NULL);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_find_data_too_short(void) {
    printf("  test_find_data_too_short\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    commit_template(PROGRAM_A, DISC_A, sizeof(DISC_A));

    // Data shorter than discriminator
    const uint8_t data[] = {0x01, 0x02};
    assert(cs_instruction_template_find(PROGRAM_A, data, sizeof(data)) == NULL);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_display_path(void) {
    printf("  test_add_display_path\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path1[] = {0x20, 0x00};
    const uint8_t path2[] = {0x20, 0x01};
    assert(cs_instruction_template_add_display_path(path1,
                                                    sizeof(path1),
                                                    CS_PARAM_TYPE_RAW,
                                                    "Field1") == 0);
    assert(cs_instruction_template_add_display_path(path2,
                                                    sizeof(path2),
                                                    CS_PARAM_TYPE_RAW,
                                                    "Field2") == 0);
    assert(builder->display_field_count == 2);
    assert(memcmp(builder->display_fields[0].argument.path, path1, sizeof(path1)) == 0);
    assert(builder->display_fields[0].argument.path_size == sizeof(path1));
    assert(memcmp(builder->display_fields[1].argument.path, path2, sizeof(path2)) == 0);

    assert(cs_instruction_template_commit() == 0);
    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_display_path_no_builder(void) {
    printf("  test_add_display_path_no_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    const uint8_t path[] = {0x20, 0x00};
    assert(cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, NULL) ==
           -1);
    assert(mock_mem_outstanding() == 0);
}

static void test_add_display_path_too_long(void) {
    printf("  test_add_display_path_too_long\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    uint8_t long_path[CS_MAX_ARGUMENT_PATH_SIZE + 1];
    memset(long_path, 0x20, sizeof(long_path));
    assert(cs_instruction_template_add_display_path(long_path,
                                                    sizeof(long_path),
                                                    CS_PARAM_TYPE_RAW,
                                                    NULL) == -1);
    assert(builder->display_field_count == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_display_path_slots_full(void) {
    printf("  test_add_display_path_slots_full\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x20, 0x00};
    for (int i = 0; i < CS_MAX_DISPLAY_FIELDS; i++) {
        assert(
            cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, NULL) ==
            0);
    }
    // One more should fail
    assert(cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, NULL) ==
           -1);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_commit_no_builder(void) {
    printf("  test_commit_no_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    assert(cs_instruction_template_commit() == -1);
    assert(mock_mem_outstanding() == 0);
}

static void test_committed_array_full(void) {
    printf("  test_committed_array_full\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    for (int i = 0; i < CS_MAX_INSTRUCTION_TEMPLATES; i++) {
        uint8_t disc = (uint8_t) i;
        commit_template(PROGRAM_A, &disc, 1);
    }
    assert(cs_instruction_template_committed_count() == CS_MAX_INSTRUCTION_TEMPLATES);

    // Next open should fail — array full
    assert(cs_instruction_template_open(TARGET_HASH) == NULL);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_open_discards_previous_builder(void) {
    printf("  test_open_discards_previous_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *first = cs_instruction_template_open(TARGET_HASH);
    assert(first != NULL);
    memcpy(first->program_id, PROGRAM_A, 32);
    // Give the doomed builder an IDL pool: discarding it must free that buffer too.
    assert(cs_instruction_template_set_idl_type_pool(IDL_POOL, sizeof(IDL_POOL)) == 0);

    // Open again without committing — previous builder is discarded
    cs_instruction_template_t *second = cs_instruction_template_open(TARGET_HASH);
    assert(second != NULL);

    // The new builder is zeroed, so program_id from the first builder is gone
    uint8_t zeroed[32] = {0};
    assert(memcmp(second->program_id, zeroed, 32) == 0);

    // Only one builder outstanding, pending is true, committed is 0
    assert(cs_instruction_template_pending() == true);
    assert(cs_instruction_template_committed_count() == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_reset_cleans_everything(void) {
    printf("  test_reset_cleans_everything\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    // Committed template carries an IDL pool, and so does the open builder:
    // reset must free both ownership levels.
    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);
    memcpy(builder->program_id, PROGRAM_A, 32);
    memcpy(builder->discriminator, DISC_A, sizeof(DISC_A));
    builder->discriminator_size = sizeof(DISC_A);
    assert(cs_instruction_template_set_idl_type_pool(IDL_POOL, sizeof(IDL_POOL)) == 0);
    assert(cs_instruction_template_commit() == 0);

    cs_instruction_template_open(TARGET_HASH);  // leave builder open
    assert(cs_instruction_template_set_idl_type_pool(IDL_POOL, sizeof(IDL_POOL)) == 0);

    assert(cs_instruction_template_committed_count() == 1);
    assert(cs_instruction_template_pending() == true);

    cs_instruction_template_table_reset();

    assert(cs_instruction_template_committed_count() == 0);
    assert(cs_instruction_template_pending() == false);
    assert(mock_mem_outstanding() == 0);
}

static void test_alloc_failure_on_open(void) {
    printf("  test_alloc_failure_on_open\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    // First alloc (table) succeeds, second (builder) fails
    mock_mem_fail_after(1);
    assert(cs_instruction_template_open(TARGET_HASH) == NULL);
    assert(cs_instruction_template_pending() == false);

    mock_mem_reset();
    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_alloc_failure_on_table(void) {
    printf("  test_alloc_failure_on_table\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    // Very first alloc (table itself) fails
    mock_mem_fail_after(0);
    assert(cs_instruction_template_open(TARGET_HASH) == NULL);

    mock_mem_reset();
    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_set_idl_type_pool_no_builder(void) {
    printf("  test_set_idl_type_pool_no_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    assert(cs_instruction_template_set_idl_type_pool(IDL_POOL, sizeof(IDL_POOL)) == -1);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_alloc_failure_on_idl_pool(void) {
    printf("  test_alloc_failure_on_idl_pool\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    // Table (1) and builder (2) allocs succeed; the IDL pool alloc (3) fails.
    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);
    mock_mem_fail_after(0);
    assert(cs_instruction_template_set_idl_type_pool(IDL_POOL, sizeof(IDL_POOL)) == -1);
    assert(builder->idl_type_pool == NULL);

    mock_mem_reset();
    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_account_field(void) {
    printf("  test_add_account_field\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    assert(cs_instruction_template_add_account_field(3, "Destination") == 0);
    assert(builder->display_field_count == 1);
    assert(builder->display_fields[0].source == CS_VALUE_SOURCE_ACCOUNT_PATH);
    assert(builder->display_fields[0].account.index == 3);
    assert(strcmp(builder->display_fields[0].name, "Destination") == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_account_field_no_builder(void) {
    printf("  test_add_account_field_no_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    assert(cs_instruction_template_add_account_field(0, "Test") == -1);
    assert(mock_mem_outstanding() == 0);
}

static void test_mixed_display_fields_order(void) {
    printf("  test_mixed_display_fields_order\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    // Add ACCOUNT_PATH first, then ARGUMENT_PATH, then ACCOUNT_PATH again
    assert(cs_instruction_template_add_account_field(2, "Owner") == 0);
    const uint8_t path[] = {0x20, 0x01};
    assert(
        cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, "Amount") ==
        0);
    assert(cs_instruction_template_add_account_field(0, "Recipient") == 0);

    assert(builder->display_field_count == 3);
    assert(builder->display_fields[0].source == CS_VALUE_SOURCE_ACCOUNT_PATH);
    assert(builder->display_fields[0].account.index == 2);
    assert(builder->display_fields[1].source == CS_VALUE_SOURCE_ARGUMENT_PATH);
    assert(builder->display_fields[1].argument.path_size == 2);
    assert(builder->display_fields[2].source == CS_VALUE_SOURCE_ACCOUNT_PATH);
    assert(builder->display_fields[2].account.index == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_constant_field(void) {
    printf("  test_add_constant_field\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t data[] = {0x63, 0x00, 0x00, 0x00};  // u32 LE = 99
    assert(cs_instruction_template_add_constant_field(data, sizeof(data), IDL_KIND_U32, "Fee") ==
           0);
    assert(builder->display_field_count == 1);
    assert(builder->display_fields[0].source == CS_VALUE_SOURCE_CONSTANT);
    assert(builder->display_fields[0].constant.data_size == 4);
    assert(memcmp(builder->display_fields[0].constant.data, data, sizeof(data)) == 0);
    assert(builder->display_fields[0].constant.kind == IDL_KIND_U32);
    assert(strcmp(builder->display_fields[0].name, "Fee") == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_constant_field_no_builder(void) {
    printf("  test_add_constant_field_no_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    const uint8_t data[] = {0x01};
    assert(cs_instruction_template_add_constant_field(data, sizeof(data), IDL_KIND_U8, "X") == -1);
    assert(mock_mem_outstanding() == 0);
}

static void test_add_constant_field_too_large(void) {
    printf("  test_add_constant_field_too_large\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    uint8_t big[CS_MAX_CONSTANT_SIZE + 1];
    memset(big, 0xAA, sizeof(big));
    assert(cs_instruction_template_add_constant_field(big, sizeof(big), IDL_KIND_U8, NULL) == -1);
    assert(builder->display_field_count == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_mixed_all_sources_order(void) {
    printf("  test_mixed_all_sources_order\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x01, 0x01};
    const uint8_t constant_data[] = {0xFF, 0x00};
    assert(
        cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, "Amount") ==
        0);
    assert(cs_instruction_template_add_constant_field(constant_data,
                                                      sizeof(constant_data),
                                                      IDL_KIND_U16,
                                                      "Version") == 0);
    assert(cs_instruction_template_add_account_field(5, "Authority") == 0);

    assert(builder->display_field_count == 3);
    assert(builder->display_fields[0].source == CS_VALUE_SOURCE_ARGUMENT_PATH);
    assert(builder->display_fields[1].source == CS_VALUE_SOURCE_CONSTANT);
    assert(builder->display_fields[1].constant.kind == IDL_KIND_U16);
    assert(builder->display_fields[1].constant.data_size == 2);
    assert(builder->display_fields[2].source == CS_VALUE_SOURCE_ACCOUNT_PATH);
    assert(builder->display_fields[2].account.index == 5);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_param_type_stored_on_display_path(void) {
    printf("  test_param_type_stored_on_display_path\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x01, 0x00};
    assert(cs_instruction_template_add_display_path(path,
                                                    sizeof(path),
                                                    CS_PARAM_TYPE_AMOUNT,
                                                    "Amount") == 0);
    assert(builder->display_fields[0].argument.param_type == CS_PARAM_TYPE_AMOUNT);

    assert(cs_instruction_template_set_format_amount(9) == 0);
    assert(builder->display_fields[0].argument.format.amount.decimals == 9);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_param_type_token_amount(void) {
    printf("  test_param_type_token_amount\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x01, 0x00};
    assert(cs_instruction_template_add_display_path(path,
                                                    sizeof(path),
                                                    CS_PARAM_TYPE_TOKEN_AMOUNT,
                                                    "Token Amount") == 0);
    assert(builder->display_fields[0].argument.param_type == CS_PARAM_TYPE_TOKEN_AMOUNT);

    cs_format_token_amount_t format = {0};
    format.mint_source = CS_TOKEN_MINT_NATIVE;
    assert(cs_instruction_template_set_format_token_amount(&format) == 0);
    assert(builder->display_fields[0].argument.format.token_amount.mint_source ==
           CS_TOKEN_MINT_NATIVE);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_set_format_amount_wrong_type(void) {
    printf("  test_set_format_amount_wrong_type\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x01};
    assert(cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, "Raw") ==
           0);
    assert(cs_instruction_template_set_format_amount(6) == -1);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_set_format_no_builder(void) {
    printf("  test_set_format_no_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    assert(cs_instruction_template_set_format_amount(9) == -1);
    cs_format_token_amount_t format = {0};
    format.mint_source = CS_TOKEN_MINT_NONE;
    assert(cs_instruction_template_set_format_token_amount(&format) == -1);
    assert(mock_mem_outstanding() == 0);
}

// ---- Main -------------------------------------------------------------------

int main(void) {
    printf("cs_instruction_template_test\n");
    test_empty_table();
    test_open_and_commit();
    test_find_by_program_and_discriminator();
    test_find_wrong_program();
    test_find_wrong_discriminator();
    test_find_data_too_short();
    test_add_display_path();
    test_add_display_path_no_builder();
    test_add_display_path_too_long();
    test_add_display_path_slots_full();
    test_commit_no_builder();
    test_committed_array_full();
    test_open_discards_previous_builder();
    test_reset_cleans_everything();
    test_alloc_failure_on_open();
    test_alloc_failure_on_table();
    test_set_idl_type_pool_no_builder();
    test_alloc_failure_on_idl_pool();
    test_add_account_field();
    test_add_account_field_no_builder();
    test_mixed_display_fields_order();
    test_add_constant_field();
    test_add_constant_field_no_builder();
    test_add_constant_field_too_large();
    test_mixed_all_sources_order();
    test_param_type_stored_on_display_path();
    test_param_type_token_amount();
    test_set_format_amount_wrong_type();
    test_set_format_no_builder();
    printf("  All passed!\\n");
    return 0;
}
