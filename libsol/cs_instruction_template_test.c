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
    assert(cs_instruction_template_set_discriminator(disc, disc_size) == 0);
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
    assert(cs_instruction_template_set_discriminator(DISC_A, sizeof(DISC_A)) == 0);
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

static void test_find_empty_discriminator_matches_any(void) {
    printf("  test_find_empty_discriminator_matches_any\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    // A zero-length discriminator (discriminator == NULL) must match any instruction.
    commit_template(PROGRAM_A, NULL, 0);
    const cs_instruction_template_t *found = cs_instruction_template_find(PROGRAM_A, NULL, 0);
    assert(found != NULL);
    assert(found->discriminator == NULL);
    assert(found->discriminator_size == 0);

    const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    assert(cs_instruction_template_find(PROGRAM_A, data, sizeof(data)) == found);
    assert(cs_instruction_template_find(PROGRAM_B, data, sizeof(data)) == NULL);

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

static void test_add_display_path_empty(void) {
    printf("  test_add_display_path_empty\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x20};
    assert(cs_instruction_template_add_display_path(path, 0, CS_PARAM_TYPE_RAW, NULL) == -1);
    assert(builder->display_field_count == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_display_path_alloc_fail(void) {
    printf("  test_add_display_path_alloc_fail\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x20, 0x00};
    // Next allocation (the path copy) returns NULL: the field must not be stored.
    mock_mem_fail_after(0);
    assert(cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, NULL) ==
           -1);
    assert(builder->display_field_count == 0);

    mock_mem_fail_after(-1);
    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_field_name_variants(void) {
    printf("  test_add_field_name_variants\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x20, 0x00};
    // Empty (non-NULL) label rejected; the already-allocated path copy is released.
    assert(cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, "") == -1);
    assert(builder->display_field_count == 0);

    // NULL label is valid (unlabeled field).
    assert(cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, NULL) == 0);
    assert(builder->display_field_count == 1);
    assert(builder->display_fields[0].name == NULL);

    assert(cs_instruction_template_add_account_field(1, "Owner") == 0);
    assert(builder->display_field_count == 2);
    assert(builder->display_fields[1].name != NULL);
    assert(strcmp(builder->display_fields[1].name, "Owner") == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_set_strings_reject_empty(void) {
    printf("  test_set_strings_reject_empty\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    // Empty operation type / program name rejected, pointer stays NULL.
    assert(cs_instruction_template_set_operation_type("ignored", 0) == -1);
    assert(builder->operation_type == NULL);
    assert(cs_instruction_template_set_program_name("ignored", 0) == -1);
    assert(builder->program_name == NULL);

    assert(cs_instruction_template_set_operation_type("Swap", 4) == 0);
    assert(builder->operation_type != NULL);
    assert(strcmp(builder->operation_type, "Swap") == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_display_fields_grows_past_old_cap(void) {
    printf("  test_add_display_fields_grows_past_old_cap\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    // The old CS_MAX_DISPLAY_FIELDS cap (8) is gone: add well past it. Each field
    // carries a distinct path so the demand-grown array is verified byte for byte.
    const size_t total = 20;
    for (size_t i = 0; i < total; i++) {
        uint8_t path[] = {0x20, (uint8_t) i};
        assert(cs_instruction_template_add_display_path(path,
                                                        sizeof(path),
                                                        CS_PARAM_TYPE_RAW,
                                                        NULL) == 0);
    }
    assert(builder->display_field_count == total);
    for (size_t i = 0; i < total; i++) {
        assert(builder->display_fields[i].source == CS_VALUE_SOURCE_ARGUMENT_PATH);
        assert(builder->display_fields[i].argument.path_size == 2);
        assert(builder->display_fields[i].argument.path[1] == (uint8_t) i);
    }

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_display_field_growth_alloc_fail(void) {
    printf("  test_add_display_field_growth_alloc_fail\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x20, 0x00};
    // Path copy (0) and name copy (1) succeed; the array growth (2) fails: the two
    // owned buffers must be released and no field stored.
    mock_mem_fail_after(2);
    assert(cs_instruction_template_add_display_path(path, sizeof(path), CS_PARAM_TYPE_RAW, "Amount") ==
           -1);
    assert(builder->display_field_count == 0);
    assert(builder->display_fields == NULL);

    mock_mem_fail_after(-1);
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

static void test_commit_grows_past_old_cap(void) {
    printf("  test_commit_grows_past_old_cap\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    // The old CS_MAX_INSTRUCTION_TEMPLATES cap (4) is gone: commit well past it.
    const uint8_t total = 10;
    for (uint8_t i = 0; i < total; i++) {
        uint8_t disc = i;
        commit_template(PROGRAM_A, &disc, 1);
    }
    assert(cs_instruction_template_committed_count() == total);

    // Every committed template survives the pointer-array growth and is findable.
    for (uint8_t i = 0; i < total; i++) {
        uint8_t disc = i;
        assert(cs_instruction_template_find(PROGRAM_A, &disc, 1) != NULL);
    }

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_commit_pool_exhaustion_fail_closed(void) {
    printf("  test_commit_pool_exhaustion_fail_closed\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);
    memcpy(builder->program_id, PROGRAM_A, 32);

    // The committed-array growth allocation fails: commit refuses, builder stays open.
    mock_mem_fail_after(0);
    assert(cs_instruction_template_commit() == -1);
    assert(cs_instruction_template_committed_count() == 0);
    assert(cs_instruction_template_pending() == true);

    mock_mem_reset();
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
    assert(cs_instruction_template_set_discriminator(DISC_A, sizeof(DISC_A)) == 0);
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

static void test_add_constant_field_empty(void) {
    printf("  test_add_constant_field_empty\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t data[] = {0x01};
    assert(cs_instruction_template_add_constant_field(data, 0, IDL_KIND_U8, NULL) == -1);
    assert(builder->display_field_count == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_constant_field_alloc_fail(void) {
    printf("  test_add_constant_field_alloc_fail\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t data[] = {0x01, 0x02, 0x03};
    // The name copy (second allocation) fails: the data copy must be freed, no field stored.
    mock_mem_fail_after(1);
    assert(cs_instruction_template_add_constant_field(data, sizeof(data), IDL_KIND_U8, "Fee") == -1);
    assert(builder->display_field_count == 0);

    mock_mem_fail_after(-1);
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

    assert(cs_instruction_template_set_format_amount(9, NULL, 0) == 0);
    assert(builder->display_fields[0].argument.format.amount.decimals == 9);
    assert(builder->display_fields[0].argument.format.amount.max_label == NULL);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

// The optional MAX_LABEL is copied into a template-owned buffer and freed on
// reset with no leak.
static void test_set_format_amount_max_label(void) {
    printf("  test_set_format_amount_max_label\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x01, 0x00};
    assert(cs_instruction_template_add_display_path(path,
                                                    sizeof(path),
                                                    CS_PARAM_TYPE_AMOUNT,
                                                    "Amount") == 0);
    const char label[] = "Unlimited";
    assert(cs_instruction_template_set_format_amount(0,
                                                     (const uint8_t *) label,
                                                     strlen(label)) == 0);
    assert(builder->display_fields[0].argument.format.amount.max_label != NULL);
    assert(strcmp(builder->display_fields[0].argument.format.amount.max_label, "Unlimited") == 0);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

// An empty MAX_LABEL (size 0) is treated as absent: no buffer is owned.
static void test_set_format_amount_empty_max_label(void) {
    printf("  test_set_format_amount_empty_max_label\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    cs_instruction_template_t *builder = cs_instruction_template_open(TARGET_HASH);
    assert(builder != NULL);

    const uint8_t path[] = {0x01, 0x00};
    assert(cs_instruction_template_add_display_path(path,
                                                    sizeof(path),
                                                    CS_PARAM_TYPE_AMOUNT,
                                                    "Amount") == 0);
    const uint8_t empty[] = {0};
    assert(cs_instruction_template_set_format_amount(9, empty, 0) == 0);
    assert(builder->display_fields[0].argument.format.amount.max_label == NULL);

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
    const char label[] = "Unlimited";
    assert(cs_instruction_template_set_format_token_amount(&format,
                                                           (const uint8_t *) label,
                                                           strlen(label)) == 0);
    assert(builder->display_fields[0].argument.format.token_amount.mint_source ==
           CS_TOKEN_MINT_NATIVE);
    assert(strcmp(builder->display_fields[0].argument.format.token_amount.max_label, "Unlimited") ==
           0);

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
    assert(cs_instruction_template_set_format_amount(6, NULL, 0) == -1);

    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_set_format_no_builder(void) {
    printf("  test_set_format_no_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    assert(cs_instruction_template_set_format_amount(9, NULL, 0) == -1);
    cs_format_token_amount_t format = {0};
    format.mint_source = CS_TOKEN_MINT_NONE;
    assert(cs_instruction_template_set_format_token_amount(&format, NULL, 0) == -1);
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
    test_find_empty_discriminator_matches_any();
    test_add_display_path();
    test_add_display_path_no_builder();
    test_add_display_path_empty();
    test_add_display_path_alloc_fail();
    test_add_field_name_variants();
    test_set_strings_reject_empty();
    test_add_display_fields_grows_past_old_cap();
    test_add_display_field_growth_alloc_fail();
    test_commit_no_builder();
    test_commit_grows_past_old_cap();
    test_commit_pool_exhaustion_fail_closed();
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
    test_add_constant_field_empty();
    test_add_constant_field_alloc_fail();
    test_mixed_all_sources_order();
    test_param_type_stored_on_display_path();
    test_set_format_amount_max_label();
    test_set_format_amount_empty_max_label();
    test_param_type_token_amount();
    test_set_format_amount_wrong_type();
    test_set_format_no_builder();
    printf("  All passed!\\n");
    return 0;
}
