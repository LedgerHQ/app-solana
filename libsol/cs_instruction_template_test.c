// Unit tests for cs_instruction_template (template table management).

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_instruction_template.h"
#include "app_mem_utils.h"

// A dummy 32-byte program ID and target hash for tests.
static const uint8_t PROGRAM_A[32] = {0xAA};
static const uint8_t PROGRAM_B[32] = {0xBB};
static const uint8_t TARGET_HASH[32] = {0};

// A dummy discriminator.
static const uint8_t DISC_A[] = {0x01, 0x02, 0x03, 0x04};
static const uint8_t DISC_B[] = {0x05, 0x06};

// Helper: open a builder, fill it with program_id + discriminator, commit.
static void commit_template(const uint8_t program_id[32],
                            const uint8_t *disc,
                            size_t disc_size) {
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

    assert(cs_instruction_template_commit() == 0);
    assert(cs_instruction_template_pending() == false);
    assert(cs_instruction_template_committed_count() == 1);

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
    const cs_instruction_template_t *found_a =
        cs_instruction_template_find(PROGRAM_A, data_a, sizeof(data_a));
    assert(found_a != NULL);
    assert(memcmp(found_a->program_id, PROGRAM_A, 32) == 0);

    // Data that starts with DISC_B should match PROGRAM_B
    const uint8_t data_b[] = {0x05, 0x06, 0xAA, 0xBB};
    const cs_instruction_template_t *found_b =
        cs_instruction_template_find(PROGRAM_B, data_b, sizeof(data_b));
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
    assert(cs_instruction_template_add_display_path(path1, sizeof(path1), "Field1") == 0);
    assert(cs_instruction_template_add_display_path(path2, sizeof(path2), "Field2") == 0);
    assert(builder->display_field_count == 2);
    assert(memcmp(builder->display_fields[0].path, path1, sizeof(path1)) == 0);
    assert(builder->display_fields[0].path_size == sizeof(path1));
    assert(memcmp(builder->display_fields[1].path, path2, sizeof(path2)) == 0);

    assert(cs_instruction_template_commit() == 0);
    cs_instruction_template_table_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_display_path_no_builder(void) {
    printf("  test_add_display_path_no_builder\n");
    mock_mem_reset();
    cs_instruction_template_table_reset();

    const uint8_t path[] = {0x20, 0x00};
    assert(cs_instruction_template_add_display_path(path, sizeof(path), NULL) == -1);
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
    assert(cs_instruction_template_add_display_path(long_path, sizeof(long_path), NULL) == -1);
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
        assert(cs_instruction_template_add_display_path(path, sizeof(path), NULL) == 0);
    }
    // One more should fail
    assert(cs_instruction_template_add_display_path(path, sizeof(path), NULL) == -1);

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

    commit_template(PROGRAM_A, DISC_A, sizeof(DISC_A));
    cs_instruction_template_open(TARGET_HASH);  // leave builder open

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
    printf("  All passed!\n");
    return 0;
}
