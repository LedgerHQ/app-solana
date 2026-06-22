#include "idl_walker.h"
#include "test_utils.h"
#include "app_mem_utils.h"  // mock allocator + test controls (mock_mem_*)

#include <assert.h>
#include <stdio.h>
#include <string.h>

// Every test starts from a clean allocator (counters zeroed, no fault
// injection) and a zero-initialized walker.
static void setup(idl_walker_t *walker) {
    mock_mem_reset();
    idl_walker_init(walker);
}

void test_init_empty() {
    idl_walker_t walker;
    setup(&walker);

    assert(walker.pool == NULL);
    assert(walker.pool_size == 0);
    assert(walker.root_index == 0);
    assert(walker.pool_ready == false);
    assert(walker.data == NULL);
    assert(walker.data_size == 0);
    assert(walker.data_ready == false);
    assert(walker.leaves == NULL);
    assert(walker.leaf_count == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_provide_pool() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool[] = {0x08, 0x12, 0x00, 0x08, 0x28};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 7) == 0);

    assert(walker.pool_ready == true);
    assert(walker.pool_size == sizeof(pool));
    assert(walker.root_index == 7);
    assert(walker.pool == pool);  // borrowed, aliased to the caller's buffer
    // Forwarding the pool does not allocate anything.
    assert(mock_mem_outstanding() == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_provide_instruction_data() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0x11, 0x22};
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);

    assert(walker.data_ready == true);
    assert(walker.data_size == sizeof(data));
    assert(walker.data == data);  // borrowed, aliased to the caller's buffer
    // Forwarding the data does not allocate anything.
    assert(mock_mem_outstanding() == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_provide_pool_replaces_previous() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool_a[] = {0x01, 0x02, 0x03};
    const uint8_t pool_b[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    assert(idl_walker_provide_pool(&walker, pool_a, sizeof(pool_a), 1) == 0);
    assert(walker.pool == pool_a);

    assert(idl_walker_provide_pool(&walker, pool_b, sizeof(pool_b), 2) == 0);
    // Re-providing just swaps the borrowed reference; nothing is allocated.
    assert(walker.pool == pool_b);
    assert(walker.pool_size == sizeof(pool_b));
    assert(walker.root_index == 2);
    assert(mock_mem_outstanding() == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_provide_pool_null_with_size_rejected() {
    idl_walker_t walker;
    setup(&walker);

    assert(idl_walker_provide_pool(&walker, NULL, 4, 0) == -1);
    assert(walker.pool_ready == false);
    assert(mock_mem_outstanding() == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_provide_empty_inputs_allowed() {
    idl_walker_t walker;
    setup(&walker);

    // An empty input is not a size *limit* refusal; it is accepted.
    assert(idl_walker_provide_pool(&walker, NULL, 0, 3) == 0);
    assert(walker.pool_ready == true);
    assert(walker.pool == NULL);
    assert(walker.pool_size == 0);
    assert(walker.root_index == 3);

    assert(idl_walker_provide_instruction_data(&walker, NULL, 0) == 0);
    assert(walker.data_ready == true);
    assert(walker.data == NULL);
    assert(walker.data_size == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_run_requires_both_inputs() {
    idl_walker_t walker;
    setup(&walker);

    // No inputs at all.
    assert(idl_walker_run(&walker) == -1);

    // Pool only.
    const uint8_t pool[] = {0x01};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_run(&walker) == -1);

    // Pool + data.
    const uint8_t data[] = {0x42};
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
    assert(idl_walker_run(&walker) == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_run_produces_mock_leaf() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool[] = {0x01, 0x02};
    const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0x11};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 7) == 0);
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
    assert(idl_walker_run(&walker) == 0);

    assert(walker.leaf_count == 1);
    assert(walker.leaves != NULL);

    // path = single-step path { step_count=1, root_index }
    const uint8_t expected_path[] = {0x01, 0x07};
    assert(walker.leaves[0].path_size == sizeof(expected_path));
    assert(memcmp(walker.leaves[0].path, expected_path, sizeof(expected_path)) == 0);

    // value = leading 4 bytes of the instruction data
    const uint8_t expected_value[] = {0xde, 0xad, 0xbe, 0xef};
    assert(walker.leaves[0].value_size == sizeof(expected_value));
    assert(memcmp(walker.leaves[0].value, expected_value, sizeof(expected_value)) == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_run_value_shorter_than_max() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool[] = {0x01};
    const uint8_t data[] = {0xaa, 0xbb};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
    assert(idl_walker_run(&walker) == 0);

    assert(walker.leaf_count == 1);
    assert(walker.leaves[0].value_size == sizeof(data));
    assert(memcmp(walker.leaves[0].value, data, sizeof(data)) == 0);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_run_with_empty_data() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool[] = {0x01};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_provide_instruction_data(&walker, NULL, 0) == 0);
    assert(idl_walker_run(&walker) == 0);

    assert(walker.leaf_count == 1);
    assert(walker.leaves[0].value == NULL);
    assert(walker.leaves[0].value_size == 0);
    assert(walker.leaves[0].path_size == 2);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_run_twice_does_not_leak() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool[] = {0x01};
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);

    assert(idl_walker_run(&walker) == 0);
    size_t after_first = mock_mem_outstanding();
    assert(idl_walker_run(&walker) == 0);
    size_t after_second = mock_mem_outstanding();

    // A second run must release the prior leaves before producing new ones.
    assert(after_first == after_second);
    assert(walker.leaf_count == 1);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_oom_on_run_leaf_array() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool[] = {0x01};
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
    size_t before_run = mock_mem_outstanding();

    mock_mem_fail_after(0);  // first allocation in run() fails
    assert(idl_walker_run(&walker) == -1);
    assert(walker.leaf_count == 0);
    assert(walker.leaves == NULL);
    // The failed run must not leak: only the inputs remain allocated.
    assert(mock_mem_outstanding() == before_run);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_oom_on_run_path_buffer() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool[] = {0x01};
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
    size_t before_run = mock_mem_outstanding();

    // Let the leaf-array allocation succeed, fail the path buffer.
    mock_mem_fail_after(1);
    assert(idl_walker_run(&walker) == -1);
    assert(walker.leaf_count == 0);
    assert(walker.leaves == NULL);
    // The partially-built leaf must be fully unwound: no leak past the inputs.
    assert(mock_mem_outstanding() == before_run);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_reset_is_idempotent() {
    idl_walker_t walker;
    setup(&walker);

    // Reset on a freshly initialized context is safe.
    idl_walker_reset(&walker);
    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);

    // Reset after use, twice, is safe and frees everything.
    const uint8_t pool[] = {0x01};
    const uint8_t data[] = {0x01, 0x02};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
    assert(idl_walker_run(&walker) == 0);
    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
    assert(walker.pool_ready == false);
    assert(walker.data_ready == false);
    assert(walker.leaf_count == 0);
}

void test_null_walker_is_safe() {
    // None of these must crash on a NULL context.
    idl_walker_init(NULL);
    assert(idl_walker_provide_pool(NULL, NULL, 0, 0) == -1);
    assert(idl_walker_provide_instruction_data(NULL, NULL, 0) == -1);
    assert(idl_walker_run(NULL) == -1);
    idl_walker_reset(NULL);
}

int main() {
    RUN_TEST(test_init_empty);
    RUN_TEST(test_provide_pool);
    RUN_TEST(test_provide_instruction_data);
    RUN_TEST(test_provide_pool_replaces_previous);
    RUN_TEST(test_provide_pool_null_with_size_rejected);
    RUN_TEST(test_provide_empty_inputs_allowed);
    RUN_TEST(test_run_requires_both_inputs);
    RUN_TEST(test_run_produces_mock_leaf);
    RUN_TEST(test_run_value_shorter_than_max);
    RUN_TEST(test_run_with_empty_data);
    RUN_TEST(test_run_twice_does_not_leak);
    RUN_TEST(test_oom_on_run_leaf_array);
    RUN_TEST(test_oom_on_run_path_buffer);
    RUN_TEST(test_reset_is_idempotent);
    RUN_TEST(test_null_walker_is_safe);

    printf("passed\n");
    return 0;
}
