#include "idl_pool.h"
#include "test_utils.h"
#include "app_mem_utils.h"  // mock allocator + test controls (mock_mem_*)

#include <assert.h>
#include <stdio.h>
#include <string.h>

// Bring the module to a known-empty state with a clean allocator (counters
// zeroed, no fault injection). idl_pool_reset() must run before
// mock_mem_reset() so any outstanding entry array is freed while the allocator
// counters are still valid.
static void setup(void) {
    idl_pool_reset();
    mock_mem_reset();
}

// =============================================================================
// Lifecycle
// =============================================================================

void test_pool_empty_state() {
    setup();

    assert(idl_pool_ready() == false);
    assert(idl_pool_count() == 0);
    assert(idl_pool_entry(0) == NULL);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_provide() {
    setup();

    const uint8_t pool[] = {0x01, IDL_KIND_U64};
    assert(idl_pool_provide(pool, sizeof(pool), 0) == 0);

    assert(idl_pool_ready() == true);
    assert(idl_pool_count() == 1);
    assert(idl_pool_root_index() == 0);
    const idl_pool_entry_t *entry = idl_pool_entry(0);
    assert(entry != NULL);
    assert(entry->kind == IDL_KIND_U64);
    // Out-of-range index is refused even when a pool is loaded.
    assert(idl_pool_entry(1) == NULL);
    // The parsed pool owns exactly one allocation (the entry array).
    assert(mock_mem_outstanding() == 1);

    idl_pool_reset();
    assert(idl_pool_ready() == false);
    assert(idl_pool_entry(0) == NULL);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_provide_refuses_when_loaded() {
    setup();

    const uint8_t pool_a[] = {0x01, IDL_KIND_U8};
    const uint8_t pool_b[] = {0x02, IDL_KIND_U16, IDL_KIND_U32};
    assert(idl_pool_provide(pool_a, sizeof(pool_a), 0) == 0);
    assert(idl_pool_count() == 1);
    assert(mock_mem_outstanding() == 1);

    // Loading over a still-loaded pool is refused; the first pool stays intact.
    assert(idl_pool_provide(pool_b, sizeof(pool_b), 1) == -1);
    assert(idl_pool_count() == 1);
    assert(idl_pool_entry(0)->kind == IDL_KIND_U8);
    assert(mock_mem_outstanding() == 1);

    // After a reset the pool is clear and a fresh load succeeds.
    idl_pool_reset();
    assert(idl_pool_provide(pool_b, sizeof(pool_b), 1) == 0);
    assert(idl_pool_count() == 2);
    assert(idl_pool_root_index() == 1);
    assert(idl_pool_entry(0)->kind == IDL_KIND_U16);
    assert(idl_pool_entry(1)->kind == IDL_KIND_U32);

    idl_pool_reset();
    assert(mock_mem_outstanding() == 0);
}

void test_pool_reset_idempotent() {
    setup();

    idl_pool_reset();
    idl_pool_reset();
    assert(mock_mem_outstanding() == 0);

    const uint8_t pool[] = {0x01, IDL_KIND_U16};
    assert(idl_pool_provide(pool, sizeof(pool), 0) == 0);
    idl_pool_reset();
    idl_pool_reset();
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

// =============================================================================
// Argument rejection
// =============================================================================

void test_pool_provide_null_with_size_rejected() {
    setup();

    assert(idl_pool_provide(NULL, 4, 0) == -1);
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_zero_size_rejected() {
    setup();

    // A pool of size 0 has no count byte: parsing returns -1.
    const uint8_t dummy = 0x00;
    assert(idl_pool_provide(&dummy, 0, 0) == -1);
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_root_index_out_of_range() {
    setup();

    const uint8_t pool[] = {0x01, IDL_KIND_U8};
    assert(idl_pool_provide(pool, sizeof(pool), 5) == -1);
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_empty_rejected() {
    setup();

    // count = 0 leaves no root entry; root_index 0 is out of range.
    const uint8_t pool[] = {0x00};
    assert(idl_pool_provide(pool, sizeof(pool), 0) == -1);
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

// =============================================================================
// Parse rejection
// =============================================================================

void test_pool_unknown_kind() {
    setup();

    const uint8_t pool[] = {0x01, 0xFF};
    assert(idl_pool_provide(pool, sizeof(pool), 0) == -1);
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_trailing_bytes() {
    setup();

    // count=1 with one u8 entry, plus a stray trailing byte.
    const uint8_t pool[] = {0x01, IDL_KIND_U8, 0x99};
    assert(idl_pool_provide(pool, sizeof(pool), 0) == -1);
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_truncated_entry() {
    setup();

    // count=1 announces an entry but the kind byte is missing.
    const uint8_t pool[] = {0x01};
    assert(idl_pool_provide(pool, sizeof(pool), 0) == -1);
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_ref_out_of_range() {
    setup();

    // struct field references a non-existent pool entry.
    const uint8_t pool[] = {0x01, IDL_KIND_STRUCT, 0x01, 0x05};
    assert(idl_pool_provide(pool, sizeof(pool), 0) == -1);
    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

void test_pool_truncated_per_kind() {
    setup();

    // Each pool truncates a single entry's inline arguments; the parser must
    // reject every one. The leading byte is the entry count.
    struct {
        const char *name;
        uint8_t pool[8];
        size_t size;
    } cases[] = {
        {"bytes_fixed", {1, IDL_KIND_BYTES_FIXED, 0x00}, 3},
        {"string_fixed", {1, IDL_KIND_STRING_FIXED, 0x00, 0x01}, 4},
        {"string_prefixed", {1, IDL_KIND_STRING_PREFIXED, IDL_KIND_U8}, 3},
        {"struct_no_count", {1, IDL_KIND_STRUCT}, 2},
        {"struct_refs", {1, IDL_KIND_STRUCT, 0x02, 0x00}, 4},
        {"option_dynamic", {1, IDL_KIND_OPTION_DYNAMIC, IDL_KIND_U8}, 3},
        {"option_zeroable_args", {1, IDL_KIND_OPTION_ZEROABLE, 0x00}, 3},
        {"option_zeroable_sentinel", {1, IDL_KIND_OPTION_ZEROABLE, 0x00, 0x04}, 4},
        {"array_fixed", {1, IDL_KIND_ARRAY_FIXED, 0x00, 0x02}, 4},
        {"array_prefixed", {1, IDL_KIND_ARRAY_PREFIXED, IDL_KIND_U8}, 3},
        {"array_remainder", {1, IDL_KIND_ARRAY_REMAINDER}, 2},
        {"option_remainder", {1, IDL_KIND_OPTION_REMAINDER}, 2},
        {"enum_args", {1, IDL_KIND_ENUM, IDL_KIND_U8, 0x00}, 4},
        {"enum_id", {1, IDL_KIND_ENUM, IDL_KIND_U8, 0x00, 0x01, 0x04}, 6},
        {"hidden_prefix", {1, IDL_KIND_HIDDEN_PREFIX, 0x00}, 3},
        {"hidden_suffix", {1, IDL_KIND_HIDDEN_SUFFIX, 0x00}, 3},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int rc = idl_pool_provide(cases[i].pool, cases[i].size, 0);
        if (rc != -1) {
            printf("FAIL: truncated pool '%s' was not rejected\n", cases[i].name);
        }
        assert(rc == -1);
        assert(idl_pool_ready() == false);
    }
    assert(mock_mem_outstanding() == 0);
}

// =============================================================================
// Out-of-space injection
// =============================================================================

void test_pool_oom_entries_alloc() {
    setup();

    const uint8_t pool[] = {0x01, IDL_KIND_U64};
    // The entry array allocation is the only allocation idl_pool_provide makes:
    // failing it must abort the provide and leave nothing allocated.
    mock_mem_fail_after(0);
    assert(idl_pool_provide(pool, sizeof(pool), 0) == -1);
    mock_mem_fail_after(-1);

    assert(idl_pool_ready() == false);
    assert(mock_mem_outstanding() == 0);
}

int main() {
    // Lifecycle
    RUN_TEST(test_pool_empty_state);
    RUN_TEST(test_pool_provide);
    RUN_TEST(test_pool_provide_refuses_when_loaded);
    RUN_TEST(test_pool_reset_idempotent);

    // Argument rejection
    RUN_TEST(test_pool_provide_null_with_size_rejected);
    RUN_TEST(test_pool_zero_size_rejected);
    RUN_TEST(test_pool_root_index_out_of_range);
    RUN_TEST(test_pool_empty_rejected);

    // Parse rejection
    RUN_TEST(test_pool_unknown_kind);
    RUN_TEST(test_pool_trailing_bytes);
    RUN_TEST(test_pool_truncated_entry);
    RUN_TEST(test_pool_ref_out_of_range);
    RUN_TEST(test_pool_truncated_per_kind);

    // Out-of-space injection
    RUN_TEST(test_pool_oom_entries_alloc);

    printf("passed\n");
    return 0;
}
