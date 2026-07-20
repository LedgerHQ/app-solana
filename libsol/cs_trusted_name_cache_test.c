// Unit tests for cs_trusted_name_cache (trusted-name cache).

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_trusted_name_cache.h"
#include "app_mem_utils.h"

static const uint8_t ADDR_A[32] = {0xAA};
static const uint8_t ADDR_B[32] = {0xBB};

#define TYPE_TOKEN          0x04
#define TYPE_SMART_CONTRACT 0x02

// ---- Tests ------------------------------------------------------------------

static void test_empty_cache(void) {
    printf("  test_empty_cache\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();

    assert(cs_trusted_name_cache_count() == 0);
    assert(cs_trusted_name_cache_find(ADDR_A) == NULL);
    assert(mock_mem_outstanding() == 0);
}

static void test_add_and_find(void) {
    printf("  test_add_and_find\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();

    assert(cs_trusted_name_cache_add(ADDR_A, "CODE", TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_count() == 1);

    const cs_trusted_name_t *found = cs_trusted_name_cache_find(ADDR_A);
    assert(found != NULL);
    assert(memcmp(found->address, ADDR_A, 32) == 0);
    assert(strcmp(found->name, "CODE") == 0);
    assert(found->type == TYPE_TOKEN);

    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// Distinct address keys must resolve to their own record (or miss).
static void test_key_disambiguation(void) {
    printf("  test_key_disambiguation\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();

    assert(cs_trusted_name_cache_add(ADDR_A, "CODE", TYPE_TOKEN) == 0);
    assert(cs_trusted_name_cache_add(ADDR_B, "Jupiter", TYPE_SMART_CONTRACT) == 0);
    assert(cs_trusted_name_cache_count() == 2);

    const cs_trusted_name_t *found;
    found = cs_trusted_name_cache_find(ADDR_A);
    assert(found != NULL && strcmp(found->name, "CODE") == 0 && found->type == TYPE_TOKEN);
    found = cs_trusted_name_cache_find(ADDR_B);
    assert(found != NULL && strcmp(found->name, "Jupiter") == 0 &&
           found->type == TYPE_SMART_CONTRACT);

    // Unknown address misses.
    uint8_t unknown[32] = {0xCC};
    assert(cs_trusted_name_cache_find(unknown) == NULL);

    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_duplicate_rejected(void) {
    printf("  test_duplicate_rejected\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();

    assert(cs_trusted_name_cache_add(ADDR_A, "CODE", TYPE_TOKEN) == 0);
    // Same key, different content: refused.
    assert(cs_trusted_name_cache_add(ADDR_A, "OTHER", TYPE_SMART_CONTRACT) == -1);
    assert(cs_trusted_name_cache_count() == 1);

    const cs_trusted_name_t *found = cs_trusted_name_cache_find(ADDR_A);
    assert(found != NULL && strcmp(found->name, "CODE") == 0);

    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_invalid_name_rejected(void) {
    printf("  test_invalid_name_rejected\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();

    // NULL name refused.
    assert(cs_trusted_name_cache_add(ADDR_A, NULL, TYPE_TOKEN) == -1);
    // Empty name refused.
    assert(cs_trusted_name_cache_add(ADDR_A, "", TYPE_TOKEN) == -1);

    // Name of exactly CS_TRUSTED_NAME_MAX_LEN is accepted.
    char max_name[CS_TRUSTED_NAME_MAX_LEN + 1];
    memset(max_name, 'x', CS_TRUSTED_NAME_MAX_LEN);
    max_name[CS_TRUSTED_NAME_MAX_LEN] = '\0';
    assert(cs_trusted_name_cache_add(ADDR_A, max_name, TYPE_TOKEN) == 0);
    const cs_trusted_name_t *found = cs_trusted_name_cache_find(ADDR_A);
    assert(found != NULL && strlen(found->name) == CS_TRUSTED_NAME_MAX_LEN);

    // One char longer is refused.
    char over_name[CS_TRUSTED_NAME_MAX_LEN + 2];
    memset(over_name, 'y', CS_TRUSTED_NAME_MAX_LEN + 1);
    over_name[CS_TRUSTED_NAME_MAX_LEN + 1] = '\0';
    assert(cs_trusted_name_cache_add(ADDR_B, over_name, TYPE_TOKEN) == -1);
    assert(cs_trusted_name_cache_count() == 1);

    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// No count cap: the cache grows past the former CS_MAX_TRUSTED_NAMES (8),
// bounded only by the pool. Every entry stays stored and findable.
static void test_grows_past_old_cap(void) {
    printf("  test_grows_past_old_cap\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();

    const uint8_t count = 40;
    for (uint8_t i = 0; i < count; i++) {
        uint8_t address[32] = {0};
        address[0] = i + 1;
        assert(cs_trusted_name_cache_add(address, "NAME", TYPE_TOKEN) == 0);
    }
    assert(cs_trusted_name_cache_count() == count);
    for (uint8_t i = 0; i < count; i++) {
        uint8_t address[32] = {0};
        address[0] = i + 1;
        const cs_trusted_name_t *found = cs_trusted_name_cache_find(address);
        assert(found != NULL && strcmp(found->name, "NAME") == 0);
    }

    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// The only accepted refusal is an allocation failure: the entry is not stored
// and nothing leaks after reset.
static void test_oom_rejected(void) {
    printf("  test_oom_rejected\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();

    assert(cs_trusted_name_cache_add(ADDR_A, "CODE", TYPE_TOKEN) == 0);

    // Fail the pointer-array growth (first allocation of the add).
    mock_mem_fail_after(0);
    assert(cs_trusted_name_cache_add(ADDR_B, "OTHER", TYPE_TOKEN) == -1);
    assert(cs_trusted_name_cache_count() == 1);

    // Fail the per-entry slot allocation (growth succeeds, slot alloc fails).
    mock_mem_fail_after(1);
    assert(cs_trusted_name_cache_add(ADDR_B, "OTHER", TYPE_TOKEN) == -1);
    assert(cs_trusted_name_cache_count() == 1);

    // Fail the name allocation (slot allocated then freed on unwind).
    mock_mem_fail_after(2);
    assert(cs_trusted_name_cache_add(ADDR_B, "OTHER", TYPE_TOKEN) == -1);
    assert(cs_trusted_name_cache_count() == 1);

    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_reset_releases_memory(void) {
    printf("  test_reset_releases_memory\n");
    mock_mem_reset();
    cs_trusted_name_cache_reset();

    assert(cs_trusted_name_cache_add(ADDR_A, "CODE", TYPE_TOKEN) == 0);
    assert(mock_mem_outstanding() > 0);

    cs_trusted_name_cache_reset();
    assert(cs_trusted_name_cache_count() == 0);
    assert(mock_mem_outstanding() == 0);

    // Reset again on an already-empty cache must be a no-op.
    cs_trusted_name_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

int main(void) {
    printf("cs_trusted_name_cache_test\n");
    test_empty_cache();
    test_add_and_find();
    test_key_disambiguation();
    test_duplicate_rejected();
    test_invalid_name_rejected();
    test_grows_past_old_cap();
    test_oom_rejected();
    test_reset_releases_memory();
    printf("  All passed!\n");
    return 0;
}
