// Unit tests for cs_alt_cache (ALT resolution cache).

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_alt_cache.h"
#include "app_mem_utils.h"

static const uint8_t ALT_A[32] = {0xAA};
static const uint8_t ALT_B[32] = {0xBB};
static const uint8_t RESOLVED_A[32] = {0x11};
static const uint8_t RESOLVED_B[32] = {0x22};

// ---- Tests ------------------------------------------------------------------

static void test_empty_cache(void) {
    printf("  test_empty_cache\n");
    mock_mem_reset();
    cs_alt_cache_reset();

    assert(cs_alt_cache_count() == 0);
    assert(cs_alt_cache_find(ALT_A, 0) == NULL);
    assert(mock_mem_outstanding() == 0);
}

static void test_add_and_find(void) {
    printf("  test_add_and_find\n");
    mock_mem_reset();
    cs_alt_cache_reset();

    assert(cs_alt_cache_add(ALT_A, 3, RESOLVED_A) == 0);
    assert(cs_alt_cache_count() == 1);

    const uint8_t *found = cs_alt_cache_find(ALT_A, 3);
    assert(found != NULL);
    assert(memcmp(found, RESOLVED_A, 32) == 0);

    cs_alt_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// The key is the (alt_address, entry_index) pair: the same ALT address at a
// different entry index is a distinct key, and vice versa.
static void test_key_disambiguation(void) {
    printf("  test_key_disambiguation\n");
    mock_mem_reset();
    cs_alt_cache_reset();

    assert(cs_alt_cache_add(ALT_A, 0, RESOLVED_A) == 0);
    assert(cs_alt_cache_add(ALT_A, 1, RESOLVED_B) == 0);
    assert(cs_alt_cache_add(ALT_B, 0, RESOLVED_B) == 0);
    assert(cs_alt_cache_count() == 3);

    const uint8_t *found;
    found = cs_alt_cache_find(ALT_A, 0);
    assert(found != NULL && memcmp(found, RESOLVED_A, 32) == 0);
    found = cs_alt_cache_find(ALT_A, 1);
    assert(found != NULL && memcmp(found, RESOLVED_B, 32) == 0);
    found = cs_alt_cache_find(ALT_B, 0);
    assert(found != NULL && memcmp(found, RESOLVED_B, 32) == 0);

    // Same ALT address, unprovided entry index misses.
    assert(cs_alt_cache_find(ALT_A, 2) == NULL);
    // Unknown ALT address misses.
    assert(cs_alt_cache_find(ALT_B, 1) == NULL);

    cs_alt_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_duplicate_rejected(void) {
    printf("  test_duplicate_rejected\n");
    mock_mem_reset();
    cs_alt_cache_reset();

    assert(cs_alt_cache_add(ALT_A, 5, RESOLVED_A) == 0);
    // Same key, different content: refused.
    assert(cs_alt_cache_add(ALT_A, 5, RESOLVED_B) == -1);
    assert(cs_alt_cache_count() == 1);

    const uint8_t *found = cs_alt_cache_find(ALT_A, 5);
    assert(found != NULL && memcmp(found, RESOLVED_A, 32) == 0);

    cs_alt_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_cache_full_rejected(void) {
    printf("  test_cache_full_rejected\n");
    mock_mem_reset();
    cs_alt_cache_reset();

    for (uint8_t i = 0; i < CS_MAX_ALT_ENTRIES; i++) {
        assert(cs_alt_cache_add(ALT_A, i, RESOLVED_A) == 0);
    }
    assert(cs_alt_cache_count() == CS_MAX_ALT_ENTRIES);

    // One more entry must be refused.
    assert(cs_alt_cache_add(ALT_A, CS_MAX_ALT_ENTRIES, RESOLVED_B) == -1);
    assert(cs_alt_cache_count() == CS_MAX_ALT_ENTRIES);

    cs_alt_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_reset_releases_memory(void) {
    printf("  test_reset_releases_memory\n");
    mock_mem_reset();
    cs_alt_cache_reset();

    assert(cs_alt_cache_add(ALT_A, 0, RESOLVED_A) == 0);
    assert(mock_mem_outstanding() > 0);

    cs_alt_cache_reset();
    assert(cs_alt_cache_count() == 0);
    assert(mock_mem_outstanding() == 0);

    // Reset again on an already-empty cache must be a no-op.
    cs_alt_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

int main(void) {
    printf("cs_alt_cache_test\n");
    test_empty_cache();
    test_add_and_find();
    test_key_disambiguation();
    test_duplicate_rejected();
    test_cache_full_rejected();
    test_reset_releases_memory();
    printf("  All passed!\n");
    return 0;
}
