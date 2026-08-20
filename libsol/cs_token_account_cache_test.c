// Unit tests for cs_token_account_cache (token account state cache).

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_token_account_cache.h"
#include "app_mem_utils.h"

static const uint8_t ACCOUNT_A[32] = {0xAA};
static const uint8_t ACCOUNT_B[32] = {0xBB};
static const uint8_t MINT_A[32] = {0x11};
static const uint8_t MINT_B[32] = {0x22};
static const uint8_t OWNER_A[32] = {0x33};
static const uint8_t OWNER_B[32] = {0x44};

// ---- Tests ------------------------------------------------------------------

static void test_empty_cache(void) {
    printf("  test_empty_cache\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    assert(cs_token_account_cache_count() == 0);
    assert(cs_token_account_cache_find(ACCOUNT_A) == NULL);
    assert(mock_mem_outstanding() == 0);
}

static void test_add_and_find(void) {
    printf("  test_add_and_find\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    assert(cs_token_account_cache_add(ACCOUNT_A, MINT_A, OWNER_A, 12345) == 0);
    assert(cs_token_account_cache_count() == 1);

    const cs_token_account_t *found = cs_token_account_cache_find(ACCOUNT_A);
    assert(found != NULL);
    assert(memcmp(found->account_address, ACCOUNT_A, 32) == 0);
    assert(found->has_mint);
    assert(memcmp(found->mint, MINT_A, 32) == 0);
    assert(found->has_owner);
    assert(memcmp(found->owner, OWNER_A, 32) == 0);
    assert(found->pre_balance == 12345);

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// An account that does not exist yet is attested by its pre-balance alone: the entry is
// stored with no mint and no owner, and the zeroed fields stay behind their flags.
static void test_add_without_mint_and_owner(void) {
    printf("  test_add_without_mint_and_owner\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    assert(cs_token_account_cache_add(ACCOUNT_A, NULL, NULL, 0) == 0);
    assert(cs_token_account_cache_count() == 1);

    const uint8_t zeroes[32] = {0};
    const cs_token_account_t *found = cs_token_account_cache_find(ACCOUNT_A);
    assert(found != NULL);
    assert(memcmp(found->account_address, ACCOUNT_A, 32) == 0);
    assert(!found->has_mint);
    assert(memcmp(found->mint, zeroes, 32) == 0);
    assert(!found->has_owner);
    assert(memcmp(found->owner, zeroes, 32) == 0);
    assert(found->pre_balance == 0);

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// The two fields are omitted independently, so each one's flag has to answer for itself
// rather than for the pair.
static void test_add_with_one_field_omitted(void) {
    printf("  test_add_with_one_field_omitted\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    assert(cs_token_account_cache_add(ACCOUNT_A, MINT_A, NULL, 0) == 0);
    assert(cs_token_account_cache_add(ACCOUNT_B, NULL, OWNER_B, 0) == 0);

    const uint8_t zeroes[32] = {0};
    const cs_token_account_t *mint_only = cs_token_account_cache_find(ACCOUNT_A);
    assert(mint_only != NULL);
    assert(mint_only->has_mint);
    assert(memcmp(mint_only->mint, MINT_A, 32) == 0);
    assert(!mint_only->has_owner);
    assert(memcmp(mint_only->owner, zeroes, 32) == 0);

    const cs_token_account_t *owner_only = cs_token_account_cache_find(ACCOUNT_B);
    assert(owner_only != NULL);
    assert(!owner_only->has_mint);
    assert(memcmp(owner_only->mint, zeroes, 32) == 0);
    assert(owner_only->has_owner);
    assert(memcmp(owner_only->owner, OWNER_B, 32) == 0);

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// Distinct account keys must resolve to their own record (or miss).
static void test_key_disambiguation(void) {
    printf("  test_key_disambiguation\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    assert(cs_token_account_cache_add(ACCOUNT_A, MINT_A, OWNER_A, 1) == 0);
    assert(cs_token_account_cache_add(ACCOUNT_B, MINT_B, OWNER_B, 2) == 0);
    assert(cs_token_account_cache_count() == 2);

    const cs_token_account_t *found;
    found = cs_token_account_cache_find(ACCOUNT_A);
    assert(found != NULL && memcmp(found->mint, MINT_A, 32) == 0 && found->pre_balance == 1);
    found = cs_token_account_cache_find(ACCOUNT_B);
    assert(found != NULL && memcmp(found->mint, MINT_B, 32) == 0 && found->pre_balance == 2);

    // Unknown account misses.
    uint8_t unknown[32] = {0xCC};
    assert(cs_token_account_cache_find(unknown) == NULL);

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_duplicate_rejected(void) {
    printf("  test_duplicate_rejected\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    assert(cs_token_account_cache_add(ACCOUNT_A, MINT_A, OWNER_A, 1) == 0);
    // Same key, different content: refused.
    assert(cs_token_account_cache_add(ACCOUNT_A, MINT_B, OWNER_B, 2) == -1);
    assert(cs_token_account_cache_count() == 1);

    const cs_token_account_t *found = cs_token_account_cache_find(ACCOUNT_A);
    assert(found != NULL && memcmp(found->mint, MINT_A, 32) == 0 && found->pre_balance == 1);

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// No count cap: the cache grows past the former CS_MAX_TOKEN_ACCOUNTS (8),
// bounded only by the pool. Every entry stays stored and findable.
static void test_grows_past_old_cap(void) {
    printf("  test_grows_past_old_cap\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    const uint8_t count = 40;
    for (uint8_t i = 0; i < count; i++) {
        uint8_t account[32] = {0};
        account[0] = i + 1;
        assert(cs_token_account_cache_add(account, MINT_A, OWNER_A, i) == 0);
    }
    assert(cs_token_account_cache_count() == count);
    for (uint8_t i = 0; i < count; i++) {
        uint8_t account[32] = {0};
        account[0] = i + 1;
        const cs_token_account_t *found = cs_token_account_cache_find(account);
        assert(found != NULL && found->pre_balance == i);
    }

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// The only accepted refusal is an allocation failure: the entry is not stored
// and nothing leaks after reset.
static void test_oom_rejected(void) {
    printf("  test_oom_rejected\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    assert(cs_token_account_cache_add(ACCOUNT_A, MINT_A, OWNER_A, 1) == 0);

    // Fail the pointer-array growth (first allocation of the add).
    mock_mem_fail_after(0);
    assert(cs_token_account_cache_add(ACCOUNT_B, MINT_B, OWNER_B, 2) == -1);
    assert(cs_token_account_cache_count() == 1);

    // Fail the per-entry allocation (growth succeeds, slot alloc fails).
    mock_mem_fail_after(1);
    assert(cs_token_account_cache_add(ACCOUNT_B, MINT_B, OWNER_B, 2) == -1);
    assert(cs_token_account_cache_count() == 1);

    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_reset_releases_memory(void) {
    printf("  test_reset_releases_memory\n");
    mock_mem_reset();
    cs_token_account_cache_reset();

    assert(cs_token_account_cache_add(ACCOUNT_A, MINT_A, OWNER_A, 1) == 0);
    assert(mock_mem_outstanding() > 0);

    cs_token_account_cache_reset();
    assert(cs_token_account_cache_count() == 0);
    assert(mock_mem_outstanding() == 0);

    // Reset again on an already-empty cache must be a no-op.
    cs_token_account_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

int main(void) {
    printf("cs_token_account_cache_test\n");
    test_empty_cache();
    test_add_and_find();
    test_add_without_mint_and_owner();
    test_add_with_one_field_omitted();
    test_key_disambiguation();
    test_duplicate_rejected();
    test_grows_past_old_cap();
    test_oom_rejected();
    test_reset_releases_memory();
    printf("  All passed!\n");
    return 0;
}
