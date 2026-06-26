#include "cs_substructure.h"
#include "test_utils.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

// Compute a SHA-256 over a single buffer using the same crypto surface the
// module relies on. Used to derive the target digests the tests commit to.
static void sha256_of(const uint8_t *data, size_t len, uint8_t out[CX_SHA256_SIZE]) {
    cx_sha256_t ctx;
    cx_sha256_init(&ctx);
    CX_ASSERT(cx_hash_update((cx_hash_t *) &ctx, data, len));
    CX_ASSERT(cx_hash_final((cx_hash_t *) &ctx, out));
}

static void setup(void) {
    cs_substructure_reset();
}

// Poll completeness on a live accumulation. Asserts the call itself succeeds
// (active) and returns the match verdict.
static bool query_complete(void) {
    bool complete = false;
    assert(cs_substructure_check_complete(&complete) == 0);
    return complete;
}

// =============================================================================
// SHA-256 backing sanity
// =============================================================================

// Guards against a broken vendored hash: SHA-256("abc") is a published vector.
void test_sha256_known_vector() {
    setup();

    const uint8_t expected[CX_SHA256_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    uint8_t digest[CX_SHA256_SIZE];
    sha256_of((const uint8_t *) "abc", 3, digest);

    assert(memcmp(digest, expected, CX_SHA256_SIZE) == 0);
}

// =============================================================================
// Lifecycle
// =============================================================================

void test_inactive_state() {
    setup();

    // No accumulation begun: update and completeness check must both refuse (-1)
    // rather than silently absorb data or report a verdict.
    bool complete = true;
    assert(cs_substructure_check_complete(&complete) == -1);
    assert(complete == true);  // left untouched by the refused call
    assert(cs_substructure_update((const uint8_t *) "refused", 7) == -1);
}

void test_reset_returns_to_inactive() {
    setup();

    const uint8_t payload[] = {0x10, 0x20, 0x30};
    uint8_t target[CX_SHA256_SIZE];
    sha256_of(payload, sizeof(payload), target);

    cs_substructure_begin(target);
    assert(cs_substructure_update(payload, sizeof(payload)) == 0);
    assert(query_complete() == true);

    // After reset the module is inactive again: both entry points refuse.
    cs_substructure_reset();
    bool complete = false;
    assert(cs_substructure_check_complete(&complete) == -1);
    assert(cs_substructure_update(payload, sizeof(payload)) == -1);
}

// =============================================================================
// Completion
// =============================================================================

void test_single_update_matches() {
    setup();

    const uint8_t payload[] = {0xaa, 0xbb, 0xcc, 0xdd};
    uint8_t target[CX_SHA256_SIZE];
    sha256_of(payload, sizeof(payload), target);

    cs_substructure_begin(target);
    assert(cs_substructure_update(payload, sizeof(payload)) == 0);
    assert(query_complete() == true);
}

// Streaming N chunks must equal the one-shot hash of their concatenation.
void test_multi_chunk_equals_one_shot() {
    setup();

    const uint8_t chunk_a[] = {0x01, 0x02, 0x03};
    const uint8_t chunk_b[] = {0x04, 0x05};
    const uint8_t chunk_c[] = {0x06, 0x07, 0x08, 0x09};
    const uint8_t whole[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    uint8_t target[CX_SHA256_SIZE];
    sha256_of(whole, sizeof(whole), target);

    cs_substructure_begin(target);
    assert(cs_substructure_update(chunk_a, sizeof(chunk_a)) == 0);
    assert(cs_substructure_update(chunk_b, sizeof(chunk_b)) == 0);
    assert(cs_substructure_update(chunk_c, sizeof(chunk_c)) == 0);
    assert(query_complete() == true);
}

// The target is only reached once the final byte has been folded in.
void test_incomplete_until_target_reached() {
    setup();

    const uint8_t chunk_a[] = {0x11, 0x22};
    const uint8_t chunk_b[] = {0x33, 0x44};
    const uint8_t whole[] = {0x11, 0x22, 0x33, 0x44};
    uint8_t target[CX_SHA256_SIZE];
    sha256_of(whole, sizeof(whole), target);

    cs_substructure_begin(target);
    assert(cs_substructure_update(chunk_a, sizeof(chunk_a)) == 0);
    assert(query_complete() == false);
    assert(cs_substructure_update(chunk_b, sizeof(chunk_b)) == 0);
    assert(query_complete() == true);
}

void test_wrong_data_never_completes() {
    setup();

    const uint8_t expected[] = {0xde, 0xad, 0xbe, 0xef};
    const uint8_t actual[] = {0xfe, 0xed, 0xfa, 0xce};
    uint8_t target[CX_SHA256_SIZE];
    sha256_of(expected, sizeof(expected), target);

    cs_substructure_begin(target);
    assert(cs_substructure_update(actual, sizeof(actual)) == 0);
    assert(query_complete() == false);
}

// check_complete() clones and finalizes a copy, so the live context survives and
// further updates keep accumulating.
void test_check_complete_is_non_destructive() {
    setup();

    const uint8_t chunk_a[] = {0x71, 0x72};
    const uint8_t chunk_b[] = {0x73, 0x74};
    const uint8_t whole[] = {0x71, 0x72, 0x73, 0x74};
    uint8_t target_a[CX_SHA256_SIZE];
    uint8_t target_whole[CX_SHA256_SIZE];
    sha256_of(chunk_a, sizeof(chunk_a), target_a);
    sha256_of(whole, sizeof(whole), target_whole);

    cs_substructure_begin(target_a);
    assert(cs_substructure_update(chunk_a, sizeof(chunk_a)) == 0);
    // Polling twice must not consume the running context.
    assert(query_complete() == true);
    assert(query_complete() == true);

    // The accumulation can still progress past the first match.
    cs_substructure_begin(target_whole);
    assert(cs_substructure_update(chunk_a, sizeof(chunk_a)) == 0);
    assert(cs_substructure_update(chunk_b, sizeof(chunk_b)) == 0);
    assert(query_complete() == true);
}

// A fresh begin() discards any in-progress accumulation.
void test_begin_discards_previous() {
    setup();

    const uint8_t stale[] = {0x90, 0x91, 0x92};
    const uint8_t payload[] = {0xa0, 0xa1};
    uint8_t target[CX_SHA256_SIZE];
    sha256_of(payload, sizeof(payload), target);

    cs_substructure_begin(target);
    assert(cs_substructure_update(stale, sizeof(stale)) == 0);
    assert(query_complete() == false);

    cs_substructure_begin(target);
    assert(cs_substructure_update(payload, sizeof(payload)) == 0);
    assert(query_complete() == true);
}

int main() {
    // SHA-256 backing sanity
    RUN_TEST(test_sha256_known_vector);

    // Lifecycle
    RUN_TEST(test_inactive_state);
    RUN_TEST(test_reset_returns_to_inactive);

    // Completion
    RUN_TEST(test_single_update_matches);
    RUN_TEST(test_multi_chunk_equals_one_shot);
    RUN_TEST(test_incomplete_until_target_reached);
    RUN_TEST(test_wrong_data_never_completes);
    RUN_TEST(test_check_complete_is_non_destructive);
    RUN_TEST(test_begin_discards_previous);

    printf("passed\n");
    return 0;
}
