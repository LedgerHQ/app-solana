// Unit tests for cs_enum_cache (enum variant descriptor cache).

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_enum_cache.h"
#include "app_mem_utils.h"

static const uint8_t PROGRAM_A[32] = {0xAA};
static const uint8_t PROGRAM_B[32] = {0xBB};

static const uint8_t ENUM_ID_A[] = {'A', 'u', 't', 'h', 'o', 'r', 'i', 't', 'y'};
static const uint8_t ENUM_ID_B[] = {'S', 'i', 'd', 'e'};

// ---- Tests ------------------------------------------------------------------

static void test_empty_cache(void) {
    printf("  test_empty_cache\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    assert(cs_enum_cache_count() == 0);
    assert(cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 0) == NULL);
    assert(mock_mem_outstanding() == 0);
}

static void test_add_and_find_empty_payload(void) {
    printf("  test_add_and_find_empty_payload\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             1,
                             "Withdrawer",
                             strlen("Withdrawer"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_count() == 1);

    const cs_enum_variant_t *found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 1);
    assert(found != NULL);
    assert(found->variant_index == 1);
    assert(found->payload_kind == CS_VARIANT_PAYLOAD_EMPTY);
    assert(strcmp(found->variant_name, "Withdrawer") == 0);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_inline_payload(void) {
    printf("  test_add_inline_payload\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    const uint8_t inline_desc[] = {0x20, 0x01, 0x01};  // STRUCT, 1 field, u8
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             2,
                             "Custodian",
                             strlen("Custodian"),
                             CS_VARIANT_PAYLOAD_INLINE,
                             inline_desc,
                             sizeof(inline_desc)) == 0);

    const cs_enum_variant_t *found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 2);
    assert(found != NULL);
    assert(found->payload_kind == CS_VARIANT_PAYLOAD_INLINE);
    assert(found->payload.inline_descriptor.size == sizeof(inline_desc));
    assert(memcmp(found->payload.inline_descriptor.bytes, inline_desc, sizeof(inline_desc)) == 0);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_add_raw_size_payload(void) {
    printf("  test_add_raw_size_payload\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    const uint8_t raw_size[] = {0x00, 0x10};  // u16 big-endian: 16 bytes
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             3,
                             "Opaque",
                             strlen("Opaque"),
                             CS_VARIANT_PAYLOAD_RAW_SIZE,
                             raw_size,
                             sizeof(raw_size)) == 0);

    const cs_enum_variant_t *found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 3);
    assert(found != NULL);
    assert(found->payload_kind == CS_VARIANT_PAYLOAD_RAW_SIZE);
    assert(found->payload.raw_size == 16);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// Distinct keys must not collide: same variant index under different program,
// enum id, or index resolves to the right record (or misses).
static void test_key_disambiguation(void) {
    printf("  test_key_disambiguation\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "A0",
                             strlen("A0"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_add(PROGRAM_B,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "B0",
                             strlen("B0"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_B,
                             sizeof(ENUM_ID_B),
                             0,
                             "A0b",
                             strlen("A0b"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             1,
                             "A1",
                             strlen("A1"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_count() == 4);

    const cs_enum_variant_t *found;
    found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 0);
    assert(found != NULL && strcmp(found->variant_name, "A0") == 0);
    found = cs_enum_cache_find(PROGRAM_B, ENUM_ID_A, sizeof(ENUM_ID_A), 0);
    assert(found != NULL && strcmp(found->variant_name, "B0") == 0);
    found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_B, sizeof(ENUM_ID_B), 0);
    assert(found != NULL && strcmp(found->variant_name, "A0b") == 0);
    found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 1);
    assert(found != NULL && strcmp(found->variant_name, "A1") == 0);

    // Unknown variant index misses.
    assert(cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 9) == NULL);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_duplicate_rejected(void) {
    printf("  test_duplicate_rejected\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "first",
                             strlen("first"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "second",
                             strlen("second"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == -1);
    assert(cs_enum_cache_count() == 1);

    const cs_enum_variant_t *found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 0);
    assert(found != NULL && strcmp(found->variant_name, "first") == 0);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// No arbitrary count cap: the cache holds as many variants as the pool allows.
static void test_cache_grows_unbounded(void) {
    printf("  test_cache_grows_unbounded\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    // Add well past the removed cap (was 8); every add must succeed.
    const size_t added = 32;
    for (size_t i = 0; i < added; i++) {
        assert(cs_enum_cache_add(PROGRAM_A,
                                 ENUM_ID_A,
                                 sizeof(ENUM_ID_A),
                                 i,
                                 "v",
                                 strlen("v"),
                                 CS_VARIANT_PAYLOAD_EMPTY,
                                 NULL,
                                 0) == 0);
    }
    assert(cs_enum_cache_count() == added);
    // Every added variant is still retrievable.
    assert(cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), added - 1) != NULL);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// OOM is the sole rejection path: a failed allocation refuses the add, returns
// -1, leaves the count untouched, and frees whatever the add already took.
static void test_oom_rejected(void) {
    printf("  test_oom_rejected\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "v",
                             strlen("v"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_count() == 1);

    // The first allocation (pointer-array growth) fails: the add is refused.
    mock_mem_fail_after(0);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             1,
                             "v",
                             strlen("v"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == -1);
    assert(cs_enum_cache_count() == 1);

    // A later per-slot buffer fails (array + slot + enum_id done, name
    // allocation fails): the half-built slot must be fully unwound, not leaked.
    mock_mem_fail_after(3);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             2,
                             "v",
                             strlen("v"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == -1);
    assert(cs_enum_cache_count() == 1);

    mock_mem_fail_after(-1);
    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// The only surviving field cap is the INLINE payload size; an empty enum_id is
// also rejected. Neither leaves a partial entry behind.
static void test_invalid_fields_rejected(void) {
    printf("  test_invalid_fields_rejected\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    // Empty enum_id: no key to match on.
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             0,
                             0,
                             "x",
                             strlen("x"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == -1);

    // INLINE payload larger than the descriptor cap.
    uint8_t big_payload[CS_VARIANT_PAYLOAD_MAX_SIZE + 1] = {0};
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "x",
                             strlen("x"),
                             CS_VARIANT_PAYLOAD_INLINE,
                             big_payload,
                             sizeof(big_payload)) == -1);

    assert(cs_enum_cache_count() == 0);
    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// enum_id and variant_name are sized to their input, so lengths well past the
// old 64-byte caps round-trip intact.
static void test_long_id_and_name_roundtrip(void) {
    printf("  test_long_id_and_name_roundtrip\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    uint8_t long_id[200];
    memset(long_id, 'i', sizeof(long_id));
    char long_name[201];
    memset(long_name, 'n', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    assert(cs_enum_cache_add(PROGRAM_A,
                             long_id,
                             sizeof(long_id),
                             0,
                             long_name,
                             strlen(long_name),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);

    const cs_enum_variant_t *found = cs_enum_cache_find(PROGRAM_A, long_id, sizeof(long_id), 0);
    assert(found != NULL);
    assert(found->enum_id_len == sizeof(long_id));
    assert(memcmp(found->enum_id, long_id, sizeof(long_id)) == 0);
    assert(strcmp(found->variant_name, long_name) == 0);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A NULL/empty variant_name stores as an empty string, always safe to strcmp.
static void test_absent_name(void) {
    printf("  test_absent_name\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             NULL,
                             0,
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    const cs_enum_variant_t *found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 0);
    assert(found != NULL);
    assert(found->variant_name != NULL && found->variant_name[0] == '\0');

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_reset_releases_memory(void) {
    printf("  test_reset_releases_memory\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "v",
                             strlen("v"),
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(mock_mem_outstanding() > 0);

    cs_enum_cache_reset();
    assert(cs_enum_cache_count() == 0);
    assert(mock_mem_outstanding() == 0);

    // Reset again on an already-empty cache must be a no-op.
    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

int main(void) {
    printf("cs_enum_cache_test\n");
    test_empty_cache();
    test_add_and_find_empty_payload();
    test_add_inline_payload();
    test_add_raw_size_payload();
    test_key_disambiguation();
    test_duplicate_rejected();
    test_cache_grows_unbounded();
    test_oom_rejected();
    test_invalid_fields_rejected();
    test_long_id_and_name_roundtrip();
    test_absent_name();
    test_reset_releases_memory();
    printf("  All passed!\n");
    return 0;
}
