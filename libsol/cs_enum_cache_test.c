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
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_add(PROGRAM_B,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "B0",
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_B,
                             sizeof(ENUM_ID_B),
                             0,
                             "A0b",
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             1,
                             "A1",
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
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "second",
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == -1);
    assert(cs_enum_cache_count() == 1);

    const cs_enum_variant_t *found = cs_enum_cache_find(PROGRAM_A, ENUM_ID_A, sizeof(ENUM_ID_A), 0);
    assert(found != NULL && strcmp(found->variant_name, "first") == 0);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_cache_full_rejected(void) {
    printf("  test_cache_full_rejected\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    for (uint16_t i = 0; i < CS_MAX_ENUM_VARIANTS; i++) {
        assert(cs_enum_cache_add(PROGRAM_A,
                                 ENUM_ID_A,
                                 sizeof(ENUM_ID_A),
                                 i,
                                 "v",
                                 CS_VARIANT_PAYLOAD_EMPTY,
                                 NULL,
                                 0) == 0);
    }
    assert(cs_enum_cache_count() == CS_MAX_ENUM_VARIANTS);

    // One more variant must be refused.
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             CS_MAX_ENUM_VARIANTS,
                             "overflow",
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == -1);
    assert(cs_enum_cache_count() == CS_MAX_ENUM_VARIANTS);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_oversized_fields_rejected(void) {
    printf("  test_oversized_fields_rejected\n");
    mock_mem_reset();
    cs_enum_cache_reset();

    uint8_t big_id[CS_ENUM_ID_MAX_SIZE + 1] = {0};
    assert(cs_enum_cache_add(PROGRAM_A,
                             big_id,
                             sizeof(big_id),
                             0,
                             "x",
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == -1);

    uint8_t big_payload[CS_VARIANT_PAYLOAD_MAX_SIZE + 1] = {0};
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             "x",
                             CS_VARIANT_PAYLOAD_INLINE,
                             big_payload,
                             sizeof(big_payload)) == -1);

    char big_name[CS_VARIANT_NAME_MAX_SIZE + 2] = {0};
    memset(big_name, 'n', CS_VARIANT_NAME_MAX_SIZE + 1);
    assert(cs_enum_cache_add(PROGRAM_A,
                             ENUM_ID_A,
                             sizeof(ENUM_ID_A),
                             0,
                             big_name,
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == -1);

    assert(cs_enum_cache_count() == 0);
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
    test_cache_full_rejected();
    test_oversized_fields_rejected();
    test_reset_releases_memory();
    printf("  All passed!\n");
    return 0;
}
