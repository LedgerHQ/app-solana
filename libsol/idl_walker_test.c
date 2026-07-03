#include "idl_walker.h"
#include "idl_pool.h"
#include "cs_enum_cache.h"
#include "test_utils.h"
#include "app_mem_utils.h"  // mock allocator + test controls (mock_mem_*)

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define MAX_TEST_PATHS 8

// A fixed 32-byte program id used as the enum-variant cache key. Enum-free
// walks ignore it; enum tests store variants under this same id.
static const uint8_t TEST_PROGRAM_ID[32] = {0xC0, 0xFF, 0xEE};

// Test context: separate input paths and output resolved leaves.
typedef struct {
    idl_match_path_t paths[MAX_TEST_PATHS];
    uint8_t path_count;
    idl_resolved_leaf_t resolved[MAX_TEST_PATHS];
    uint8_t resolved_count;
} test_walk_t;

// Run a complete walk against an in-memory pool + data.
// Returns the idl_walker_run() result code, or -1 if the pool fails to parse.
static int run_walk(const uint8_t *pool,
                    size_t pool_size,
                    uint8_t root,
                    const uint8_t *data,
                    size_t data_size,
                    test_walk_t *tw) {
    idl_pool_reset();
    mock_mem_reset();
    if (idl_pool_provide(pool, pool_size, root) != 0) {
        idl_pool_reset();
        assert(mock_mem_outstanding() == 0);
        return -1;
    }
    int rc = idl_walker_run(data,
                            data_size,
                            TEST_PROGRAM_ID,
                            tw->paths,
                            tw->path_count,
                            tw->resolved,
                            &tw->resolved_count);
    idl_pool_reset();
    assert(mock_mem_outstanding() == 0);
    return rc;
}

// Add a path to match at slot `index`.
static void tw_add_path(test_walk_t *tw, uint8_t index, const uint8_t *path, size_t path_size) {
    assert(index < MAX_TEST_PATHS);
    assert(path_size <= IDL_MATCH_PATH_MAX_SIZE);
    memcpy(tw->paths[index].path, path, path_size);
    tw->paths[index].path_size = (uint8_t) path_size;
    if (index >= tw->path_count) {
        tw->path_count = index + 1;
    }
}

// Assert that resolved leaf at slot `index` has the expected kind and value.
static void expect_resolved(const test_walk_t *tw,
                            uint8_t index,
                            uint8_t kind,
                            const uint8_t *value,
                            size_t value_size) {
    assert(index < tw->path_count);
    assert(tw->resolved[index].kind == kind);
    assert(tw->resolved[index].value_size == value_size);
    if (value_size > 0) {
        assert(memcmp(tw->resolved[index].value, value, value_size) == 0);
    }
}

// Run a walk with the enum-variant cache pre-populated by the caller. Unlike
// run_walk it does not reset the cache or assert on outstanding allocations:
// the cache legitimately holds heap across the walk, so the caller owns the
// cache lifecycle (reset + outstanding assertion) around this call.
static int run_walk_enum(const uint8_t *pool,
                         size_t pool_size,
                         uint8_t root,
                         const uint8_t *data,
                         size_t data_size,
                         test_walk_t *tw) {
    idl_pool_reset();
    if (idl_pool_provide(pool, pool_size, root) != 0) {
        idl_pool_reset();
        return -1;
    }
    int rc = idl_walker_run(data,
                            data_size,
                            TEST_PROGRAM_ID,
                            tw->paths,
                            tw->path_count,
                            tw->resolved,
                            &tw->resolved_count);
    idl_pool_reset();
    return rc;
}

// =============================================================================
// Primitive leaves
// =============================================================================

void test_primitive_root_widths() {
    const uint8_t data[16] = {0x11,
                              0x22,
                              0x33,
                              0x44,
                              0x55,
                              0x66,
                              0x77,
                              0x88,
                              0x99,
                              0xaa,
                              0xbb,
                              0xcc,
                              0xdd,
                              0xee,
                              0xff,
                              0x01};
    const uint8_t no_step[] = {0x00};

    struct {
        uint8_t kind;
        size_t width;
    } cases[] = {
        {IDL_KIND_U8, 1},
        {IDL_KIND_I8, 1},
        {IDL_KIND_BOOL_U8, 1},
        {IDL_KIND_U16, 2},
        {IDL_KIND_I16, 2},
        {IDL_KIND_BOOL_U16, 2},
        {IDL_KIND_U32, 4},
        {IDL_KIND_I32, 4},
        {IDL_KIND_BOOL_U32, 4},
        {IDL_KIND_F32, 4},
        {IDL_KIND_U64, 8},
        {IDL_KIND_I64, 8},
        {IDL_KIND_F64, 8},
        {IDL_KIND_U128, 16},
        {IDL_KIND_I128, 16},
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        uint8_t pool[2] = {0x01, cases[k].kind};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, no_step, sizeof(no_step));
        assert(run_walk(pool, sizeof(pool), 0, data, cases[k].width, &tw) == 0);
        assert(tw.resolved_count == 1);
        expect_resolved(&tw, 0, cases[k].kind, data, cases[k].width);
    }
}

void test_pubkey_leaf() {
    uint8_t data[32];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t) (i + 1);
    }
    const uint8_t pool[] = {0x01, IDL_KIND_PUBKEY_32};
    const uint8_t no_step[] = {0x00};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, no_step, sizeof(no_step));
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 1);
    expect_resolved(&tw, 0, IDL_KIND_PUBKEY_32, data, sizeof(data));
}

void test_short_u16_varints() {
    const uint8_t pool[] = {0x01, IDL_KIND_SHORT_U16};
    const uint8_t no_step[] = {0x00};

    // 1-byte varint (value < 0x80).
    {
        const uint8_t data[] = {0x7f};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, no_step, sizeof(no_step));
        assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == 0);
        expect_resolved(&tw, 0, IDL_KIND_SHORT_U16, data, 1);
    }
    // 2-byte varint (value 128).
    {
        const uint8_t data[] = {0x80, 0x01};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, no_step, sizeof(no_step));
        assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == 0);
        expect_resolved(&tw, 0, IDL_KIND_SHORT_U16, data, 2);
    }
    // 3-byte varint (value 0x4000).
    {
        const uint8_t data[] = {0x80, 0x80, 0x01};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, no_step, sizeof(no_step));
        assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == 0);
        expect_resolved(&tw, 0, IDL_KIND_SHORT_U16, data, 3);
    }
}

// =============================================================================
// Byte / string leaves
// =============================================================================

void test_bytes_fixed_leaf() {
    const uint8_t pool[] = {0x01, IDL_KIND_BYTES_FIXED, 0x00, 0x03};
    const uint8_t data[] = {0xaa, 0xbb, 0xcc};
    const uint8_t no_step[] = {0x00};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, no_step, sizeof(no_step));
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 1);
    expect_resolved(&tw, 0, IDL_KIND_BYTES_FIXED, data, 3);
}

void test_string_fixed_leaf() {
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_FIXED, 0x00, 0x04, IDL_ENCODING_UTF8};
    const uint8_t data[] = {'a', 'b', 'c', 'd'};
    const uint8_t no_step[] = {0x00};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, no_step, sizeof(no_step));
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 1);
    expect_resolved(&tw, 0, IDL_KIND_STRING_FIXED, data, 4);
}

void test_string_prefixed_leaf() {
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_PREFIXED, IDL_KIND_U8, IDL_ENCODING_UTF8};
    const uint8_t data[] = {0x03, 'x', 'y', 'z'};
    const uint8_t expected_value[] = {'x', 'y', 'z'};
    const uint8_t no_step[] = {0x00};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, no_step, sizeof(no_step));
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 1);
    expect_resolved(&tw, 0, IDL_KIND_STRING_PREFIXED, expected_value, 3);
}

void test_bytes_remainder_leaf() {
    const uint8_t pool[] = {
        IDL_KIND_U8,               // entry 0
        IDL_KIND_BYTES_REMAINDER,  // entry 1
        IDL_KIND_STRUCT,
        0x02,
        0,
        1,  // entry 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x01, 0xde, 0xad, 0xbe, 0xef};
    const uint8_t path0[] = {0x01, 0x00};
    const uint8_t path1[] = {0x01, 0x01};
    const uint8_t tail[] = {0xde, 0xad, 0xbe, 0xef};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path0, sizeof(path0));
    tw_add_path(&tw, 1, path1, sizeof(path1));
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_U8, data, 1);
    expect_resolved(&tw, 1, IDL_KIND_BYTES_REMAINDER, tail, sizeof(tail));
}

// =============================================================================
// Aggregates
// =============================================================================

void test_struct_two_fields() {
    const uint8_t pool[] = {
        IDL_KIND_U8,   // 0
        IDL_KIND_U32,  // 1
        IDL_KIND_STRUCT,
        0x02,
        0,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xab, 0x11, 0x22, 0x33, 0x44};
    const uint8_t path0[] = {0x01, 0x00};
    const uint8_t path1[] = {0x01, 0x01};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path0, sizeof(path0));
    tw_add_path(&tw, 1, path1, sizeof(path1));
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_U8, &data[0], 1);
    expect_resolved(&tw, 1, IDL_KIND_U32, &data[1], 4);
}

void test_struct_reused_ref() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_STRUCT,
        0x02,
        0,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xaa, 0xbb};
    const uint8_t path0[] = {0x01, 0x00};
    const uint8_t path1[] = {0x01, 0x01};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path0, sizeof(path0));
    tw_add_path(&tw, 1, path1, sizeof(path1));
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_U8, &data[0], 1);
    expect_resolved(&tw, 1, IDL_KIND_U8, &data[1], 1);
}

void test_tuple() {
    const uint8_t pool[] = {
        IDL_KIND_U16,  // 0
        IDL_KIND_U8,   // 1
        IDL_KIND_TUPLE,
        0x02,
        0,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x34, 0x12, 0xff};
    const uint8_t path0[] = {0x01, 0x00};
    const uint8_t path1[] = {0x01, 0x01};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path0, sizeof(path0));
    tw_add_path(&tw, 1, path1, sizeof(path1));
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_U16, &data[0], 2);
    expect_resolved(&tw, 1, IDL_KIND_U8, &data[2], 1);
}

void test_array_fixed() {
    const uint8_t pool[] = {
        IDL_KIND_U16,  // 0
        IDL_KIND_ARRAY_FIXED,
        0x00,
        0x03,
        0,  // 1
        IDL_KIND_STRUCT,
        0x01,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x01, 0x00, 0x02, 0x00, 0x03, 0x00};

    test_walk_t tw = {0};
    const uint8_t p0[] = {0x02, 0x00, 0x00, 0x00};
    const uint8_t p1[] = {0x02, 0x00, 0x00, 0x01};
    const uint8_t p2[] = {0x02, 0x00, 0x00, 0x02};
    tw_add_path(&tw, 0, p0, sizeof(p0));
    tw_add_path(&tw, 1, p1, sizeof(p1));
    tw_add_path(&tw, 2, p2, sizeof(p2));
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 3);
    for (uint8_t i = 0; i < 3; i++) {
        expect_resolved(&tw, i, IDL_KIND_U16, &data[i * 2], 2);
    }
}

void test_array_prefixed() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_ARRAY_PREFIXED,
        IDL_KIND_U8,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x02, 0xaa, 0xbb};
    const uint8_t path0[] = {0x01, 0x00, 0x00};
    const uint8_t path1[] = {0x01, 0x00, 0x01};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path0, sizeof(path0));
    tw_add_path(&tw, 1, path1, sizeof(path1));
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_U8, &data[1], 1);
    expect_resolved(&tw, 1, IDL_KIND_U8, &data[2], 1);
}

void test_array_remainder() {
    const uint8_t pool[] = {
        IDL_KIND_U16,  // 0
        IDL_KIND_ARRAY_REMAINDER,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x01, 0x00, 0x02, 0x00, 0x03, 0x00};

    test_walk_t tw = {0};
    const uint8_t p0[] = {0x01, 0x00, 0x00};
    const uint8_t p1[] = {0x01, 0x00, 0x01};
    const uint8_t p2[] = {0x01, 0x00, 0x02};
    tw_add_path(&tw, 0, p0, sizeof(p0));
    tw_add_path(&tw, 1, p1, sizeof(p1));
    tw_add_path(&tw, 2, p2, sizeof(p2));
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 3);
    for (uint8_t i = 0; i < 3; i++) {
        expect_resolved(&tw, i, IDL_KIND_U16, &data[i * 2], 2);
    }
}

// =============================================================================
// Options
// =============================================================================

void test_option_dynamic() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_OPTION_DYNAMIC,
        IDL_KIND_U8,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0, nothing emitted, the flag byte is the whole buffer.
    {
        const uint8_t data[] = {0x00};
        test_walk_t tw = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 0);
    }
    // Present: flag 1, then the inner u8.
    {
        const uint8_t data[] = {0x01, 0xcd};
        const uint8_t path[] = {0x01, 0x00};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, path, sizeof(path));
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 1);
        expect_resolved(&tw, 0, IDL_KIND_U8, &data[1], 1);
    }
}

void test_option_fixed() {
    const uint8_t pool[] = {
        IDL_KIND_U32,  // 0
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0 + 4 skipped bytes, nothing emitted.
    {
        const uint8_t data[] = {0x00, 0x11, 0x22, 0x33, 0x44};
        test_walk_t tw = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 0);
    }
    // Present: flag 1, then the inner u32.
    {
        const uint8_t data[] = {0x01, 0xaa, 0xbb, 0xcc, 0xdd};
        const uint8_t path[] = {0x01, 0x00};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, path, sizeof(path));
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 1);
        expect_resolved(&tw, 0, IDL_KIND_U32, &data[1], 4);
    }
}

void test_option_zeroable() {
    uint8_t pool[1 + 1 + 3 + 32];
    size_t n = 0;
    pool[n++] = 2;
    pool[n++] = IDL_KIND_PUBKEY_32;
    pool[n++] = IDL_KIND_OPTION_ZEROABLE;
    pool[n++] = 0;
    pool[n++] = 32;
    for (size_t i = 0; i < 32; i++) {
        pool[n++] = 0x00;
    }
    assert(n == sizeof(pool));

    // Sentinel match (all zero): nothing emitted.
    {
        uint8_t data[32] = {0};
        test_walk_t tw = {0};
        assert(run_walk(pool, sizeof(pool), 1, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 0);
    }
    // Non-sentinel: the inner pubkey is emitted.
    {
        uint8_t data[32];
        for (size_t i = 0; i < 32; i++) {
            data[i] = (uint8_t) (i + 1);
        }
        const uint8_t path[] = {0x01, 0x00};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, path, sizeof(path));
        assert(run_walk(pool, sizeof(pool), 1, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 1);
        expect_resolved(&tw, 0, IDL_KIND_PUBKEY_32, data, 32);
    }
}

void test_option_remainder() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_OPTION_REMAINDER,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Empty buffer: option absent, nothing emitted.
    {
        test_walk_t tw = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, NULL, 0, &tw) == 0);
        assert(tw.resolved_count == 0);
    }
    // Non-empty: option present.
    {
        const uint8_t data[] = {0x7e};
        const uint8_t path[] = {0x01, 0x00};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, path, sizeof(path));
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 1);
        expect_resolved(&tw, 0, IDL_KIND_U8, data, 1);
    }
}

// =============================================================================
// Hidden wrappers
// =============================================================================

void test_hidden_prefix() {
    const uint8_t pool[] = {
        IDL_KIND_U32,  // 0 (skip)
        IDL_KIND_U8,   // 1 (inner)
        IDL_KIND_HIDDEN_PREFIX,
        0,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0xab};
    const uint8_t path_skip[] = {0x01, 0x01};
    const uint8_t path_inner[] = {0x01, 0x00};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path_skip, sizeof(path_skip));
    tw_add_path(&tw, 1, path_inner, sizeof(path_inner));
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_U32, &data[0], 4);
    expect_resolved(&tw, 1, IDL_KIND_U8, &data[4], 1);
}

void test_hidden_suffix() {
    const uint8_t pool[] = {
        IDL_KIND_U32,  // 0 (skip)
        IDL_KIND_U8,   // 1 (inner)
        IDL_KIND_HIDDEN_SUFFIX,
        0,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xab, 0x11, 0x22, 0x33, 0x44};
    const uint8_t path_inner[] = {0x01, 0x00};
    const uint8_t path_skip[] = {0x01, 0x01};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path_inner, sizeof(path_inner));
    tw_add_path(&tw, 1, path_skip, sizeof(path_skip));
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_U8, &data[0], 1);
    expect_resolved(&tw, 1, IDL_KIND_U32, &data[1], 4);
}

// =============================================================================
// Deep nesting (stack growth) and path packing
// =============================================================================

void test_deep_nesting_grows_stack() {
    const uint8_t depth = 12;
    uint8_t pool[64];
    size_t n = 0;
    pool[n++] = depth + 1;
    pool[n++] = IDL_KIND_U8;
    for (uint8_t i = 1; i <= depth; i++) {
        pool[n++] = IDL_KIND_STRUCT;
        pool[n++] = 1;
        pool[n++] = i - 1;
    }

    const uint8_t data[] = {0x5a};
    uint8_t expected_path[1 + 12] = {0};
    expected_path[0] = depth;

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, expected_path, 1 + depth);
    assert(run_walk(pool, n, depth, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 1);
    expect_resolved(&tw, 0, IDL_KIND_U8, data, 1);
}

// =============================================================================
// Structural validation
// =============================================================================

void test_structural_validation() {
    const uint8_t pool[] = {0x01, IDL_KIND_U32};

    // Walk validates the cursor: exact consume.
    {
        const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
        idl_pool_reset();
        mock_mem_reset();
        assert(idl_pool_provide(pool, sizeof(pool), 0) == 0);
        test_walk_t tw = {0};
        assert(idl_walker_run(data,
                              sizeof(data),
                              TEST_PROGRAM_ID,
                              tw.paths,
                              tw.path_count,
                              tw.resolved,
                              &tw.resolved_count) == 0);
        idl_pool_reset();
        assert(mock_mem_outstanding() == 0);
    }
    // Walk returns -1 on a length mismatch.
    {
        const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        idl_pool_reset();
        mock_mem_reset();
        assert(idl_pool_provide(pool, sizeof(pool), 0) == 0);
        test_walk_t tw = {0};
        assert(idl_walker_run(data,
                              sizeof(data),
                              TEST_PROGRAM_ID,
                              tw.paths,
                              tw.path_count,
                              tw.resolved,
                              &tw.resolved_count) == -1);
        idl_pool_reset();
        assert(mock_mem_outstanding() == 0);
    }
}

// =============================================================================
// Error paths
// =============================================================================

void test_error_data_too_short() {
    const uint8_t pool[] = {
        IDL_KIND_U8,   // 0
        IDL_KIND_U32,  // 1
        IDL_KIND_STRUCT,
        0x02,
        0,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xab, 0x11, 0x22};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == -1);
}

void test_error_data_too_long() {
    const uint8_t pool[] = {0x01, IDL_KIND_U8};
    const uint8_t data[] = {0xaa, 0xbb};
    test_walk_t tw = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == -1);
}

// =============================================================================
// Enum variant decoding
// =============================================================================

// enum_id shared by the enum tests: a struct{ ENUM, U8 } root where the enum's
// variant name and the trailing u8 are both matched leaves. The u8 position
// proves the enum consumed exactly the discriminator (+ payload) it should.
static const uint8_t ENUM_ID[] = {'s', 'w'};

// Pool: entry 0 = ENUM(disc U8, total_variants=4, enum_id "sw"),
//       entry 1 = U8, entry 2 = STRUCT[enum, u8].
static const uint8_t ENUM_STRUCT_POOL[] = {
    0x03,
    IDL_KIND_ENUM,
    IDL_KIND_U8,
    0x00,
    0x04,
    0x02,
    's',
    'w',          // 0
    IDL_KIND_U8,  // 1
    IDL_KIND_STRUCT,
    0x02,
    0,
    1,  // 2
};

// Empty-payload variant: the discriminator alone is consumed, the variant name
// is emitted as the enum leaf, and the trailing u8 follows immediately.
void test_enum_empty_payload() {
    mock_mem_reset();
    cs_enum_cache_reset();
    assert(cs_enum_cache_add(TEST_PROGRAM_ID,
                             ENUM_ID,
                             sizeof(ENUM_ID),
                             0,
                             "Alpha",
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);

    const uint8_t data[] = {0x00, 0xAB};  // disc=0, u8=0xAB
    const uint8_t enum_path[] = {0x01, 0x00};
    const uint8_t u8_path[] = {0x01, 0x01};
    test_walk_t tw = {0};
    tw_add_path(&tw, 0, enum_path, sizeof(enum_path));
    tw_add_path(&tw, 1, u8_path, sizeof(u8_path));

    assert(run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
           0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_ENUM, (const uint8_t *) "Alpha", 5);
    expect_resolved(&tw, 1, IDL_KIND_U8, &data[1], 1);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// RAW_SIZE variant: the captured u16 BE byte count is skipped opaquely between
// the discriminator and the trailing u8.
void test_enum_raw_size_payload() {
    mock_mem_reset();
    cs_enum_cache_reset();
    const uint8_t raw_size[] = {0x00, 0x04};  // 4 opaque bytes
    assert(cs_enum_cache_add(TEST_PROGRAM_ID,
                             ENUM_ID,
                             sizeof(ENUM_ID),
                             2,
                             "Gamma",
                             CS_VARIANT_PAYLOAD_RAW_SIZE,
                             raw_size,
                             sizeof(raw_size)) == 0);

    // disc=2, 4 opaque bytes, u8=0x77
    const uint8_t data[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x77};
    const uint8_t enum_path[] = {0x01, 0x00};
    const uint8_t u8_path[] = {0x01, 0x01};
    test_walk_t tw = {0};
    tw_add_path(&tw, 0, enum_path, sizeof(enum_path));
    tw_add_path(&tw, 1, u8_path, sizeof(u8_path));

    assert(run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
           0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_ENUM, (const uint8_t *) "Gamma", 5);
    expect_resolved(&tw, 1, IDL_KIND_U8, &data[5], 1);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A discriminator with no matching cached variant fails the walk closed.
void test_enum_missing_variant_fails() {
    mock_mem_reset();
    cs_enum_cache_reset();
    // Cache holds only variant 0; the data selects variant 1.
    assert(cs_enum_cache_add(TEST_PROGRAM_ID,
                             ENUM_ID,
                             sizeof(ENUM_ID),
                             0,
                             "Alpha",
                             CS_VARIANT_PAYLOAD_EMPTY,
                             NULL,
                             0) == 0);

    const uint8_t data[] = {0x01, 0xAB};  // disc=1 -> not cached
    test_walk_t tw = {0};
    assert(run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
           -1);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// A discriminator >= total_variants is rejected before any cache lookup.
void test_enum_discriminator_out_of_range() {
    mock_mem_reset();
    cs_enum_cache_reset();

    const uint8_t data[] = {0x05, 0xAB};  // disc=5 >= total_variants=4
    test_walk_t tw = {0};
    assert(run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
           -1);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// INLINE payload with a STRUCT{ U8, U32 } body: the two inner fields become
// leaves under the enum, and the trailing root u8 still follows the payload.
void test_enum_inline_struct_payload() {
    mock_mem_reset();
    cs_enum_cache_reset();
    const uint8_t inline_desc[] = {IDL_KIND_STRUCT, 0x02, IDL_KIND_U8, IDL_KIND_U32};
    assert(cs_enum_cache_add(TEST_PROGRAM_ID,
                             ENUM_ID,
                             sizeof(ENUM_ID),
                             1,
                             "Beta",
                             CS_VARIANT_PAYLOAD_INLINE,
                             inline_desc,
                             sizeof(inline_desc)) == 0);

    // disc=1, payload u8=0x55, payload u32 LE bytes {DE,AD,BE,EF}, trailing u8=0xAB.
    const uint8_t data[] = {0x01, 0x55, 0xDE, 0xAD, 0xBE, 0xEF, 0xAB};
    const uint8_t enum_path[] = {0x01, 0x00};
    const uint8_t inner_u8_path[] = {0x03, 0x00, 0x01, 0x00};
    const uint8_t inner_u32_path[] = {0x03, 0x00, 0x01, 0x01};
    const uint8_t trailing_u8_path[] = {0x01, 0x01};
    test_walk_t tw = {0};
    tw_add_path(&tw, 0, enum_path, sizeof(enum_path));
    tw_add_path(&tw, 1, inner_u8_path, sizeof(inner_u8_path));
    tw_add_path(&tw, 2, inner_u32_path, sizeof(inner_u32_path));
    tw_add_path(&tw, 3, trailing_u8_path, sizeof(trailing_u8_path));

    assert(run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
           0);
    assert(tw.resolved_count == 4);
    expect_resolved(&tw, 0, IDL_KIND_ENUM, (const uint8_t *) "Beta", 4);
    expect_resolved(&tw, 1, IDL_KIND_U8, &data[1], 1);
    expect_resolved(&tw, 2, IDL_KIND_U32, &data[2], 4);
    expect_resolved(&tw, 3, IDL_KIND_U8, &data[6], 1);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// INLINE payload with a nested aggregate: STRUCT{ STRUCT{ U8, U16 }, U8 }.
// Reaching the second field requires skipping the whole nested-struct
// descriptor span, exercising inline_span over an aggregate.
void test_enum_inline_nested_payload() {
    mock_mem_reset();
    cs_enum_cache_reset();
    const uint8_t inline_desc[] = {
        IDL_KIND_STRUCT,
        0x02,
        IDL_KIND_STRUCT,
        0x02,
        IDL_KIND_U8,
        IDL_KIND_U16,
        IDL_KIND_U8,
    };
    assert(cs_enum_cache_add(TEST_PROGRAM_ID,
                             ENUM_ID,
                             sizeof(ENUM_ID),
                             1,
                             "Beta",
                             CS_VARIANT_PAYLOAD_INLINE,
                             inline_desc,
                             sizeof(inline_desc)) == 0);

    // disc=1, nested u8=0x11, nested u16 LE {33,22}, field1 u8=0x44, trailing u8=0xAB.
    const uint8_t data[] = {0x01, 0x11, 0x33, 0x22, 0x44, 0xAB};
    const uint8_t nested_u8_path[] = {0x04, 0x00, 0x01, 0x00, 0x00};
    const uint8_t nested_u16_path[] = {0x04, 0x00, 0x01, 0x00, 0x01};
    const uint8_t field1_u8_path[] = {0x03, 0x00, 0x01, 0x01};
    const uint8_t trailing_u8_path[] = {0x01, 0x01};
    test_walk_t tw = {0};
    tw_add_path(&tw, 0, nested_u8_path, sizeof(nested_u8_path));
    tw_add_path(&tw, 1, nested_u16_path, sizeof(nested_u16_path));
    tw_add_path(&tw, 2, field1_u8_path, sizeof(field1_u8_path));
    tw_add_path(&tw, 3, trailing_u8_path, sizeof(trailing_u8_path));

    assert(run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
           0);
    assert(tw.resolved_count == 4);
    expect_resolved(&tw, 0, IDL_KIND_U8, &data[1], 1);
    expect_resolved(&tw, 1, IDL_KIND_U16, &data[2], 2);
    expect_resolved(&tw, 2, IDL_KIND_U8, &data[4], 1);
    expect_resolved(&tw, 3, IDL_KIND_U8, &data[5], 1);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// INLINE payload holding an OPTION_DYNAMIC(U8 flag, U32 inner): when the flag
// is set, the inner leaf is present under the enum; when clear, it is absent
// and only the trailing root u8 follows.
void test_enum_inline_option_payload() {
    const uint8_t inline_desc[] = {
        IDL_KIND_STRUCT,
        0x01,
        IDL_KIND_OPTION_DYNAMIC,
        IDL_KIND_U8,
        IDL_KIND_U32,
    };
    const uint8_t inner_u32_path[] = {0x04, 0x00, 0x01, 0x00, 0x00};
    const uint8_t trailing_u8_path[] = {0x01, 0x01};

    // Flag present: inner u32 decoded.
    mock_mem_reset();
    cs_enum_cache_reset();
    assert(cs_enum_cache_add(TEST_PROGRAM_ID,
                             ENUM_ID,
                             sizeof(ENUM_ID),
                             1,
                             "Beta",
                             CS_VARIANT_PAYLOAD_INLINE,
                             inline_desc,
                             sizeof(inline_desc)) == 0);
    {
        const uint8_t data[] = {0x01, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xAB};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, inner_u32_path, sizeof(inner_u32_path));
        tw_add_path(&tw, 1, trailing_u8_path, sizeof(trailing_u8_path));
        assert(
            run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
            0);
        assert(tw.resolved_count == 2);
        expect_resolved(&tw, 0, IDL_KIND_U32, &data[2], 4);
        expect_resolved(&tw, 1, IDL_KIND_U8, &data[6], 1);
    }
    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);

    // Flag absent: the inner slot resolves to nothing, trailing u8 still follows.
    mock_mem_reset();
    cs_enum_cache_reset();
    assert(cs_enum_cache_add(TEST_PROGRAM_ID,
                             ENUM_ID,
                             sizeof(ENUM_ID),
                             1,
                             "Beta",
                             CS_VARIANT_PAYLOAD_INLINE,
                             inline_desc,
                             sizeof(inline_desc)) == 0);
    {
        const uint8_t data[] = {0x01, 0x00, 0xAB};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, inner_u32_path, sizeof(inner_u32_path));
        tw_add_path(&tw, 1, trailing_u8_path, sizeof(trailing_u8_path));
        assert(
            run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
            0);
        assert(tw.resolved_count == 1);
        expect_resolved(&tw, 1, IDL_KIND_U8, &data[2], 1);
    }
    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// An INLINE payload whose fields overrun the instruction data fails closed.
void test_enum_inline_payload_overruns_data() {
    mock_mem_reset();
    cs_enum_cache_reset();
    // Payload wants a u32, but only one byte follows the discriminator.
    const uint8_t inline_desc[] = {IDL_KIND_STRUCT, 0x01, IDL_KIND_U32};
    assert(cs_enum_cache_add(TEST_PROGRAM_ID,
                             ENUM_ID,
                             sizeof(ENUM_ID),
                             1,
                             "Beta",
                             CS_VARIANT_PAYLOAD_INLINE,
                             inline_desc,
                             sizeof(inline_desc)) == 0);

    const uint8_t data[] = {0x01, 0x55};  // disc=1, then a lone byte (u32 needs 4)
    test_walk_t tw = {0};
    assert(run_walk_enum(ENUM_STRUCT_POOL, sizeof(ENUM_STRUCT_POOL), 2, data, sizeof(data), &tw) ==
           -1);

    cs_enum_cache_reset();
    assert(mock_mem_outstanding() == 0);
}

// =============================================================================
// Out-of-space injection
// =============================================================================

void test_oom_at_each_alloc_site() {
    const uint8_t pool[] = {
        IDL_KIND_U8,   // 0
        IDL_KIND_U32,  // 1
        IDL_KIND_STRUCT,
        0x02,
        0,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));
    const uint8_t data[] = {0xab, 0x11, 0x22, 0x33, 0x44};

    for (int fail_at = 0; fail_at < 3; fail_at++) {
        idl_pool_reset();

        mock_mem_fail_after(fail_at);
        int rc;
        if (idl_pool_provide(pool_buf, sizeof(pool_buf), 2) != 0) {
            rc = -1;
        } else {
            test_walk_t tw = {0};
            rc = idl_walker_run(data,
                                sizeof(data),
                                TEST_PROGRAM_ID,
                                tw.paths,
                                tw.path_count,
                                tw.resolved,
                                &tw.resolved_count);
        }
        assert(rc == -1);

        idl_pool_reset();
        assert(mock_mem_outstanding() == 0);
        mock_mem_fail_after(-1);
    }
}

void test_oom_fixed_size_table() {
    const uint8_t pool[] = {
        IDL_KIND_U8,   // 0
        IDL_KIND_U32,  // 1
        IDL_KIND_STRUCT,
        0x02,
        0,
        1,  // 2
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        2,  // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));
    const uint8_t data[] = {0x01, 0xab, 0x11, 0x22, 0x33, 0x44};

    for (int fail_at = 0; fail_at < 4; fail_at++) {
        idl_pool_reset();

        mock_mem_fail_after(fail_at);
        int rc;
        if (idl_pool_provide(pool_buf, sizeof(pool_buf), 3) != 0) {
            rc = -1;
        } else {
            test_walk_t tw = {0};
            rc = idl_walker_run(data,
                                sizeof(data),
                                TEST_PROGRAM_ID,
                                tw.paths,
                                tw.path_count,
                                tw.resolved,
                                &tw.resolved_count);
        }
        assert(rc == -1);

        idl_pool_reset();
        assert(mock_mem_outstanding() == 0);
        mock_mem_fail_after(-1);
    }
}

// =============================================================================
// OPTION_FIXED with non-primitive inner (static-size table)
// =============================================================================

void test_option_fixed_struct_inner() {
    const uint8_t pool[] = {
        IDL_KIND_U8,   // 0
        IDL_KIND_U32,  // 1
        IDL_KIND_STRUCT,
        0x02,
        0,
        1,  // 2
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        2,  // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0 + 5 statically-skipped bytes, nothing emitted.
    {
        const uint8_t data[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        test_walk_t tw = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 0);
    }
    // Present: flag 1, then the struct.
    {
        const uint8_t data[] = {0x01, 0xab, 0x11, 0x22, 0x33, 0x44};
        const uint8_t path0[] = {0x02, 0x00, 0x00};
        const uint8_t path1[] = {0x02, 0x00, 0x01};
        test_walk_t tw = {0};
        tw_add_path(&tw, 0, path0, sizeof(path0));
        tw_add_path(&tw, 1, path1, sizeof(path1));
        assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 2);
        expect_resolved(&tw, 0, IDL_KIND_U8, &data[1], 1);
        expect_resolved(&tw, 1, IDL_KIND_U32, &data[2], 4);
    }
}

void test_option_fixed_array_inner() {
    const uint8_t pool[] = {
        IDL_KIND_U16,  // 0
        IDL_KIND_ARRAY_FIXED,
        0x00,
        0x02,
        0,  // 1
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 0);
}

void test_option_fixed_zeroable_inner() {
    uint8_t pool[40];
    size_t n = 0;
    pool[n++] = 3;
    pool[n++] = IDL_KIND_PUBKEY_32;
    pool[n++] = IDL_KIND_OPTION_ZEROABLE;
    pool[n++] = 0;
    pool[n++] = 32;
    for (size_t i = 0; i < 32; i++) {
        pool[n++] = 0x00;
    }
    pool[n++] = IDL_KIND_OPTION_FIXED;
    pool[n++] = IDL_KIND_U8;
    pool[n++] = 1;
    assert(n == sizeof(pool));

    uint8_t data[1 + 32] = {0};
    data[0] = 0x00;
    test_walk_t tw = {0};
    assert(run_walk(pool, sizeof(pool), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 0);
}

void test_option_fixed_hidden_inner() {
    const uint8_t pool[] = {
        IDL_KIND_U16,  // 0 (skip)
        IDL_KIND_U8,   // 1 (inner)
        IDL_KIND_HIDDEN_SUFFIX,
        0,
        1,  // 2
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        2,  // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0x11, 0x22, 0x33};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 0);
}

void test_option_fixed_bytes_inner() {
    const uint8_t pool[] = {
        IDL_KIND_BYTES_FIXED,
        0x00,
        0x03,  // 0
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0 + 3 statically-skipped bytes.
    {
        const uint8_t data[] = {0x00, 0x11, 0x22, 0x33};
        test_walk_t tw = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
        assert(tw.resolved_count == 0);
    }
    // Absent but too few bytes to skip: the walk returns -1.
    {
        const uint8_t data[] = {0x00, 0x11};
        test_walk_t tw = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == -1);
    }
}

void test_option_fixed_array_variable_child_fails() {
    const uint8_t pool[] = {
        IDL_KIND_STRING_PREFIXED,
        IDL_KIND_U8,
        IDL_ENCODING_UTF8,  // 0
        IDL_KIND_ARRAY_FIXED,
        0x00,
        0x02,
        0,  // 1
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0x11, 0x22};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == -1);
}

void test_option_fixed_hidden_variable_child_fails() {
    const uint8_t pool[] = {
        IDL_KIND_STRING_PREFIXED,
        IDL_KIND_U8,
        IDL_ENCODING_UTF8,  // 0 (skip)
        IDL_KIND_U8,        // 1 (inner)
        IDL_KIND_HIDDEN_PREFIX,
        0,
        1,  // 2
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        2,  // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0x11, 0x22};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &tw) == -1);
}

void test_option_fixed_forward_reference() {
    const uint8_t pool[] = {
        IDL_KIND_STRUCT,
        0x02,
        1,
        2,             // 0 (refers forward)
        IDL_KIND_U8,   // 1
        IDL_KIND_U32,  // 2
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        0,  // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 0);
}

void test_option_zeroable_empty_sentinel() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_OPTION_ZEROABLE,
        0,
        0,  // 1
        IDL_KIND_STRUCT,
        0x02,
        1,
        0,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x7c};
    const uint8_t path[] = {0x01, 0x01};
    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path, sizeof(path));
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 1);
    expect_resolved(&tw, 0, IDL_KIND_U8, &data[0], 1);
}

void test_option_zeroable_sentinel_longer_than_data() {
    uint8_t pool[37];
    size_t n = 0;
    pool[n++] = 2;
    pool[n++] = IDL_KIND_PUBKEY_32;
    pool[n++] = IDL_KIND_OPTION_ZEROABLE;
    pool[n++] = 0;
    pool[n++] = 32;
    for (size_t i = 0; i < 32; i++) {
        pool[n++] = 0x00;
    }
    assert(n == sizeof(pool));

    const uint8_t data[] = {0x01, 0x02, 0x03};
    test_walk_t tw = {0};
    assert(run_walk(pool, sizeof(pool), 1, data, sizeof(data), &tw) == -1);
}

void test_option_fixed_variable_inner_absent_fails() {
    const uint8_t pool[] = {
        IDL_KIND_STRING_PREFIXED,
        IDL_KIND_U8,
        IDL_ENCODING_UTF8,  // 0
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent flag with trailing bytes: inner is variable -> -1.
    const uint8_t data[] = {0x00, 0x11, 0x22};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == -1);

    // Present is fine: flag 1, len 2, then 2 string bytes.
    const uint8_t data_present[] = {0x01, 0x02, 'h', 'i'};
    const uint8_t value[] = {'h', 'i'};
    const uint8_t path[] = {0x01, 0x00};
    test_walk_t tw2 = {0};
    tw_add_path(&tw2, 0, path, sizeof(path));
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data_present, sizeof(data_present), &tw2) == 0);
    assert(tw2.resolved_count == 1);
    expect_resolved(&tw2, 0, IDL_KIND_STRING_PREFIXED, value, 2);
}

void test_option_fixed_struct_variable_child_fails() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_STRING_PREFIXED,
        IDL_KIND_U8,
        IDL_ENCODING_UTF8,  // 1
        IDL_KIND_STRUCT,
        0x02,
        0,
        1,  // 2
        IDL_KIND_OPTION_FIXED,
        IDL_KIND_U8,
        2,  // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0x11, 0x22};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &tw) == -1);
}

// =============================================================================
// Length / flag kind variants
// =============================================================================

void test_array_prefixed_len_short_u16() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_ARRAY_PREFIXED,
        IDL_KIND_SHORT_U16,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x02, 0xaa, 0xbb};
    const uint8_t path0[] = {0x01, 0x00, 0x00};
    const uint8_t path1[] = {0x01, 0x00, 0x01};
    test_walk_t tw = {0};
    tw_add_path(&tw, 0, path0, sizeof(path0));
    tw_add_path(&tw, 1, path1, sizeof(path1));
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == 0);
    assert(tw.resolved_count == 2);
    expect_resolved(&tw, 0, IDL_KIND_U8, &data[1], 1);
    expect_resolved(&tw, 1, IDL_KIND_U8, &data[2], 1);
}

void test_string_prefixed_len_u16() {
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_PREFIXED, IDL_KIND_U16, IDL_ENCODING_UTF8};
    const uint8_t data[] = {0x03, 0x00, 'a', 'b', 'c'};
    const uint8_t value[] = {'a', 'b', 'c'};
    const uint8_t no_step[] = {0x00};

    test_walk_t tw = {0};
    tw_add_path(&tw, 0, no_step, sizeof(no_step));
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == 0);
    expect_resolved(&tw, 0, IDL_KIND_STRING_PREFIXED, value, 3);
}

void test_error_invalid_len_kind() {
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_PREFIXED, IDL_KIND_U128, IDL_ENCODING_UTF8};
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    test_walk_t tw = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == -1);
}

void test_error_invalid_flag_kind() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_OPTION_DYNAMIC,
        IDL_KIND_PUBKEY_32,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x01, 0x02};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == -1);
}

// =============================================================================
// Read-past-end on individual leaf kinds
// =============================================================================

void test_error_short_u16_truncated() {
    const uint8_t pool[] = {0x01, IDL_KIND_SHORT_U16};
    const uint8_t data[] = {0x80};
    test_walk_t tw = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == -1);
}

void test_error_bytes_fixed_too_short() {
    const uint8_t pool[] = {0x01, IDL_KIND_BYTES_FIXED, 0x00, 0x04};
    const uint8_t data[] = {0xaa, 0xbb};
    test_walk_t tw = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == -1);
}

void test_error_string_prefixed_value_too_short() {
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_PREFIXED, IDL_KIND_U8, IDL_ENCODING_UTF8};
    const uint8_t data[] = {0x04, 'a', 'b'};
    test_walk_t tw = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &tw) == -1);
}

void test_error_array_prefixed_len_truncated() {
    const uint8_t pool[] = {
        IDL_KIND_U8,  // 0
        IDL_KIND_ARRAY_PREFIXED,
        IDL_KIND_U8,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, NULL, 0, &tw) == -1);
}

void test_error_array_remainder_zero_progress() {
    const uint8_t pool[] = {
        IDL_KIND_STRUCT,
        0x00,  // 0: empty struct
        IDL_KIND_ARRAY_REMAINDER,
        0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xff};
    test_walk_t tw = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &tw) == -1);
}

int main() {
    // Primitive leaves
    RUN_TEST(test_primitive_root_widths);
    RUN_TEST(test_pubkey_leaf);
    RUN_TEST(test_short_u16_varints);

    // Byte / string leaves
    RUN_TEST(test_bytes_fixed_leaf);
    RUN_TEST(test_string_fixed_leaf);
    RUN_TEST(test_string_prefixed_leaf);
    RUN_TEST(test_bytes_remainder_leaf);

    // Aggregates
    RUN_TEST(test_struct_two_fields);
    RUN_TEST(test_struct_reused_ref);
    RUN_TEST(test_tuple);
    RUN_TEST(test_array_fixed);
    RUN_TEST(test_array_prefixed);
    RUN_TEST(test_array_remainder);

    // Options
    RUN_TEST(test_option_dynamic);
    RUN_TEST(test_option_fixed);
    RUN_TEST(test_option_zeroable);
    RUN_TEST(test_option_remainder);

    // OPTION_FIXED with non-primitive inner (static-size table)
    RUN_TEST(test_option_fixed_struct_inner);
    RUN_TEST(test_option_fixed_array_inner);
    RUN_TEST(test_option_fixed_zeroable_inner);
    RUN_TEST(test_option_fixed_hidden_inner);
    RUN_TEST(test_option_fixed_bytes_inner);
    RUN_TEST(test_option_fixed_forward_reference);
    RUN_TEST(test_option_fixed_variable_inner_absent_fails);
    RUN_TEST(test_option_fixed_struct_variable_child_fails);
    RUN_TEST(test_option_fixed_array_variable_child_fails);
    RUN_TEST(test_option_fixed_hidden_variable_child_fails);
    RUN_TEST(test_option_zeroable_empty_sentinel);
    RUN_TEST(test_option_zeroable_sentinel_longer_than_data);

    // Hidden wrappers
    RUN_TEST(test_hidden_prefix);
    RUN_TEST(test_hidden_suffix);

    // Length / flag kind variants
    RUN_TEST(test_array_prefixed_len_short_u16);
    RUN_TEST(test_string_prefixed_len_u16);

    // Deep nesting + path packing
    RUN_TEST(test_deep_nesting_grows_stack);

    // Structural validation
    RUN_TEST(test_structural_validation);

    // Error paths
    RUN_TEST(test_error_data_too_short);
    RUN_TEST(test_error_data_too_long);
    RUN_TEST(test_error_invalid_len_kind);
    RUN_TEST(test_error_invalid_flag_kind);
    RUN_TEST(test_error_short_u16_truncated);
    RUN_TEST(test_error_bytes_fixed_too_short);
    RUN_TEST(test_error_string_prefixed_value_too_short);
    RUN_TEST(test_error_array_prefixed_len_truncated);
    RUN_TEST(test_error_array_remainder_zero_progress);

    // Enum variant decoding
    RUN_TEST(test_enum_empty_payload);
    RUN_TEST(test_enum_raw_size_payload);
    RUN_TEST(test_enum_missing_variant_fails);
    RUN_TEST(test_enum_discriminator_out_of_range);
    RUN_TEST(test_enum_inline_struct_payload);
    RUN_TEST(test_enum_inline_nested_payload);
    RUN_TEST(test_enum_inline_option_payload);
    RUN_TEST(test_enum_inline_payload_overruns_data);

    // Out-of-space injection
    RUN_TEST(test_oom_at_each_alloc_site);
    RUN_TEST(test_oom_fixed_size_table);

    printf("passed\n");
    return 0;
}
