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

// Leaf-callback capture harness. Records each emitted leaf so the test can
// assert on walk output. `path` is scratch (valid only during the callback),
// so it is copied; `value` is borrowed from a buffer that outlives the walk,
// so the pointer is kept as-is. Bounds are sized for the test inputs only --
// this is test code, not the walker.
#define CAPTURE_MAX_LEAVES 32
#define CAPTURE_MAX_PATH   40
typedef struct {
    size_t count;
    uint8_t path[CAPTURE_MAX_LEAVES][CAPTURE_MAX_PATH];
    size_t path_size[CAPTURE_MAX_LEAVES];
    uint8_t kind[CAPTURE_MAX_LEAVES];
    const uint8_t *value[CAPTURE_MAX_LEAVES];
    size_t value_size[CAPTURE_MAX_LEAVES];
} capture_t;

static void capture_cb(const idl_leaf_t *leaf, void *ctx) {
    capture_t *cap = (capture_t *) ctx;
    assert(cap->count < CAPTURE_MAX_LEAVES);
    assert(leaf->path_size <= CAPTURE_MAX_PATH);
    size_t i = cap->count;
    if (leaf->path_size > 0) {
        memcpy(cap->path[i], leaf->path, leaf->path_size);
    }
    cap->path_size[i] = leaf->path_size;
    cap->kind[i] = leaf->kind;
    cap->value[i] = leaf->value;
    cap->value_size[i] = leaf->value_size;
    cap->count++;
}

// Run a complete walk against an in-memory pool + data, capturing every leaf.
// Returns the idl_walker_run() result code, or -1 if the pool fails to parse
// at provide time (parsing now happens in idl_walker_provide_pool). Asserts
// that the flow left no outstanding allocations behind.
static int run_walk(const uint8_t *pool,
                    size_t pool_size,
                    uint8_t root,
                    const uint8_t *data,
                    size_t data_size,
                    capture_t *cap) {
    idl_walker_t walker;
    idl_walker_init(&walker);
    if (idl_walker_provide_pool(&walker, pool, pool_size, root) != 0) {
        idl_walker_reset(&walker);
        assert(mock_mem_outstanding() == 0);
        return -1;
    }
    assert(idl_walker_provide_instruction_data(&walker, data, data_size) == 0);
    int rc = idl_walker_run(&walker, capture_cb, cap);
    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
    return rc;
}

// Assert that captured leaf `i` has the expected path, kind and value.
static void expect_leaf(const capture_t *cap,
                        size_t i,
                        const uint8_t *path,
                        size_t path_size,
                        uint8_t kind,
                        const uint8_t *value,
                        size_t value_size) {
    assert(i < cap->count);
    assert(cap->path_size[i] == path_size);
    assert(memcmp(cap->path[i], path, path_size) == 0);
    assert(cap->kind[i] == kind);
    assert(cap->value_size[i] == value_size);
    if (value_size > 0) {
        assert(memcmp(cap->value[i], value, value_size) == 0);
    }
}

// =============================================================================
// Input-forwarding / lifecycle preconditions
// =============================================================================

void test_init_empty() {
    idl_walker_t walker;
    setup(&walker);

    assert(walker.entries == NULL);
    assert(walker.entry_count == 0);
    assert(walker.root_index == 0);
    assert(walker.pool_ready == false);
    assert(walker.data == NULL);
    assert(walker.data_size == 0);
    assert(walker.data_ready == false);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_provide_pool() {
    idl_walker_t walker;
    setup(&walker);

    const uint8_t pool[] = {0x01, IDL_KIND_U64};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);

    assert(walker.pool_ready == true);
    assert(walker.entry_count == 1);
    assert(walker.root_index == 0);
    // Parsing the pool owns one allocation (the parsed entry array).
    assert(mock_mem_outstanding() == 1);

    idl_walker_reset(&walker);
    assert(walker.pool_ready == false);
    assert(walker.entries == NULL);
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

    const uint8_t pool_a[] = {0x01, IDL_KIND_U8};
    const uint8_t pool_b[] = {0x02, IDL_KIND_U16, IDL_KIND_U32};
    assert(idl_walker_provide_pool(&walker, pool_a, sizeof(pool_a), 0) == 0);
    assert(walker.entry_count == 1);
    assert(mock_mem_outstanding() == 1);

    // Re-providing frees the previous parsed pool and replaces it; no leak.
    assert(idl_walker_provide_pool(&walker, pool_b, sizeof(pool_b), 1) == 0);
    assert(walker.entry_count == 2);
    assert(walker.root_index == 1);
    assert(mock_mem_outstanding() == 1);

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

void test_run_requires_both_inputs() {
    idl_walker_t walker;
    setup(&walker);

    capture_t cap = {0};

    // No inputs at all.
    assert(idl_walker_run(&walker, capture_cb, &cap) == -1);

    // Pool only.
    const uint8_t pool[] = {0x01, IDL_KIND_U8};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_run(&walker, capture_cb, &cap) == -1);

    // Pool + data: now the walk runs.
    const uint8_t data[] = {0x42};
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
    assert(idl_walker_run(&walker, capture_cb, &cap) == 0);
    assert(cap.count == 1);

    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_null_walker_is_safe() {
    // None of these must crash on a NULL context.
    idl_walker_init(NULL);
    assert(idl_walker_provide_pool(NULL, NULL, 0, 0) == -1);
    assert(idl_walker_provide_instruction_data(NULL, NULL, 0) == -1);
    assert(idl_walker_run(NULL, NULL, NULL) == -1);
    idl_walker_reset(NULL);
}

void test_reset_is_idempotent() {
    idl_walker_t walker;
    setup(&walker);

    idl_walker_reset(&walker);
    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);

    const uint8_t pool[] = {0x01, IDL_KIND_U16};
    const uint8_t data[] = {0x01, 0x02};
    assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
    assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
    capture_t cap = {0};
    assert(idl_walker_run(&walker, capture_cb, &cap) == 0);
    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
    assert(walker.pool_ready == false);
    assert(walker.data_ready == false);
}

// =============================================================================
// Primitive leaves
// =============================================================================

void test_primitive_root_widths() {
    const uint8_t data[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01};
    const uint8_t no_step[] = {0x00};  // root leaf: step_count 0

    struct {
        uint8_t kind;
        size_t width;
    } cases[] = {
        {IDL_KIND_U8, 1},   {IDL_KIND_I8, 1},   {IDL_KIND_BOOL_U8, 1},
        {IDL_KIND_U16, 2},  {IDL_KIND_I16, 2},  {IDL_KIND_BOOL_U16, 2},
        {IDL_KIND_U32, 4},  {IDL_KIND_I32, 4},  {IDL_KIND_BOOL_U32, 4},
        {IDL_KIND_F32, 4},  {IDL_KIND_U64, 8},  {IDL_KIND_I64, 8},
        {IDL_KIND_F64, 8},  {IDL_KIND_U128, 16}, {IDL_KIND_I128, 16},
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        uint8_t pool[2] = {0x01, cases[k].kind};
        capture_t cap = {0};
        assert(run_walk(pool, sizeof(pool), 0, data, cases[k].width, &cap) == 0);
        assert(cap.count == 1);
        expect_leaf(&cap, 0, no_step, sizeof(no_step), cases[k].kind, data, cases[k].width);
    }
}

void test_pubkey_leaf() {
    uint8_t data[32];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t) (i + 1);
    }
    const uint8_t pool[] = {0x01, IDL_KIND_PUBKEY_32};
    const uint8_t no_step[] = {0x00};

    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == 0);
    assert(cap.count == 1);
    expect_leaf(&cap, 0, no_step, sizeof(no_step), IDL_KIND_PUBKEY_32, data, sizeof(data));
}

void test_short_u16_varints() {
    const uint8_t pool[] = {0x01, IDL_KIND_SHORT_U16};
    const uint8_t no_step[] = {0x00};

    // 1-byte varint (value < 0x80).
    {
        const uint8_t data[] = {0x7f};
        capture_t cap = {0};
        assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == 0);
        expect_leaf(&cap, 0, no_step, sizeof(no_step), IDL_KIND_SHORT_U16, data, 1);
    }
    // 2-byte varint (value 128).
    {
        const uint8_t data[] = {0x80, 0x01};
        capture_t cap = {0};
        assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == 0);
        expect_leaf(&cap, 0, no_step, sizeof(no_step), IDL_KIND_SHORT_U16, data, 2);
    }
    // 3-byte varint (value 0x4000).
    {
        const uint8_t data[] = {0x80, 0x80, 0x01};
        capture_t cap = {0};
        assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == 0);
        expect_leaf(&cap, 0, no_step, sizeof(no_step), IDL_KIND_SHORT_U16, data, 3);
    }
}

// =============================================================================
// Byte / string leaves
// =============================================================================

void test_bytes_fixed_leaf() {
    // BYTES_FIXED(3)
    const uint8_t pool[] = {0x01, IDL_KIND_BYTES_FIXED, 0x00, 0x03};
    const uint8_t data[] = {0xaa, 0xbb, 0xcc};
    const uint8_t no_step[] = {0x00};

    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == 0);
    expect_leaf(&cap, 0, no_step, sizeof(no_step), IDL_KIND_BYTES_FIXED, data, 3);
}

void test_string_fixed_leaf() {
    // STRING_FIXED(4, utf8)
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_FIXED, 0x00, 0x04, IDL_ENCODING_UTF8};
    const uint8_t data[] = {'a', 'b', 'c', 'd'};
    const uint8_t no_step[] = {0x00};

    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == 0);
    expect_leaf(&cap, 0, no_step, sizeof(no_step), IDL_KIND_STRING_FIXED, data, 4);
}

void test_string_prefixed_leaf() {
    // STRING_PREFIXED(len_kind=U8, utf8)
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_PREFIXED, IDL_KIND_U8, IDL_ENCODING_UTF8};
    const uint8_t data[] = {0x03, 'x', 'y', 'z'};
    const uint8_t expected_value[] = {'x', 'y', 'z'};
    const uint8_t no_step[] = {0x00};

    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == 0);
    // The length prefix is consumed but not part of the emitted value.
    expect_leaf(&cap, 0, no_step, sizeof(no_step), IDL_KIND_STRING_PREFIXED, expected_value, 3);
}

void test_bytes_remainder_leaf() {
    // struct { u8, bytes_remainder }
    const uint8_t pool[] = {
        IDL_KIND_U8,                  // entry 0
        IDL_KIND_BYTES_REMAINDER,     // entry 1
        IDL_KIND_STRUCT, 0x02, 0, 1,  // entry 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x01, 0xde, 0xad, 0xbe, 0xef};
    const uint8_t path0[] = {0x01, 0x00};
    const uint8_t path1[] = {0x01, 0x01};
    const uint8_t tail[] = {0xde, 0xad, 0xbe, 0xef};

    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 2);
    expect_leaf(&cap, 0, path0, sizeof(path0), IDL_KIND_U8, data, 1);
    expect_leaf(&cap, 1, path1, sizeof(path1), IDL_KIND_BYTES_REMAINDER, tail, sizeof(tail));
}

// =============================================================================
// Aggregates
// =============================================================================

void test_struct_two_fields() {
    // struct { u8, u32 }
    const uint8_t pool[] = {
        IDL_KIND_U8,                  // 0
        IDL_KIND_U32,                 // 1
        IDL_KIND_STRUCT, 0x02, 0, 1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xab, 0x11, 0x22, 0x33, 0x44};
    const uint8_t path0[] = {0x01, 0x00};
    const uint8_t path1[] = {0x01, 0x01};

    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 2);
    expect_leaf(&cap, 0, path0, sizeof(path0), IDL_KIND_U8, &data[0], 1);
    expect_leaf(&cap, 1, path1, sizeof(path1), IDL_KIND_U32, &data[1], 4);
}

void test_struct_reused_ref() {
    // struct { u8, u8 } where both fields point at the same pool entry.
    const uint8_t pool[] = {
        IDL_KIND_U8,                  // 0
        IDL_KIND_STRUCT, 0x02, 0, 0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xaa, 0xbb};
    const uint8_t path0[] = {0x01, 0x00};
    const uint8_t path1[] = {0x01, 0x01};

    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
    assert(cap.count == 2);
    expect_leaf(&cap, 0, path0, sizeof(path0), IDL_KIND_U8, &data[0], 1);
    expect_leaf(&cap, 1, path1, sizeof(path1), IDL_KIND_U8, &data[1], 1);
}

void test_tuple() {
    // tuple ( u16, u8 )
    const uint8_t pool[] = {
        IDL_KIND_U16,                // 0
        IDL_KIND_U8,                 // 1
        IDL_KIND_TUPLE, 0x02, 0, 1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x34, 0x12, 0xff};
    const uint8_t path0[] = {0x01, 0x00};
    const uint8_t path1[] = {0x01, 0x01};

    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 2);
    expect_leaf(&cap, 0, path0, sizeof(path0), IDL_KIND_U16, &data[0], 2);
    expect_leaf(&cap, 1, path1, sizeof(path1), IDL_KIND_U8, &data[2], 1);
}

void test_array_fixed() {
    // array_fixed(3) of u16, wrapped in a struct so the path has two steps.
    const uint8_t pool[] = {
        IDL_KIND_U16,                          // 0
        IDL_KIND_ARRAY_FIXED, 0x00, 0x03, 0,   // 1
        IDL_KIND_STRUCT, 0x01, 1,              // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x01, 0x00, 0x02, 0x00, 0x03, 0x00};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 3);
    // path = { step_count=2, (STRUCT,0)=u8 0x00, (ARRAY_FIXED,idx)=u16 BE }
    for (uint8_t i = 0; i < 3; i++) {
        const uint8_t path[] = {0x02, 0x00, 0x00, i};
        expect_leaf(&cap, i, path, sizeof(path), IDL_KIND_U16, &data[i * 2], 2);
    }
}

void test_array_prefixed() {
    // array_prefixed(len_kind=U8) of u8 at the root.
    const uint8_t pool[] = {
        IDL_KIND_U8,                            // 0
        IDL_KIND_ARRAY_PREFIXED, IDL_KIND_U8, 0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x02, 0xaa, 0xbb};  // count 2, then 2 elements
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
    assert(cap.count == 2);
    const uint8_t path0[] = {0x01, 0x00, 0x00};
    const uint8_t path1[] = {0x01, 0x00, 0x01};
    expect_leaf(&cap, 0, path0, sizeof(path0), IDL_KIND_U8, &data[1], 1);
    expect_leaf(&cap, 1, path1, sizeof(path1), IDL_KIND_U8, &data[2], 1);
}

void test_array_remainder() {
    // array_remainder of u16 at the root: consume the whole buffer.
    const uint8_t pool[] = {
        IDL_KIND_U16,                  // 0
        IDL_KIND_ARRAY_REMAINDER, 0,   // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x01, 0x00, 0x02, 0x00, 0x03, 0x00};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
    assert(cap.count == 3);
    for (uint8_t i = 0; i < 3; i++) {
        const uint8_t path[] = {0x01, 0x00, i};
        expect_leaf(&cap, i, path, sizeof(path), IDL_KIND_U16, &data[i * 2], 2);
    }
}

// =============================================================================
// Options
// =============================================================================

void test_option_dynamic() {
    // option_dynamic(flag=U8) of u8 at the root.
    const uint8_t pool[] = {
        IDL_KIND_U8,                              // 0
        IDL_KIND_OPTION_DYNAMIC, IDL_KIND_U8, 0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0, nothing emitted, the flag byte is the whole buffer.
    {
        const uint8_t data[] = {0x00};
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
        assert(cap.count == 0);
    }
    // Present: flag 1, then the inner u8.
    {
        const uint8_t data[] = {0x01, 0xcd};
        const uint8_t path[] = {0x01, 0x00};
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
        assert(cap.count == 1);
        expect_leaf(&cap, 0, path, sizeof(path), IDL_KIND_U8, &data[1], 1);
    }
}

void test_option_fixed() {
    // option_fixed(flag=U8) of u32 at the root. When absent, the 4 inner bytes
    // are still present in the buffer and must be skipped.
    const uint8_t pool[] = {
        IDL_KIND_U32,                            // 0
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 0,   // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0 + 4 skipped bytes, nothing emitted.
    {
        const uint8_t data[] = {0x00, 0x11, 0x22, 0x33, 0x44};
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
        assert(cap.count == 0);
    }
    // Present: flag 1, then the inner u32.
    {
        const uint8_t data[] = {0x01, 0xaa, 0xbb, 0xcc, 0xdd};
        const uint8_t path[] = {0x01, 0x00};
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
        assert(cap.count == 1);
        expect_leaf(&cap, 0, path, sizeof(path), IDL_KIND_U32, &data[1], 4);
    }
}

void test_option_zeroable() {
    // option_zeroable of pubkey, sentinel = 32 zero bytes.
    uint8_t pool[1 + 1 + 3 + 32];
    size_t n = 0;
    pool[n++] = 2;                          // count
    pool[n++] = IDL_KIND_PUBKEY_32;         // entry 0
    pool[n++] = IDL_KIND_OPTION_ZEROABLE;   // entry 1
    pool[n++] = 0;                          // inner_ref
    pool[n++] = 32;                         // sentinel_len
    for (size_t i = 0; i < 32; i++) {
        pool[n++] = 0x00;                   // sentinel bytes
    }
    assert(n == sizeof(pool));

    // Sentinel match (all zero): nothing emitted, 32 bytes consumed.
    {
        uint8_t data[32] = {0};
        capture_t cap = {0};
        assert(run_walk(pool, sizeof(pool), 1, data, sizeof(data), &cap) == 0);
        assert(cap.count == 0);
    }
    // Non-sentinel: the inner pubkey is emitted from the same 32 bytes.
    {
        uint8_t data[32];
        for (size_t i = 0; i < 32; i++) {
            data[i] = (uint8_t) (i + 1);
        }
        const uint8_t path[] = {0x01, 0x00};
        capture_t cap = {0};
        assert(run_walk(pool, sizeof(pool), 1, data, sizeof(data), &cap) == 0);
        assert(cap.count == 1);
        expect_leaf(&cap, 0, path, sizeof(path), IDL_KIND_PUBKEY_32, data, 32);
    }
}

void test_option_remainder() {
    // option_remainder of u8 at the root.
    const uint8_t pool[] = {
        IDL_KIND_U8,                   // 0
        IDL_KIND_OPTION_REMAINDER, 0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Empty buffer: option absent, nothing emitted.
    {
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, NULL, 0, &cap) == 0);
        assert(cap.count == 0);
    }
    // Non-empty: option present.
    {
        const uint8_t data[] = {0x7e};
        const uint8_t path[] = {0x01, 0x00};
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
        assert(cap.count == 1);
        expect_leaf(&cap, 0, path, sizeof(path), IDL_KIND_U8, data, 1);
    }
}

// =============================================================================
// Hidden wrappers
// =============================================================================

void test_hidden_prefix() {
    // hidden_prefix(skip=u32, inner=u8): skip walked first (step 1), then inner
    // (step 0). Serialization order is skip-then-inner.
    const uint8_t pool[] = {
        IDL_KIND_U32,                         // 0 (skip)
        IDL_KIND_U8,                          // 1 (inner)
        IDL_KIND_HIDDEN_PREFIX, 0, 1,         // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0xab};
    const uint8_t path_skip[] = {0x01, 0x01};
    const uint8_t path_inner[] = {0x01, 0x00};

    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 2);
    expect_leaf(&cap, 0, path_skip, sizeof(path_skip), IDL_KIND_U32, &data[0], 4);
    expect_leaf(&cap, 1, path_inner, sizeof(path_inner), IDL_KIND_U8, &data[4], 1);
}

void test_hidden_suffix() {
    // hidden_suffix(skip=u32, inner=u8): inner walked first (step 0), then skip
    // (step 1). Serialization order is inner-then-skip.
    const uint8_t pool[] = {
        IDL_KIND_U32,                         // 0 (skip)
        IDL_KIND_U8,                          // 1 (inner)
        IDL_KIND_HIDDEN_SUFFIX, 0, 1,         // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xab, 0x11, 0x22, 0x33, 0x44};
    const uint8_t path_inner[] = {0x01, 0x00};
    const uint8_t path_skip[] = {0x01, 0x01};

    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 2);
    expect_leaf(&cap, 0, path_inner, sizeof(path_inner), IDL_KIND_U8, &data[0], 1);
    expect_leaf(&cap, 1, path_skip, sizeof(path_skip), IDL_KIND_U32, &data[1], 4);
}

// =============================================================================
// Deep nesting (stack growth) and path packing
// =============================================================================

void test_deep_nesting_grows_stack() {
    // A chain of `depth` single-field structs wrapping a u8 leaf, forcing the
    // frame stack to grow past its initial capacity and producing a long path.
    const uint8_t depth = 12;
    uint8_t pool[64];
    size_t n = 0;
    pool[n++] = depth + 1;       // count
    pool[n++] = IDL_KIND_U8;     // entry 0 (leaf)
    for (uint8_t i = 1; i <= depth; i++) {
        pool[n++] = IDL_KIND_STRUCT;
        pool[n++] = 1;
        pool[n++] = i - 1;       // wraps the previous entry
    }

    const uint8_t data[] = {0x5a};
    capture_t cap = {0};
    assert(run_walk(pool, n, depth, data, sizeof(data), &cap) == 0);
    assert(cap.count == 1);

    // path = { step_count=depth, depth zero bytes (each STRUCT step is 0) }
    uint8_t expected_path[1 + 12] = {0};
    expected_path[0] = depth;
    expect_leaf(&cap, 0, expected_path, 1 + depth, IDL_KIND_U8, data, 1);
}

// =============================================================================
// NULL callback
// =============================================================================

void test_null_callback_validates() {
    const uint8_t pool[] = {0x01, IDL_KIND_U32};

    // A NULL callback still walks and validates the cursor: exact consume.
    {
        const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
        idl_walker_t walker;
        idl_walker_init(&walker);
        assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
        assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
        assert(idl_walker_run(&walker, NULL, NULL) == 0);
        idl_walker_reset(&walker);
        assert(mock_mem_outstanding() == 0);
    }
    // A NULL callback still returns -1 on a length mismatch.
    {
        const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};  // one byte too many
        idl_walker_t walker;
        idl_walker_init(&walker);
        assert(idl_walker_provide_pool(&walker, pool, sizeof(pool), 0) == 0);
        assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
        assert(idl_walker_run(&walker, NULL, NULL) == -1);
        idl_walker_reset(&walker);
        assert(mock_mem_outstanding() == 0);
    }
}

// =============================================================================
// Error paths
// =============================================================================

void test_error_data_too_short() {
    // struct { u8, u32 } but only 3 bytes: the u32 read runs past the end.
    const uint8_t pool[] = {
        IDL_KIND_U8,                  // 0
        IDL_KIND_U32,                 // 1
        IDL_KIND_STRUCT, 0x02, 0, 1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xab, 0x11, 0x22};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == -1);
}

void test_error_data_too_long() {
    // Root u8 but two data bytes: the cursor does not land on the end.
    const uint8_t pool[] = {0x01, IDL_KIND_U8};
    const uint8_t data[] = {0xaa, 0xbb};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_root_index_out_of_range() {
    const uint8_t pool[] = {0x01, IDL_KIND_U8};
    const uint8_t data[] = {0xaa};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 5, data, sizeof(data), &cap) == -1);
}

void test_error_ref_out_of_range() {
    // struct field references a non-existent pool entry.
    const uint8_t pool[] = {0x01, IDL_KIND_STRUCT, 0x01, 0x05};
    const uint8_t data[] = {0xaa};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_unknown_kind() {
    const uint8_t pool[] = {0x01, 0xFF};
    const uint8_t data[] = {0xaa};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_trailing_pool_bytes() {
    // count=1 with one u8 entry, plus a stray trailing byte.
    const uint8_t pool[] = {0x01, IDL_KIND_U8, 0x99};
    const uint8_t data[] = {0xaa};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_truncated_entry() {
    // count=1 announces an entry but the kind byte is missing.
    const uint8_t pool[] = {0x01};
    const uint8_t data[] = {0xaa};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_enum_unsupported() {
    // ENUM(disc=U8, total=1, id="") is unsupported and aborts the walk.
    const uint8_t pool[] = {0x01, IDL_KIND_ENUM, IDL_KIND_U8, 0x00, 0x01, 0x00};
    const uint8_t data[] = {0x00};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

// =============================================================================
// Out-of-space injection
// =============================================================================

void test_oom_at_each_alloc_site() {
    // struct { u8, u32 } drives three allocations: the parsed-pool array (at
    // provide time), the frame stack, and the first leaf's scratch path.
    // Failing any one must abort the flow and leave nothing allocated.
    const uint8_t pool[] = {
        IDL_KIND_U8,                  // 0
        IDL_KIND_U32,                 // 1
        IDL_KIND_STRUCT, 0x02, 0, 1,  // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));
    const uint8_t data[] = {0xab, 0x11, 0x22, 0x33, 0x44};

    for (int fail_at = 0; fail_at < 3; fail_at++) {
        idl_walker_t walker;
        idl_walker_init(&walker);

        mock_mem_fail_after(fail_at);
        int rc;
        if (idl_walker_provide_pool(&walker, pool_buf, sizeof(pool_buf), 2) != 0) {
            rc = -1;
        } else {
            assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
            capture_t cap = {0};
            rc = idl_walker_run(&walker, capture_cb, &cap);
        }
        assert(rc == -1);

        idl_walker_reset(&walker);
        assert(mock_mem_outstanding() == 0);
        mock_mem_fail_after(-1);
    }
}

void test_oom_fixed_size_table() {
    // option_fixed of struct{u8,u32} forces the fixed-size table to be built.
    // Allocation order: parsed pool (at provide time), fixed-size table, frame
    // stack, scratch path. Failing any one must abort the flow with no leak.
    const uint8_t pool[] = {
        IDL_KIND_U8,                             // 0
        IDL_KIND_U32,                            // 1
        IDL_KIND_STRUCT, 0x02, 0, 1,             // 2
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 2,   // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));
    // flag=1 (present): emits the struct's two leaves.
    const uint8_t data[] = {0x01, 0xab, 0x11, 0x22, 0x33, 0x44};

    for (int fail_at = 0; fail_at < 4; fail_at++) {
        idl_walker_t walker;
        idl_walker_init(&walker);

        mock_mem_fail_after(fail_at);
        int rc;
        if (idl_walker_provide_pool(&walker, pool_buf, sizeof(pool_buf), 3) != 0) {
            rc = -1;
        } else {
            assert(idl_walker_provide_instruction_data(&walker, data, sizeof(data)) == 0);
            capture_t cap = {0};
            rc = idl_walker_run(&walker, capture_cb, &cap);
        }
        assert(rc == -1);

        idl_walker_reset(&walker);
        assert(mock_mem_outstanding() == 0);
        mock_mem_fail_after(-1);
    }
}

// =============================================================================
// OPTION_FIXED with non-primitive inner (static-size table)
// =============================================================================

void test_option_fixed_struct_inner() {
    // option_fixed of struct{u8,u32}. When absent the 5 inner bytes are
    // statically sized and skipped; when present both fields are emitted.
    const uint8_t pool[] = {
        IDL_KIND_U8,                             // 0
        IDL_KIND_U32,                            // 1
        IDL_KIND_STRUCT, 0x02, 0, 1,             // 2
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 2,   // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0 + 5 statically-skipped bytes, nothing emitted.
    {
        const uint8_t data[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &cap) == 0);
        assert(cap.count == 0);
    }
    // Present: flag 1, then the struct.
    {
        const uint8_t data[] = {0x01, 0xab, 0x11, 0x22, 0x33, 0x44};
        const uint8_t path0[] = {0x02, 0x00, 0x00};
        const uint8_t path1[] = {0x02, 0x00, 0x01};
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &cap) == 0);
        assert(cap.count == 2);
        expect_leaf(&cap, 0, path0, sizeof(path0), IDL_KIND_U8, &data[1], 1);
        expect_leaf(&cap, 1, path1, sizeof(path1), IDL_KIND_U32, &data[2], 4);
    }
}

void test_option_fixed_array_inner() {
    // option_fixed of array_fixed(2) of u16: absent skips 2*2 = 4 bytes.
    const uint8_t pool[] = {
        IDL_KIND_U16,                            // 0
        IDL_KIND_ARRAY_FIXED, 0x00, 0x02, 0,     // 1
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 1,   // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 0);
}

void test_option_fixed_zeroable_inner() {
    // option_fixed of option_zeroable(pubkey, sentinel=32 zeros): the zeroable
    // is statically sized to the inner width (32), so an absent outer skips 32.
    uint8_t pool[40];
    size_t n = 0;
    pool[n++] = 3;                          // count
    pool[n++] = IDL_KIND_PUBKEY_32;         // entry 0
    pool[n++] = IDL_KIND_OPTION_ZEROABLE;   // entry 1
    pool[n++] = 0;                          // inner_ref
    pool[n++] = 32;                         // sentinel_len
    for (size_t i = 0; i < 32; i++) {
        pool[n++] = 0x00;
    }
    pool[n++] = IDL_KIND_OPTION_FIXED;      // entry 2
    pool[n++] = IDL_KIND_U8;                // flag kind
    pool[n++] = 1;                          // inner_ref -> entry 1
    assert(n == sizeof(pool));

    // Outer absent: flag 0 + 32 statically-skipped bytes.
    uint8_t data[1 + 32] = {0};
    data[0] = 0x00;
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 0);
}

void test_option_fixed_hidden_inner() {
    // option_fixed of hidden_suffix(skip=u16, inner=u8): static size 2+1 = 3.
    const uint8_t pool[] = {
        IDL_KIND_U16,                            // 0 (skip)
        IDL_KIND_U8,                             // 1 (inner)
        IDL_KIND_HIDDEN_SUFFIX, 0, 1,            // 2
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 2,   // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0 + 3 statically-skipped bytes.
    const uint8_t data[] = {0x00, 0x11, 0x22, 0x33};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &cap) == 0);
    assert(cap.count == 0);
}

void test_option_fixed_bytes_inner() {
    // option_fixed of bytes_fixed(3): absent skips the 3 inner bytes.
    const uint8_t pool[] = {
        IDL_KIND_BYTES_FIXED, 0x00, 0x03,        // 0
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 0,   // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0 + 3 statically-skipped bytes.
    {
        const uint8_t data[] = {0x00, 0x11, 0x22, 0x33};
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
        assert(cap.count == 0);
    }
    // Absent but too few bytes to skip: the walk returns -1.
    {
        const uint8_t data[] = {0x00, 0x11};  // need 3 more, only 2
        capture_t cap = {0};
        assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == -1);
    }
}

void test_option_fixed_array_variable_child_fails() {
    // option_fixed of array_fixed(2) of string_prefixed: the array inherits the
    // variable size of its element, so an absent outer cannot be skipped.
    const uint8_t pool[] = {
        IDL_KIND_STRING_PREFIXED, IDL_KIND_U8, IDL_ENCODING_UTF8,  // 0
        IDL_KIND_ARRAY_FIXED, 0x00, 0x02, 0,                       // 1
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 1,                     // 2
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0x11, 0x22};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == -1);
}

void test_option_fixed_hidden_variable_child_fails() {
    // option_fixed of hidden_prefix(skip=string_prefixed, inner=u8): the hidden
    // wrapper inherits the skip's variable size, so an absent outer fails.
    const uint8_t pool[] = {
        IDL_KIND_STRING_PREFIXED, IDL_KIND_U8, IDL_ENCODING_UTF8,  // 0 (skip)
        IDL_KIND_U8,                                               // 1 (inner)
        IDL_KIND_HIDDEN_PREFIX, 0, 1,                              // 2
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 2,                     // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0x11, 0x22};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &cap) == -1);
}

void test_option_fixed_forward_reference() {
    // The aggregate precedes its fields in pool index order, so the static-size
    // fixpoint cannot resolve it on the first pass and must iterate. struct
    // {u8,u32} sits at index 0, its fields at 1 and 2, the option at 3.
    const uint8_t pool[] = {
        IDL_KIND_STRUCT, 0x02, 1, 2,             // 0 (refers forward)
        IDL_KIND_U8,                             // 1
        IDL_KIND_U32,                            // 2
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 0,   // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent: flag 0 + 5 statically-skipped bytes (resolved across passes).
    const uint8_t data[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &cap) == 0);
    assert(cap.count == 0);
}

void test_option_zeroable_empty_sentinel() {
    // A zero-length sentinel always "matches": the option is treated as absent
    // and consumes nothing.
    const uint8_t pool[] = {
        IDL_KIND_U8,                          // 0
        IDL_KIND_OPTION_ZEROABLE, 0, 0,       // 1: inner_ref 0, sentinel_len 0
        IDL_KIND_STRUCT, 0x02, 1, 0,          // 2: option then a trailing u8
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 3;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Only the trailing u8 is present; the zeroable consumed nothing.
    const uint8_t data[] = {0x7c};
    const uint8_t path[] = {0x01, 0x01};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 2, data, sizeof(data), &cap) == 0);
    assert(cap.count == 1);
    expect_leaf(&cap, 0, path, sizeof(path), IDL_KIND_U8, &data[0], 1);
}

void test_option_zeroable_sentinel_longer_than_data() {
    // The 32-byte sentinel cannot fit in the remaining data, so the option is
    // treated as present and the inner pubkey read runs past the end.
    uint8_t pool[37];
    size_t n = 0;
    pool[n++] = 2;                          // count
    pool[n++] = IDL_KIND_PUBKEY_32;         // entry 0
    pool[n++] = IDL_KIND_OPTION_ZEROABLE;   // entry 1
    pool[n++] = 0;                          // inner_ref
    pool[n++] = 32;                         // sentinel_len
    for (size_t i = 0; i < 32; i++) {
        pool[n++] = 0x00;
    }
    assert(n == sizeof(pool));

    const uint8_t data[] = {0x01, 0x02, 0x03};  // far fewer than 32 bytes
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 1, data, sizeof(data), &cap) == -1);
}

void test_zero_size_pool_rejected() {
    // A pool of size 0 has no count byte: parsing at provide time returns -1.
    idl_walker_t walker;
    setup(&walker);
    const uint8_t dummy = 0x00;
    assert(idl_walker_provide_pool(&walker, &dummy, 0, 0) == -1);
    assert(walker.pool_ready == false);
    idl_walker_reset(&walker);
    assert(mock_mem_outstanding() == 0);
}

void test_option_fixed_variable_inner_absent_fails() {
    // option_fixed of string_prefixed: a variable-size inner has no static
    // size, so an absent outer cannot be skipped and the walk returns -1.
    const uint8_t pool[] = {
        IDL_KIND_STRING_PREFIXED, IDL_KIND_U8, IDL_ENCODING_UTF8,  // 0
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 0,                     // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // Absent flag with trailing bytes: inner is variable -> -1.
    const uint8_t data[] = {0x00, 0x11, 0x22};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == -1);

    // Present is fine: flag 1, len 2, then 2 string bytes.
    const uint8_t data_present[] = {0x01, 0x02, 'h', 'i'};
    const uint8_t value[] = {'h', 'i'};
    const uint8_t path[] = {0x01, 0x00};
    capture_t cap2 = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data_present, sizeof(data_present), &cap2) == 0);
    assert(cap2.count == 1);
    expect_leaf(&cap2, 0, path, sizeof(path), IDL_KIND_STRING_PREFIXED, value, 2);
}

void test_option_fixed_struct_variable_child_fails() {
    // option_fixed of struct{u8, string_prefixed}: the struct inherits the
    // variable size of its string field, so an absent outer cannot be skipped.
    const uint8_t pool[] = {
        IDL_KIND_U8,                                               // 0
        IDL_KIND_STRING_PREFIXED, IDL_KIND_U8, IDL_ENCODING_UTF8,  // 1
        IDL_KIND_STRUCT, 0x02, 0, 1,                               // 2
        IDL_KIND_OPTION_FIXED, IDL_KIND_U8, 2,                     // 3
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 4;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x00, 0x11, 0x22};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 3, data, sizeof(data), &cap) == -1);
}

// =============================================================================
// Length / flag kind variants
// =============================================================================

void test_array_prefixed_len_short_u16() {
    // array_prefixed(len_kind=SHORT_U16) of u8 at the root.
    const uint8_t pool[] = {
        IDL_KIND_U8,                                    // 0
        IDL_KIND_ARRAY_PREFIXED, IDL_KIND_SHORT_U16, 0, // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    // ShortU16 length 2 (single-byte varint), then two elements.
    const uint8_t data[] = {0x02, 0xaa, 0xbb};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == 0);
    assert(cap.count == 2);
    const uint8_t path0[] = {0x01, 0x00, 0x00};
    const uint8_t path1[] = {0x01, 0x00, 0x01};
    expect_leaf(&cap, 0, path0, sizeof(path0), IDL_KIND_U8, &data[1], 1);
    expect_leaf(&cap, 1, path1, sizeof(path1), IDL_KIND_U8, &data[2], 1);
}

void test_string_prefixed_len_u16() {
    // string_prefixed(len_kind=U16) reads a 2-byte little-endian length.
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_PREFIXED, IDL_KIND_U16, IDL_ENCODING_UTF8};
    const uint8_t data[] = {0x03, 0x00, 'a', 'b', 'c'};
    const uint8_t value[] = {'a', 'b', 'c'};
    const uint8_t no_step[] = {0x00};

    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == 0);
    expect_leaf(&cap, 0, no_step, sizeof(no_step), IDL_KIND_STRING_PREFIXED, value, 3);
}

void test_error_invalid_len_kind() {
    // string_prefixed with a length kind wider than 8 bytes is unreadable.
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_PREFIXED, IDL_KIND_U128, IDL_ENCODING_UTF8};
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_invalid_flag_kind() {
    // option_dynamic with a non-integer flag kind cannot be read.
    const uint8_t pool[] = {
        IDL_KIND_U8,                                       // 0
        IDL_KIND_OPTION_DYNAMIC, IDL_KIND_PUBKEY_32, 0,    // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0x01, 0x02};
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == -1);
}

// =============================================================================
// Read-past-end on individual leaf kinds
// =============================================================================

void test_error_short_u16_truncated() {
    // Continuation bit set on the final byte: the varint runs off the end.
    const uint8_t pool[] = {0x01, IDL_KIND_SHORT_U16};
    const uint8_t data[] = {0x80};  // expects another byte
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_bytes_fixed_too_short() {
    const uint8_t pool[] = {0x01, IDL_KIND_BYTES_FIXED, 0x00, 0x04};
    const uint8_t data[] = {0xaa, 0xbb};  // only 2 of 4 bytes
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_string_prefixed_value_too_short() {
    // Length prefix says 4 but only 2 value bytes follow.
    const uint8_t pool[] = {0x01, IDL_KIND_STRING_PREFIXED, IDL_KIND_U8, IDL_ENCODING_UTF8};
    const uint8_t data[] = {0x04, 'a', 'b'};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

void test_error_array_prefixed_len_truncated() {
    // The length prefix itself cannot be read from empty data.
    const uint8_t pool[] = {
        IDL_KIND_U8,                              // 0
        IDL_KIND_ARRAY_PREFIXED, IDL_KIND_U8, 0,  // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, NULL, 0, &cap) == -1);
}

void test_error_array_remainder_zero_progress() {
    // array_remainder of an empty struct: each element consumes zero bytes, so
    // the progress guard must abort the walk instead of looping forever.
    const uint8_t pool[] = {
        IDL_KIND_STRUCT, 0x00,         // 0: empty struct
        IDL_KIND_ARRAY_REMAINDER, 0,   // 1
    };
    uint8_t pool_buf[1 + sizeof(pool)];
    pool_buf[0] = 2;
    memcpy(pool_buf + 1, pool, sizeof(pool));

    const uint8_t data[] = {0xff};  // non-empty -> at least one element
    capture_t cap = {0};
    assert(run_walk(pool_buf, sizeof(pool_buf), 1, data, sizeof(data), &cap) == -1);
}

// =============================================================================
// parse_pool per-kind truncation
// =============================================================================

void test_error_pool_truncated_per_kind() {
    // Each pool truncates a single entry's inline arguments; parse_pool must
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
        const uint8_t data[] = {0x00};
        capture_t cap = {0};
        int rc = run_walk(cases[i].pool, cases[i].size, 0, data, sizeof(data), &cap);
        if (rc != -1) {
            printf("FAIL: truncated pool '%s' was not rejected\n", cases[i].name);
        }
        assert(rc == -1);
    }
}

void test_empty_pool_rejected() {
    // count = 0 leaves no root entry to walk; root_index 0 is out of range.
    const uint8_t pool[] = {0x00};
    const uint8_t data[] = {0x00};
    capture_t cap = {0};
    assert(run_walk(pool, sizeof(pool), 0, data, sizeof(data), &cap) == -1);
}

int main() {
    // Lifecycle / preconditions
    RUN_TEST(test_init_empty);
    RUN_TEST(test_provide_pool);
    RUN_TEST(test_provide_instruction_data);
    RUN_TEST(test_provide_pool_replaces_previous);
    RUN_TEST(test_provide_pool_null_with_size_rejected);
    RUN_TEST(test_run_requires_both_inputs);
    RUN_TEST(test_null_walker_is_safe);
    RUN_TEST(test_reset_is_idempotent);

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

    // NULL callback
    RUN_TEST(test_null_callback_validates);

    // Error paths
    RUN_TEST(test_error_data_too_short);
    RUN_TEST(test_error_data_too_long);
    RUN_TEST(test_error_root_index_out_of_range);
    RUN_TEST(test_error_ref_out_of_range);
    RUN_TEST(test_error_unknown_kind);
    RUN_TEST(test_error_trailing_pool_bytes);
    RUN_TEST(test_error_truncated_entry);
    RUN_TEST(test_error_enum_unsupported);
    RUN_TEST(test_error_invalid_len_kind);
    RUN_TEST(test_error_invalid_flag_kind);
    RUN_TEST(test_error_short_u16_truncated);
    RUN_TEST(test_error_bytes_fixed_too_short);
    RUN_TEST(test_error_string_prefixed_value_too_short);
    RUN_TEST(test_error_array_prefixed_len_truncated);
    RUN_TEST(test_error_array_remainder_zero_progress);
    RUN_TEST(test_error_pool_truncated_per_kind);
    RUN_TEST(test_empty_pool_rejected);
    RUN_TEST(test_zero_size_pool_rejected);

    // Out-of-space injection
    RUN_TEST(test_oom_at_each_alloc_site);
    RUN_TEST(test_oom_fixed_size_table);

    printf("passed\n");
    return 0;
}
