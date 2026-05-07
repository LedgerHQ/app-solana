#include "safe_math.c"
#include <assert.h>
#include <stdio.h>

// floor(a * b / 10000) must succeed and equal expected
static void assert_ok(uint64_t a, uint16_t b, uint64_t expected) {
    uint64_t result = 0xDEAD;
    assert(safe_mul_bps_div10000(a, b, &result) == 0);
    if (result != expected) {
        printf("FAIL: safe_mul_bps_div10000(%lu, %u) = %lu, expected %lu\n",
               (unsigned long) a,
               (unsigned) b,
               (unsigned long) result,
               (unsigned long) expected);
    }
    assert(result == expected);
}

// floor(a * b / 10000) must fail (overflow)
static void assert_overflow(uint64_t a, uint16_t b) {
    uint64_t result = 0xDEAD;
    assert(safe_mul_bps_div10000(a, b, &result) == -1);
}

// --- Zero cases ---
void test_zero_amount(void) {
    assert_ok(0, 100, 0);    // 0 * 100 / 10000 = 0
    assert_ok(0, 10000, 0);  // 0 * 10000 / 10000 = 0
    assert_ok(0, 65535, 0);  // 0 * max_bps / 10000 = 0
}

void test_zero_bps(void) {
    assert_ok(1000000, 0, 0);     // anything * 0 / 10000 = 0
    assert_ok(UINT64_MAX, 0, 0);  // max * 0 / 10000 = 0
}

// --- Basic arithmetic ---
void test_basic_100bps(void) {
    // 100 bps = 1%
    assert_ok(1000000, 100, 10000);  // 1M * 100 / 10000 = 10000
    assert_ok(10000, 100, 100);      // 10000 * 100 / 10000 = 100
    assert_ok(99, 100, 0);           // 99 * 100 / 10000 = 0 (truncated)
    assert_ok(100, 100, 1);          // 100 * 100 / 10000 = 1
}

void test_10000bps_identity(void) {
    // 10000 bps = 100%, result should equal the amount
    assert_ok(1, 10000, 1);
    assert_ok(12345, 10000, 12345);
    assert_ok(1000000000, 10000, 1000000000);
}

void test_1bps(void) {
    // 1 bps = 0.01%
    assert_ok(10000, 1, 1);  // 10000 * 1 / 10000 = 1
    assert_ok(9999, 1, 0);   // truncated to 0
    assert_ok(20000, 1, 2);
    assert_ok(1000000, 1, 100);
}

void test_truncation(void) {
    // Verify floor semantics (no rounding up)
    assert_ok(10001, 100, 100);  // 10001 * 100 / 10000 = 100.01 -> 100
    assert_ok(19999, 100, 199);  // 19999 * 100 / 10000 = 199.99 -> 199
    assert_ok(3, 10000, 3);      // exact
    assert_ok(7, 5000, 3);       // 7 * 5000 / 10000 = 3.5 -> 3
}

// --- Large amounts that still fit ---
void test_large_amount_low_bps(void) {
    // UINT64_MAX with small bps
    // UINT64_MAX * 1 / 10000 = 1844674407370955
    assert_ok(UINT64_MAX, 1, 1844674407370955ULL);
}

void test_large_amount_10000bps(void) {
    // UINT64_MAX * 10000 / 10000 = UINT64_MAX
    assert_ok(UINT64_MAX, 10000, UINT64_MAX);
}

void test_large_amount_moderate_bps(void) {
    // UINT64_MAX * 25 / 10000... should succeed
    // UINT64_MAX = 18446744073709551615
    // * 25 = 461168601842738790375 (128-bit)
    // / 10000 = 46116860184273879 (fits u64)
    assert_ok(UINT64_MAX, 25, 46116860184273879ULL);
}

// --- Overflow cases ---
void test_overflow_max_bps(void) {
    // UINT64_MAX * 65535 / 10000
    // = 18446744073709551615 * 65535 / 10000
    // True result ~= 1.209e20, far exceeds UINT64_MAX
    assert_overflow(UINT64_MAX, 65535);
}

void test_overflow_just_over(void) {
    // Find a case where true result just barely overflows u64
    // UINT64_MAX * 10001 / 10000 = UINT64_MAX + UINT64_MAX/10000
    // This is > UINT64_MAX, so must overflow
    assert_overflow(UINT64_MAX, 10001);
}

// --- The specific bug case: hi_div == UINT32_MAX, final addition overflows ---
void test_overflow_hi_div_at_boundary(void) {
    // swap_amount = (655370000ULL << 32) | 0xFFFFFFFF, bps = 65535
    // This makes hi_div == UINT32_MAX, but the final addition overflows u64.
    // The old code (checking only hi_div > UINT32_MAX) would miss this.
    uint64_t a = (655370000ULL << 32) | 0xFFFFFFFFULL;
    assert_overflow(a, 65535);
}

// --- hi_div exactly UINT32_MAX but NO overflow in the final addition ---
void test_hi_div_at_uint32_max_no_overflow(void) {
    // swap_amount_hi = 655370000, bps = 65535
    // hi32 = 655370000 * 65535 = UINT32_MAX * 10000 exactly
    // hi_div = UINT32_MAX, hi_rem = 0
    // lo32 = 0 * 65535 = 0 (lower bits = 0)
    // lo_part = 0, hi_part = UINT32_MAX << 32 -> no overflow in addition
    uint64_t a = 655370000ULL << 32;  // lower 32 bits are 0
    uint64_t result;
    assert(safe_mul_bps_div10000(a, 65535, &result) == 0);
    // result = UINT32_MAX << 32 = 0xFFFFFFFF00000000
    assert(result == ((uint64_t) UINT32_MAX << 32));
}

// --- Boundary: result == UINT64_MAX exactly ---
void test_result_exactly_uint64_max(void) {
    // UINT64_MAX * 10000 / 10000 = UINT64_MAX
    assert_ok(UINT64_MAX, 10000, UINT64_MAX);
}

// --- Small edge cases ---
void test_one_one(void) {
    assert_ok(1, 1, 0);  // 1 * 1 / 10000 = 0
}

void test_10000_10000(void) {
    assert_ok(10000, 10000, 10000);  // 10000 * 10000 / 10000 = 10000
}

// --- Cross 32-bit boundary ---
void test_amount_crosses_32bit(void) {
    // amount = 2^32 = 4294967296
    // 4294967296 * 100 / 10000 = 42949672
    assert_ok(4294967296ULL, 100, 42949672ULL);

    // amount = 2^32 - 1 = 4294967295 (fits in lo32 only when hi=0... wait no, >> 32 = 0)
    // Wait 2^32-1 >> 32 = 0, so hi32 = 0 and all value is in lo32
    // 4294967295 * 100 / 10000 = 42949672
    assert_ok(4294967295ULL, 100, 42949672ULL);

    // amount = 2^33 = 8589934592
    // 8589934592 * 5000 / 10000 = 4294967296
    assert_ok(8589934592ULL, 5000, 4294967296ULL);
}

// --- High bps values (over 10000 = over 100%) ---
void test_bps_over_10000(void) {
    // 1000 * 20000 / 10000 = 2000
    assert_ok(1000, 20000, 2000);
    // 1000 * 65535 / 10000 = 6553
    assert_ok(1000, 65535, 6553);
}

int main() {
    test_zero_amount();
    test_zero_bps();
    test_basic_100bps();
    test_10000bps_identity();
    test_1bps();
    test_truncation();
    test_large_amount_low_bps();
    test_large_amount_10000bps();
    test_large_amount_moderate_bps();
    test_overflow_max_bps();
    test_overflow_just_over();
    test_overflow_hi_div_at_boundary();
    test_hi_div_at_uint32_max_no_overflow();
    test_result_exactly_uint64_max();
    test_one_one();
    test_10000_10000();
    test_amount_crosses_32bit();
    test_bps_over_10000();

    printf("passed\n");
    return 0;
}
