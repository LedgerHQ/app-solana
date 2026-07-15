#include "print_float.c"
#include "test_utils.h"
#include "util.h"

#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The host oracle (strtod / printf) is allowed to use real floating point; the
// module under test never does.

static void bytes_from_f64(double d, uint8_t out[8]) {
    memcpy(out, &d, 8);
}

static void bytes_from_f32(float f, uint8_t out[4]) {
    memcpy(out, &f, 4);
}

static double f64_from_bytes(const uint8_t in[8]) {
    double d;
    memcpy(&d, in, 8);
    return d;
}

static float f32_from_bytes(const uint8_t in[4]) {
    float f;
    memcpy(&f, in, 4);
    return f;
}

// Exact-string check for f64.
static void check_f64_string(double d, const char *expected) {
    uint8_t bytes[8];
    char out[80];
    bytes_from_f64(d, bytes);
    assert(print_f64(bytes, out, sizeof(out)) == 0);
    if (strcmp(out, expected) != 0) {
        printf("    f64 mismatch: got \"%s\" expected \"%s\"\n", out, expected);
    }
    assert_string_equal(out, expected);
}

// Print, then parse back and require a bit-exact round-trip.
static void roundtrip_f64(double d) {
    uint8_t bytes[8];
    char out[80];
    bytes_from_f64(d, bytes);
    assert(print_f64(bytes, out, sizeof(out)) == 0);
    double parsed = strtod(out, NULL);
    if (parsed != d) {
        printf("    f64 roundtrip failed: %.17g -> \"%s\" -> %.17g\n", d, out, parsed);
    }
    assert(parsed == d);
}

static void roundtrip_f32(float f) {
    uint8_t bytes[4];
    char out[80];
    bytes_from_f32(f, bytes);
    assert(print_f32(bytes, out, sizeof(out)) == 0);
    float parsed = strtof(out, NULL);
    if (parsed != f) {
        printf("    f32 roundtrip failed: %.9g -> \"%s\" -> %.9g\n", (double) f, out, (double) parsed);
    }
    assert(parsed == f);
}

static void test_specials(void) {
    printf("  test_specials\n");
    char out[80];

    // +0 and -0 both render as "0".
    uint8_t pos_zero[8] = {0};
    assert(print_f64(pos_zero, out, sizeof(out)) == 0);
    assert_string_equal(out, "0");

    uint8_t neg_zero[8] = {0, 0, 0, 0, 0, 0, 0, 0x80};
    assert(print_f64(neg_zero, out, sizeof(out)) == 0);
    assert_string_equal(out, "0");

    // +Inf: exp all ones, frac zero.
    uint8_t pos_inf[8] = {0, 0, 0, 0, 0, 0, 0xF0, 0x7F};
    assert(print_f64(pos_inf, out, sizeof(out)) == 0);
    assert_string_equal(out, "Infinity");

    uint8_t neg_inf[8] = {0, 0, 0, 0, 0, 0, 0xF0, 0xFF};
    assert(print_f64(neg_inf, out, sizeof(out)) == 0);
    assert_string_equal(out, "-Infinity");

    // NaN: exp all ones, frac non-zero.
    uint8_t nan_bytes[8] = {0, 0, 0, 0, 0, 0, 0xF8, 0x7F};
    assert(print_f64(nan_bytes, out, sizeof(out)) == 0);
    assert_string_equal(out, "NaN");

    // f32 specials.
    uint8_t f32_inf[4] = {0, 0, 0x80, 0x7F};
    assert(print_f32(f32_inf, out, sizeof(out)) == 0);
    assert_string_equal(out, "Infinity");
    uint8_t f32_nan[4] = {0, 0, 0xC0, 0x7F};
    assert(print_f32(f32_nan, out, sizeof(out)) == 0);
    assert_string_equal(out, "NaN");
}

static void test_exact_strings(void) {
    printf("  test_exact_strings\n");
    // Values exactly representable in binary render to a clean decimal.
    check_f64_string(1.0, "1");
    check_f64_string(-1.0, "-1");
    check_f64_string(0.5, "0.5");
    check_f64_string(-0.5, "-0.5");
    check_f64_string(0.25, "0.25");
    check_f64_string(-3.25, "-3.25");
    check_f64_string(100.0, "100");
    check_f64_string(1000000.0, "1000000");
    check_f64_string(0.0009765625, "0.0009765625");  // 2^-10, E == -4 (plain)
}

static void test_scientific(void) {
    printf("  test_scientific\n");
    char out[80];

    // DBL_MAX and FLT_MAX have a huge exponent -> scientific notation.
    uint8_t bytes[8];
    bytes_from_f64(DBL_MAX, bytes);
    assert(print_f64(bytes, out, sizeof(out)) == 0);
    assert(strchr(out, 'e') != NULL);
    roundtrip_f64(DBL_MAX);

    roundtrip_f32(FLT_MAX);

    // Smallest positive subnormal double (bit pattern 0x0...01).
    uint8_t denorm_min_bytes[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    double denorm_min = f64_from_bytes(denorm_min_bytes);
    assert(print_f64(denorm_min_bytes, out, sizeof(out)) == 0);
    assert(strchr(out, 'e') != NULL);
    assert(strtod(out, NULL) == denorm_min);

    // Smallest positive subnormal float.
    uint8_t f32_denorm_min[4] = {1, 0, 0, 0};
    float f32_dm = f32_from_bytes(f32_denorm_min);
    roundtrip_f32(f32_dm);
}

static void test_roundtrip_selected(void) {
    printf("  test_roundtrip_selected\n");
    static const double values[] = {0.1,
                                    0.2,
                                    0.3,
                                    1.0 / 3.0,
                                    2.0 / 3.0,
                                    3.141592653589793,
                                    2.718281828459045,
                                    123456789.123456789,
                                    -0.000123456,
                                    9.999999999999999e15,
                                    1e21,
                                    1e-21,
                                    138.72,
                                    -987654321.0,
                                    1234567890123456.0};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        roundtrip_f64(values[i]);
    }

    static const float f32_values[] =
        {0.1f, 0.2f, 138.72f, 3.14159265f, -2.5f, 1e10f, 1e-10f, 16777216.0f};
    for (size_t i = 0; i < sizeof(f32_values) / sizeof(f32_values[0]); i++) {
        roundtrip_f32(f32_values[i]);
    }
}

// Sweep random bit patterns and cross-check against the host oracle.
static void test_random_sweep(void) {
    printf("  test_random_sweep\n");
    char out[80];
    srand(0x50134);

    for (int i = 0; i < 200000; i++) {
        uint8_t bytes[8];
        for (int b = 0; b < 8; b++) {
            bytes[b] = (uint8_t) (rand() & 0xFF);
        }
        double d = f64_from_bytes(bytes);
        assert(print_f64(bytes, out, sizeof(out)) == 0);
        if (isnan(d)) {
            assert_string_equal(out, "NaN");
        } else if (isinf(d)) {
            assert_string_equal(out, (d < 0) ? "-Infinity" : "Infinity");
        } else {
            double parsed = strtod(out, NULL);
            if (parsed != d) {
                printf("    sweep f64 failed: %.17g -> \"%s\" -> %.17g\n", d, out, parsed);
            }
            assert(parsed == d);
        }
    }

    for (int i = 0; i < 200000; i++) {
        uint8_t bytes[4];
        for (int b = 0; b < 4; b++) {
            bytes[b] = (uint8_t) (rand() & 0xFF);
        }
        float f = f32_from_bytes(bytes);
        assert(print_f32(bytes, out, sizeof(out)) == 0);
        if (isnan(f)) {
            assert_string_equal(out, "NaN");
        } else if (isinf(f)) {
            assert_string_equal(out, (f < 0) ? "-Infinity" : "Infinity");
        } else {
            float parsed = strtof(out, NULL);
            if (parsed != f) {
                printf("    sweep f32 failed: %.9g -> \"%s\" -> %.9g\n",
                       (double) f,
                       out,
                       (double) parsed);
            }
            assert(parsed == f);
        }
    }
}

static void test_buffer_too_small(void) {
    printf("  test_buffer_too_small\n");
    uint8_t bytes[8];
    char out[4];
    bytes_from_f64(DBL_MAX, bytes);
    // A scientific rendering cannot fit in 4 bytes: must refuse, not truncate.
    assert(print_f64(bytes, out, sizeof(out)) != 0);
}

int main(void) {
    printf("print_float_test\n");
    RUN_TEST(test_specials);
    RUN_TEST(test_exact_strings);
    RUN_TEST(test_scientific);
    RUN_TEST(test_roundtrip_selected);
    RUN_TEST(test_random_sweep);
    RUN_TEST(test_buffer_too_small);
    printf("passed\n");
    return 0;
}
