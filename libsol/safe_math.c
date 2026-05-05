#include "sol/safe_math.h"
#include <limits.h>

// Computes floor(a * b / 10000) where a is u64 and b is u16.
// The intermediate product a*b can reach ~2^80, so we use manual
// 128-bit arithmetic by splitting a into two 32-bit halves.
//
// Let a = a_hi * 2^32 + a_lo  (a_hi, a_lo are at most 2^32-1)
// Then a * b = a_hi*b * 2^32 + a_lo*b
//
// Each partial product fits in u64 (u32 * u16 < 2^48).
// We then divide the 96-bit value (prod_hi * 2^32 + prod_lo) by 10000:
//   q_hi = prod_hi / 10000
//   r_hi = prod_hi % 10000
//   result = q_hi * 2^32 + (r_hi * 2^32 + prod_lo) / 10000
//
// Overflow is detected at two points:
//   1) q_hi must fit in 32 bits for the shift to be valid
//   2) The final addition must not wrap around
int safe_mul_bps_div10000(uint64_t a, uint16_t b, uint64_t *result) {
    // Partial products (each fits in u64: max ~2^48)
    uint64_t prod_lo = (uint64_t) (uint32_t) a * b;
    uint64_t prod_hi = (a >> 32) * b;

    uint64_t q_hi = prod_hi / 10000;
    uint64_t r_hi = prod_hi % 10000;

    // q_hi << 32 must not overflow u64
    if (q_hi > UINT32_MAX) {
        return -1;
    }

    uint64_t hi_part = q_hi << 32;
    uint64_t lo_part = ((r_hi << 32) + prod_lo) / 10000;

    // Final addition must not overflow u64
    if (lo_part > UINT64_MAX - hi_part) {
        return -1;
    }

    *result = hi_part + lo_part;
    return 0;
}
