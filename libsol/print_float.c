#include <string.h>
#include <stdbool.h>

#include "print_float.h"
#include "os_print.h"

// IEEE-754 -> decimal rendering, integer-only (no float/double arithmetic in
// this module; the value is decoded to an exact rational M * 2^e2 and scaled
// into a fixed number of significant decimal digits with round-half-to-even).
//
// The only non-trivial machinery is a small fixed-size big integer. Denominators
// are always powers of two, so the sole division needed is a right shift with
// rounding; no big/big division is required.

// 40 limbs (1280 bits) covers every intermediate: the largest is 5^s for a f64
// (|s| up to ~340, ~790 bits) or mantissa << e2 (up to ~1024 bits).
#define FP_LIMBS 40

typedef struct {
    uint32_t limb[FP_LIMBS];  // little-endian
    int len;                  // significant limbs, always >= 1
} fp_bignum_t;

static void bn_from_u64(fp_bignum_t *bn, uint64_t v) {
    memset(bn->limb, 0, sizeof(bn->limb));
    bn->limb[0] = (uint32_t) v;
    bn->limb[1] = (uint32_t) (v >> 32);
    if (bn->limb[1] != 0) {
        bn->len = 2;
    } else {
        bn->len = 1;
    }
}

static bool bn_is_zero(const fp_bignum_t *bn) {
    return bn->len == 1 && bn->limb[0] == 0;
}

static void bn_normalize(fp_bignum_t *bn) {
    while (bn->len > 1 && bn->limb[bn->len - 1] == 0) {
        bn->len--;
    }
}

// bn *= m (m must fit in 32 bits). Returns false on capacity overflow.
static bool bn_mul_small(fp_bignum_t *bn, uint32_t m) {
    uint64_t carry = 0;
    for (int i = 0; i < bn->len; i++) {
        uint64_t current = (uint64_t) bn->limb[i] * m + carry;
        bn->limb[i] = (uint32_t) current;
        carry = current >> 32;
    }
    while (carry != 0) {
        if (bn->len >= FP_LIMBS) {
            PRINTF("bn_mul_small: capacity overflow\n");
            return false;
        }
        bn->limb[bn->len++] = (uint32_t) carry;
        carry >>= 32;
    }
    return true;
}

// bn *= 5^e, applied in 5^13 chunks (5^13 = 1220703125 < 2^31).
static bool bn_mul_pow5(fp_bignum_t *bn, unsigned e) {
    static const uint32_t pow5[14] = {1u,
                                      5u,
                                      25u,
                                      125u,
                                      625u,
                                      3125u,
                                      15625u,
                                      78125u,
                                      390625u,
                                      1953125u,
                                      9765625u,
                                      48828125u,
                                      244140625u,
                                      1220703125u};
    while (e >= 13) {
        if (!bn_mul_small(bn, pow5[13])) {
            return false;
        }
        e -= 13;
    }
    if (e > 0) {
        if (!bn_mul_small(bn, pow5[e])) {
            return false;
        }
    }
    return true;
}

// bn <<= bits. Returns false on capacity overflow.
static bool bn_shl(fp_bignum_t *bn, unsigned bits) {
    unsigned limb_shift = bits / 32;
    unsigned bit_shift = bits % 32;
    if (limb_shift > 0) {
        if (bn->len + (int) limb_shift > FP_LIMBS) {
            PRINTF("bn_shl: capacity overflow\n");
            return false;
        }
        for (int i = bn->len - 1; i >= 0; i--) {
            bn->limb[i + limb_shift] = bn->limb[i];
        }
        for (unsigned i = 0; i < limb_shift; i++) {
            bn->limb[i] = 0;
        }
        bn->len += (int) limb_shift;
    }
    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (int i = 0; i < bn->len; i++) {
            uint64_t current = ((uint64_t) bn->limb[i] << bit_shift) | carry;
            bn->limb[i] = (uint32_t) current;
            carry = (uint32_t) (current >> 32);
        }
        if (carry != 0) {
            if (bn->len >= FP_LIMBS) {
                PRINTF("bn_shl: capacity overflow\n");
                return false;
            }
            bn->limb[bn->len++] = carry;
        }
    }
    return true;
}

// Divide bn by 10 in place, returning the remainder digit.
static uint32_t bn_divmod10(fp_bignum_t *bn) {
    uint64_t remainder = 0;
    for (int i = bn->len - 1; i >= 0; i--) {
        uint64_t current = (remainder << 32) | bn->limb[i];
        bn->limb[i] = (uint32_t) (current / 10);
        remainder = current % 10;
    }
    bn_normalize(bn);
    return (uint32_t) remainder;
}

// bn = round(bn / 2^k) with round-half-to-even. k must be > 0.
static void bn_shr_round(fp_bignum_t *bn, unsigned k) {
    // Inspect the round bit (bit k-1) and the sticky bits (everything below it)
    // before discarding them.
    unsigned round_pos = k - 1;
    unsigned round_limb = round_pos / 32;
    unsigned round_bit = round_pos % 32;
    int round = 0;
    int sticky = 0;
    if ((int) round_limb < bn->len) {
        round = (int) ((bn->limb[round_limb] >> round_bit) & 1u);
        if (round_bit > 0) {
            uint32_t mask = (1u << round_bit) - 1u;
            if ((bn->limb[round_limb] & mask) != 0) {
                sticky = 1;
            }
        }
        for (unsigned i = 0; i < round_limb && sticky == 0; i++) {
            if (bn->limb[i] != 0) {
                sticky = 1;
            }
        }
    }

    unsigned limb_shift = k / 32;
    unsigned bit_shift = k % 32;
    if (limb_shift >= (unsigned) bn->len) {
        bn->limb[0] = 0;
        bn->len = 1;
    } else {
        int new_len = bn->len - (int) limb_shift;
        for (int i = 0; i < new_len; i++) {
            bn->limb[i] = bn->limb[i + limb_shift];
        }
        for (int i = new_len; i < bn->len; i++) {
            bn->limb[i] = 0;
        }
        bn->len = new_len;
        if (bit_shift > 0) {
            for (int i = 0; i < bn->len; i++) {
                uint32_t high = 0;
                if (i + 1 < bn->len) {
                    high = bn->limb[i + 1];
                }
                bn->limb[i] = (uint32_t) ((bn->limb[i] >> bit_shift) |
                                          ((uint64_t) high << (32 - bit_shift)));
            }
        }
        bn_normalize(bn);
    }

    bool round_up = false;
    if (round != 0) {
        if (sticky != 0) {
            round_up = true;
        } else {
            // Exactly halfway: round to even.
            round_up = (bn->limb[0] & 1u) != 0;
        }
    }
    if (round_up) {
        uint64_t carry = 1;
        for (int i = 0; i < bn->len && carry != 0; i++) {
            uint64_t current = (uint64_t) bn->limb[i] + carry;
            bn->limb[i] = (uint32_t) current;
            carry = current >> 32;
        }
        if (carry != 0) {
            bn->limb[bn->len++] = (uint32_t) carry;
        }
    }
}

// Render bn as decimal into out (NUL-terminated). Returns digit count or -1.
// Destroys bn.
static int bn_to_decimal(fp_bignum_t *bn, char *out, size_t out_size) {
    int n = 0;
    if (bn_is_zero(bn)) {
        if (out_size < 2) {
            PRINTF("bn_to_decimal: buffer too small for \"0\"\n");
            return -1;
        }
        out[0] = '0';
        out[1] = '\0';
        return 1;
    }
    while (!bn_is_zero(bn)) {
        if ((size_t) n + 1 >= out_size) {
            PRINTF("bn_to_decimal: scratch overflow\n");
            return -1;
        }
        out[n++] = (char) ('0' + bn_divmod10(bn));
    }
    for (int i = 0, j = n - 1; i < j; i++, j--) {
        char tmp = out[i];
        out[i] = out[j];
        out[j] = tmp;
    }
    out[n] = '\0';
    return n;
}

// True if bn >= threshold (threshold must be a plain u64).
static bool bn_ge_u64(const fp_bignum_t *bn, uint64_t threshold) {
    if (bn->len > 2) {
        return true;
    }
    uint64_t value = bn->limb[0];
    if (bn->len == 2) {
        value |= (uint64_t) bn->limb[1] << 32;
    }
    return value >= threshold;
}

// bn += 1.
static void bn_increment(fp_bignum_t *bn) {
    uint64_t carry = 1;
    for (int i = 0; i < bn->len && carry != 0; i++) {
        uint64_t current = (uint64_t) bn->limb[i] + carry;
        bn->limb[i] = (uint32_t) current;
        carry = current >> 32;
    }
    if (carry != 0) {
        bn->limb[bn->len++] = (uint32_t) carry;
    }
}

// 10^exponent as a u64 (exponent <= 17, always fits).
static uint64_t pow10_u64(int exponent) {
    uint64_t result = 1;
    for (int i = 0; i < exponent; i++) {
        result *= 10;
    }
    return result;
}

// Highest set-bit index of a non-zero value.
static int highest_bit(uint64_t v) {
    int index = 0;
    while (v > 1) {
        v >>= 1;
        index++;
    }
    return index;
}

// floor(a / b) for b > 0 (C division truncates toward zero, so a negative
// remainder means the quotient was rounded up and must be decremented).
static long floor_div(long a, long b) {
    long quotient = a / b;
    long remainder = a % b;
    if (remainder < 0) {
        quotient--;
    }
    return quotient;
}

// Copy src (length len) into digits, dropping trailing zeros (keeping >= 1
// digit). Returns the trimmed length or -1 if it does not fit.
static int emit_trimmed(const char *src, int len, char *digits, size_t digits_size) {
    while (len > 1 && src[len - 1] == '0') {
        len--;
    }
    if ((size_t) len + 1 > digits_size) {
        PRINTF("emit_trimmed: %d digits do not fit\n", len);
        return -1;
    }
    memcpy(digits, src, len);
    digits[len] = '\0';
    return len;
}

// Value = mantissa * 2^e2 (mantissa > 0). Produces the significant digits
// (trailing zeros trimmed) and *leading_exp = exponent of the leading digit,
// so value == digits[0].digits[1..] x 10^(*leading_exp). Returns 0 on success.
static int compute_significant_digits(uint64_t mantissa,
                                      int e2,
                                      int precision,
                                      char *digits,
                                      size_t digits_size,
                                      int *leading_exp) {
    fp_bignum_t bn;
    // Holds the rounded significand: at most precision (+1 on carry) digits.
    char scratch[32];

    if (e2 >= 0) {
        // Value is an integer. Drop its low decimal digits one at a time until
        // only `precision` significant digits remain, rounding half-to-even.
        bn_from_u64(&bn, mantissa);
        if (!bn_shl(&bn, (unsigned) e2)) {
            return -1;
        }
        uint64_t threshold = pow10_u64(precision);
        int drop = 0;
        int round_digit = 0;
        int sticky = 0;
        while (bn_ge_u64(&bn, threshold)) {
            // Fold the previously kept round digit into the sticky flag before
            // capturing the next (more significant) dropped digit.
            if (round_digit != 0) {
                sticky = 1;
            }
            round_digit = (int) bn_divmod10(&bn);
            drop++;
        }
        bool round_up = false;
        if (round_digit > 5) {
            round_up = true;
        } else if (round_digit == 5) {
            round_up = (sticky != 0) || ((bn.limb[0] & 1u) != 0);
        }
        if (round_up) {
            bn_increment(&bn);
        }
        int len = bn_to_decimal(&bn, scratch, sizeof(scratch));
        if (len < 0) {
            return -1;
        }
        *leading_exp = (len - 1) + drop;
        if (emit_trimmed(scratch, len, digits, digits_size) < 0) {
            return -1;
        }
        return 0;
    } else {
        // Fractional value: n = round(value * 10^s) scaled to `precision` digits.
        // value * 10^s = mantissa * 5^s * 2^(s+e2); the 2-power is the only
        // divisor, handled by a rounding right shift.
        long b = (long) e2 + highest_bit(mantissa);
        int decimal_exp = (int) floor_div(b * 30103L, 100000L);  // ~log10(2)
        int s = precision - 1 - decimal_exp;

        for (int iteration = 0; iteration < 8; iteration++) {
            bn_from_u64(&bn, mantissa);
            if (!bn_mul_pow5(&bn, (unsigned) s)) {
                return -1;
            }
            int shift = s + e2;
            if (shift >= 0) {
                if (!bn_shl(&bn, (unsigned) shift)) {
                    return -1;
                }
            } else {
                bn_shr_round(&bn, (unsigned) (-shift));
            }
            int len = bn_to_decimal(&bn, scratch, sizeof(scratch));
            if (len < 0) {
                return -1;
            }
            if (len < precision) {
                s++;
                continue;
            }
            if (len > precision) {
                s--;
                continue;
            }
            *leading_exp = (len - 1) - s;
            if (emit_trimmed(scratch, len, digits, digits_size) < 0) {
                return -1;
            }
            return 0;
        }
        PRINTF("compute_significant_digits: did not converge\n");
        return -1;
    }
}

// Assemble the final string from the significant digits, the leading-digit
// exponent, and the sign. Plain decimal inside a sane exponent window, else
// scientific notation.
static int format_decimal(const char *digits,
                          int digit_count,
                          int leading_exp,
                          bool negative,
                          char *out,
                          size_t out_length) {
    char buf[80];
    int pos = 0;

    if (negative) {
        buf[pos++] = '-';
    }

    bool scientific = (leading_exp < -4) || (leading_exp >= 21);
    if (!scientific) {
        if (leading_exp >= 0) {
            int integer_digits = leading_exp + 1;
            if (digit_count <= integer_digits) {
                memcpy(buf + pos, digits, digit_count);
                pos += digit_count;
                for (int i = 0; i < integer_digits - digit_count; i++) {
                    buf[pos++] = '0';
                }
            } else {
                memcpy(buf + pos, digits, integer_digits);
                pos += integer_digits;
                buf[pos++] = '.';
                memcpy(buf + pos, digits + integer_digits, digit_count - integer_digits);
                pos += digit_count - integer_digits;
            }
        } else {
            buf[pos++] = '0';
            buf[pos++] = '.';
            for (int i = 0; i < -leading_exp - 1; i++) {
                buf[pos++] = '0';
            }
            memcpy(buf + pos, digits, digit_count);
            pos += digit_count;
        }
    } else {
        buf[pos++] = digits[0];
        if (digit_count > 1) {
            buf[pos++] = '.';
            memcpy(buf + pos, digits + 1, digit_count - 1);
            pos += digit_count - 1;
        }
        buf[pos++] = 'e';
        int exponent = leading_exp;
        if (exponent < 0) {
            buf[pos++] = '-';
            exponent = -exponent;
        } else {
            buf[pos++] = '+';
        }
        char exp_digits[6];
        int exp_count = 0;
        if (exponent == 0) {
            exp_digits[exp_count++] = '0';
        }
        while (exponent > 0) {
            exp_digits[exp_count++] = (char) ('0' + exponent % 10);
            exponent /= 10;
        }
        while (exp_count < 2) {
            exp_digits[exp_count++] = '0';
        }
        for (int i = exp_count - 1; i >= 0; i--) {
            buf[pos++] = exp_digits[i];
        }
    }

    if ((size_t) pos + 1 > out_length) {
        PRINTF("format_decimal: output does not fit\n");
        return -1;
    }
    memcpy(out, buf, pos);
    out[pos] = '\0';
    return 0;
}

static int write_literal(const char *literal, char *out, size_t out_length) {
    size_t len = strlen(literal);
    if (len + 1 > out_length) {
        PRINTF("print_float: literal does not fit\n");
        return -1;
    }
    memcpy(out, literal, len + 1);
    return 0;
}

static int print_float_generic(uint64_t bits,
                               int exp_bits,
                               int mant_bits,
                               int precision,
                               char *out,
                               size_t out_length) {
    int bias = (1 << (exp_bits - 1)) - 1;
    uint64_t mant_mask = ((uint64_t) 1 << mant_bits) - 1;
    uint64_t exp_mask = ((uint64_t) 1 << exp_bits) - 1;
    bool negative = ((bits >> (exp_bits + mant_bits)) & 1u) != 0;
    uint64_t exp_field = (bits >> mant_bits) & exp_mask;
    uint64_t frac = bits & mant_mask;

    if (exp_field == exp_mask) {
        if (frac != 0) {
            return write_literal("NaN", out, out_length);
        } else if (negative) {
            return write_literal("-Infinity", out, out_length);
        } else {
            return write_literal("Infinity", out, out_length);
        }
    }

    uint64_t mantissa;
    int e2;
    if (exp_field == 0) {
        if (frac == 0) {
            return write_literal("0", out, out_length);
        }
        // Subnormal: no implicit leading bit.
        mantissa = frac;
        e2 = 1 - bias - mant_bits;
    } else {
        mantissa = frac | ((uint64_t) 1 << mant_bits);
        e2 = (int) exp_field - bias - mant_bits;
    }

    char digits[40];
    int leading_exp;
    if (compute_significant_digits(mantissa, e2, precision, digits, sizeof(digits), &leading_exp) !=
        0) {
        PRINTF("print_float: compute_significant_digits failed\n");
        return -1;
    }
    return format_decimal(digits, (int) strlen(digits), leading_exp, negative, out, out_length);
}

int print_f32(const uint8_t value[4], char *out, size_t out_length) {
    uint64_t bits = (uint64_t) value[0] | ((uint64_t) value[1] << 8) | ((uint64_t) value[2] << 16) |
                    ((uint64_t) value[3] << 24);
    return print_float_generic(bits, 8, 23, 9, out, out_length);
}

int print_f64(const uint8_t value[8], char *out, size_t out_length) {
    uint64_t bits = 0;
    for (int i = 0; i < 8; i++) {
        bits |= (uint64_t) value[i] << (8 * i);
    }
    return print_float_generic(bits, 11, 52, 17, out, out_length);
}
