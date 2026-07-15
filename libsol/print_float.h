#pragma once

#include <stdint.h>
#include <stddef.h>

// Render an IEEE-754 binary float from its raw little-endian bytes as a
// faithful decimal string (round-trip-safe: 9 significant digits for f32,
// 17 for f64). Special values render as "Infinity", "-Infinity" or "NaN";
// both zeroes render as "0". Returns 0 on success, non-zero on failure.
int print_f32(const uint8_t value[4], char *out, size_t out_length);

int print_f64(const uint8_t value[8], char *out, size_t out_length);
