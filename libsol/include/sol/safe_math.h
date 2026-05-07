#pragma once

#include <stdbool.h>
#include <stdint.h>

// Computes floor(a * b / 10000) and stores the result in *result.
// Returns 0 on success, -1 if the result would overflow uint64_t.
int safe_mul_bps_div10000(uint64_t a, uint16_t b, uint64_t *result);
