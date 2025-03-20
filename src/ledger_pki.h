#pragma once
#include <stdint.h>
#include "os.h"
#include "buffer.h"

int check_signature_with_pubkey(const uint8_t *buffer,
                                uint8_t buffer_length,
                                uint8_t expected_key_usage,
                                cx_curve_t expected_curve,
                                const buffer_t signature);
