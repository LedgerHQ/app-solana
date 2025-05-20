#pragma once

#include "os.h"
#include "buffer.h"
#include "cx.h"

#define DER_SIGNATURE_MIN_SIZE 70
#define DER_SIGNATURE_MAX_SIZE 72

int check_signature_with_pubkey(const buffer_t hash,
                                uint8_t expected_key_usage,
                                cx_curve_t expected_curve,
                                const buffer_t signature);
