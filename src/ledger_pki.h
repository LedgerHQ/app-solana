#pragma once

#include "os.h"
#include "buffer.h"
#include "cx.h"

#define DER_SIGNATURE_MIN_SIZE 70
#define DER_SIGNATURE_MAX_SIZE 72

typedef enum check_signature_with_pki_status_e {
    CHECK_SIGNATURE_WITH_PKI_SUCCESS = 0,
    CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE = 1,
    CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_USAGE = 2,
    CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_CURVE = 3,
    CHECK_SIGNATURE_WITH_PKI_WRONG_SIGNATURE = 4,
} check_signature_with_pki_status_t;

check_signature_with_pki_status_t check_signature_with_pki(const buffer_t hash,
                                                           uint8_t expected_key_usage,
                                                           cx_curve_t expected_curve,
                                                           const buffer_t signature);
