#include "os_types.h"
#include "os_pki.h"
#include "ledger_pki.h"

check_signature_with_pki_status_t check_signature_with_pki(const buffer_t hash,
                                                           uint8_t expected_key_usage,
                                                           cx_curve_t expected_curve,
                                                           const buffer_t signature) {
    uint8_t key_usage = 0;
    size_t certificate_name_len = 0;
    uint8_t certificate_name[CERTIFICATE_TRUSTED_NAME_MAXLEN] = {0};
    cx_ecfp_384_public_key_t public_key = {0};
    bolos_err_t bolos_err;

    bolos_err = os_pki_get_info(&key_usage, certificate_name, &certificate_name_len, &public_key);
    if (bolos_err != 0x0000) {
        PRINTF("Error %x while getting PKI certificate info\n", bolos_err);
        return CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE;
    }

    if (key_usage != expected_key_usage) {
        PRINTF("Wrong usage certificate %d, expected %d\n", key_usage, expected_key_usage);
        return CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_USAGE;
    }

    if (public_key.curve != expected_curve) {
        PRINTF("Wrong curve %d, expected %d\n", public_key.curve, expected_curve);
        return CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_CURVE;
    }

    PRINTF("Certificate '%s' loaded with success\n", certificate_name);

    // Checking the signature with PKI
    if (!os_pki_verify((uint8_t *) hash.ptr,
                       hash.size,
                       (uint8_t *) signature.ptr,
                       signature.size)) {
        PRINTF("Error, '%.*H' is not a signature of hash '%.*H' by the PKI key '%.*H'\n",
               signature.size,
               signature.ptr,
               hash.size,
               hash.ptr,
               sizeof(public_key),
               &public_key);
        return CHECK_SIGNATURE_WITH_PKI_WRONG_SIGNATURE;
    }

    PRINTF("Signature verified successfully\n");
    return CHECK_SIGNATURE_WITH_PKI_SUCCESS;
}
