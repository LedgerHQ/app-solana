#include "os.h"
#include "cx.h"
#include <stdlib.h>

#include "lib_standard_app/crypto_helpers.h"

#include "utils.h"

void get_public_key(uint8_t publicKeyArray[static PUBKEY_LENGTH],
                    const uint32_t *derivationPath,
                    size_t pathLength) {
    uint8_t rawPubkey[65];
    cx_err_t cx_err;

    cx_err = bip32_derive_with_seed_get_pubkey_256(HDW_ED25519_SLIP10,
                                                   CX_CURVE_Ed25519,
                                                   derivationPath,
                                                   pathLength,
                                                   rawPubkey,
                                                   NULL,
                                                   CX_SHA512,
                                                   NULL,
                                                   0);

    if (CX_OK != cx_err) {
        THROW(cx_err);
    }

    for (int i = 0; i < PUBKEY_LENGTH; i++) {
        publicKeyArray[i] = rawPubkey[PUBKEY_LENGTH + PRIVATEKEY_LENGTH - i];
    }
    if ((rawPubkey[PUBKEY_LENGTH] & 1) != 0) {
        publicKeyArray[PUBKEY_LENGTH - 1] |= 0x80;
    }
}

int get_pubkey_index(const Pubkey *needle,
                     const Pubkey *haystack,
                     size_t haystack_len,
                     size_t *index) {
    for (size_t i = 0; i < haystack_len; ++i) {
        const Pubkey *current_pubkey = &(haystack[i]);
        if (memcmp(current_pubkey, needle, PUBKEY_SIZE) == 0) {
            *index = i;
            return 0;
        }
    }
    return -1;
}

int read_derivation_path(const uint8_t *data_buffer,
                         size_t data_size,
                         uint32_t *derivation_path,
                         uint32_t *derivation_path_length) {
    if (!data_buffer || !derivation_path || !derivation_path_length) {
        return ApduReplySdkInvalidParameter;
    }
    if (!data_size) {
        return ApduReplySolanaInvalidMessageSize;
    }
    const size_t len = data_buffer[0];
    data_buffer += 1;
    if (len < 1 || len > MAX_BIP32_PATH_LENGTH) {
        return ApduReplySolanaInvalidMessage;
    }
    if (1 + 4 * len > data_size) {
        return ApduReplySolanaInvalidMessageSize;
    }

    for (size_t i = 0; i < len; i++) {
        derivation_path[i] = ((data_buffer[0] << 24u) | (data_buffer[1] << 16u) |
                              (data_buffer[2] << 8u) | (data_buffer[3]));
        data_buffer += 4;
    }

    *derivation_path_length = len;

    return 0;
}

uint8_t set_result_sign_message(void) {
    size_t sigLen = SIGNATURE_LENGTH;
    cx_err_t cx_err;

    cx_err = bip32_derive_with_seed_eddsa_sign_hash_256(HDW_ED25519_SLIP10,
                                                        CX_CURVE_Ed25519,
                                                        G_command.derivation_path,
                                                        G_command.derivation_path_length,
                                                        CX_SHA512,
                                                        G_command.message,
                                                        G_command.message_length,
                                                        G_io_apdu_buffer,
                                                        &sigLen,
                                                        NULL,
                                                        0);

    if (CX_OK != cx_err) {
        THROW(cx_err);
    }

    return SIGNATURE_LENGTH;
}
