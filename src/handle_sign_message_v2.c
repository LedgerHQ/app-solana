#include "os.h"
#include "cx.h"
#include "globals.h"
#include "apdu.h"
#include "handle_sign_message_v2.h"
#include "sol/printer.h"

#include <string.h>

// Local Ed25519 signing that does NOT clean the private key
// This is intentionally duplicated and insecure - prototype only
static void derive_private_key_v2(cx_ecfp_private_key_t *private_key,
                                  const uint32_t *derivation_path,
                                  uint32_t derivation_path_length) {
    uint8_t raw_private_key[PRIVATEKEY_LENGTH];

    os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10,
                                        CX_CURVE_Ed25519,
                                        derivation_path,
                                        derivation_path_length,
                                        raw_private_key,
                                        NULL,
                                        NULL,
                                        0);

    cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, raw_private_key, PRIVATEKEY_LENGTH, private_key);
    // NOTE: raw_private_key is intentionally NOT cleared
}

static void sign_message_v2(const uint8_t *message,
                            size_t message_length,
                            uint8_t *signature,
                            const uint32_t *derivation_path,
                            uint32_t derivation_path_length) {
    cx_ecfp_private_key_t private_key;
    size_t sig_len = SIGNATURE_LENGTH;

    derive_private_key_v2(&private_key, derivation_path, derivation_path_length);

    cx_eddsa_sign_no_throw(&private_key,
                           CX_SHA512,
                           message,
                           message_length,
                           signature,
                           sig_len);
    // NOTE: private_key is intentionally NOT cleared
}

void handle_sign_message_v2(volatile unsigned int *flags, volatile unsigned int *tx) {
    UNUSED(flags);

    if (G_command.state != ApduStatePayloadComplete) {
        THROW(ApduReplySdkInvalidParameter);
    }

    if (G_command.instruction != InsSignMessageV2) {
        THROW(ApduReplySdkInvalidParameter);
    }

    if (G_command.message_length == 0) {
        THROW(ApduReplySolanaInvalidMessageSize);
    }

    PRINTF("handle_sign_message_v2: message_length=%d\n", G_command.message_length);
    PRINTF("handle_sign_message_v2: derivation_path_length=%d\n", G_command.derivation_path_length);

    // Sign directly without any UI or deep validation
    sign_message_v2(G_command.message,
                    G_command.message_length,
                    G_io_apdu_buffer,
                    G_command.derivation_path,
                    G_command.derivation_path_length);

    *tx = SIGNATURE_LENGTH;
    THROW(ApduReplySuccess);
}
