#include "utils.h"
#include "globals.h"
#include "handle_get_pubkey.h"
#include "sol/printer.h"
#include "ui_api.h"
#include "io.h"

static uint8_t G_publicKey[PUBKEY_LENGTH];
char G_publicKeyStr[BASE58_PUBKEY_LENGTH];

void reset_getpubkey_globals(void) {
    MEMCLEAR(G_publicKey);
    MEMCLEAR(G_publicKeyStr);
}

uint8_t set_result_get_pubkey(void) {
    memcpy(G_io_apdu_buffer, G_publicKey, PUBKEY_LENGTH);
    return PUBKEY_LENGTH;
}

//////////////////////////////////////////////////////////////////////

int handle_get_pubkey(void) {
    if ((G_command.instruction != InsDeprecatedGetPubkey &&
         G_command.instruction != InsGetPubkey) ||
        G_command.state != ApduStatePayloadComplete) {
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    cx_err_t cx_err = get_public_key(G_publicKey,
                                     G_command.derivation_path,
                                     G_command.derivation_path_length);
    if (cx_err != CX_OK) {
        return io_send_sw(ApduReplySdkException);
    }
    encode_base58(G_publicKey, PUBKEY_LENGTH, G_publicKeyStr, BASE58_PUBKEY_LENGTH);

    if (G_command.non_confirm) {
        return io_send_response_pointer(G_publicKey, PUBKEY_LENGTH, ApduReplySuccess);
    } else {
        ui_get_public_key();
        // RAPDU will be sent by the UI after user confirms / refuses, so we just return here.
        return 0;
    }
}
