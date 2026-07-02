#include <os.h>

#include "handle_start_generic_clear_signing_session.h"
#include "handle_sign_message_preview.h"
#include "cs_transaction.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "sol/parser.h"

int handle_start_generic_clear_signing_session(void) {
    PRINTF("handle_start_generic_clear_signing_session\n");

    int state_err = cs_check_state(CS_SESSION_IDLE);
    if (state_err != 0) {
        return io_send_sw(state_err);
    }

    if (G_command.instruction != InsStartGenericClearSigningSession ||
        G_command.state != ApduStatePayloadComplete) {
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    // Validate the serialized message parses as a Solana message before buffering it.
    Parser parser = {G_command.message, G_command.message_length};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("start cs session: invalid Solana message\n");
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaInvalidMessage);
    }

    // Discard any previous preview fingerprint.
    clear_preview_state();

    // The descriptor stream that follows reuses G_command.message, so the
    // transaction and derivation path must be copied into the clear-signing
    // context now. The fingerprint is computed later at user approval time.
    if (cs_transaction_begin(G_command.message,
                             G_command.message_length,
                             G_command.derivation_path,
                             G_command.derivation_path_length) != 0) {
        PRINTF("start cs session: failed to buffer transaction\n");
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    PRINTF("start cs session: buffered %d-byte transaction, %d instructions\n",
           G_command.message_length,
           header.instructions_length);
    G_cs_session_state = CS_SESSION_STREAMING;
    return io_send_sw(ApduReplySuccess);
}
