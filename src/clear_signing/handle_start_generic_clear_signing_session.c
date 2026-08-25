#include <os.h>

#include "handle_start_generic_clear_signing_session.h"
#include "handle_sign_message_preview.h"
#include "cs_transaction.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "sol/parser.h"
#include "reply.h"
#include "utils.h"

int handle_start_generic_clear_signing_session(void) {
    PRINTF("handle_start_generic_clear_signing_session\n");

    // This APDU opens the flow from any state: a host abandoning a session mid-stream
    // restarts by sending it again, so whatever was buffered is dropped here rather than
    // refused. Every later clear-signing APDU still demands its own state.
    cs_session_reset();

    if (G_command.instruction != InsStartGenericClearSigningSession ||
        G_command.state != ApduStatePayloadComplete) {
        return reply_sw(ApduReplySdkInvalidParameter);
    }

    // Validate the serialized message parses as a Solana message before buffering it.
    Parser parser = {G_command.message, G_command.message_length};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("start cs session: invalid Solana message\n");
        return reply_sw(ApduReplySolanaInvalidMessage);
    }

    // The device only signs messages it is a party to, exactly as InsSignMessage requires.
    // Refusing here rather than at finalize keeps the whole descriptor stream off the wire.
    size_t signer_index;
    if (scan_header_for_signer(G_command.derivation_path,
                               G_command.derivation_path_length,
                               &signer_index,
                               &header) != 0) {
        PRINTF("start cs session: requested signer is absent from the header\n");
        return reply_sw(ApduReplySolanaInvalidMessageHeader);
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
        return reply_sw(ApduReplySolanaInvalidGenericPreview);
    }

    PRINTF("start cs session: buffered %d-byte transaction, %d instructions\n",
           G_command.message_length,
           header.instructions_length);
    G_cs_session_state = CS_SESSION_STREAMING;
    return reply_sw(ApduReplySuccess);
}
