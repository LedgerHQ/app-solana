#include <os.h>

#include "handle_sign_message_generic_preview.h"
#include "cs_transaction.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "sol/parser.h"

int handle_sign_message_generic_preview(void) {
    PRINTF("handle_sign_message_generic_preview\n");

    if (G_command.instruction != InsSignMessageGenericPreview ||
        G_command.state != ApduStatePayloadComplete) {
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    // Validate the serialized message parses as a Solana message before buffering it.
    Parser parser = {G_command.message, G_command.message_length};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("generic preview: invalid Solana message\n");
        return io_send_sw(ApduReplySolanaInvalidMessage);
    }

    // The descriptor stream that follows reuses G_command.message, so the
    // transaction must be copied into the clear-signing context now.
    if (cs_transaction_begin(G_command.message, G_command.message_length) != 0) {
        PRINTF("generic preview: failed to buffer transaction\n");
        return io_send_sw(ApduReplySolanaInvalidGenericPreview);
    }

    PRINTF("generic preview: buffered %d-byte transaction, %d instructions\n",
           G_command.message_length,
           header.instructions_length);
    return io_send_sw(ApduReplySuccess);
}
