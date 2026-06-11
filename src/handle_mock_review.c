#include "handle_mock_review.h"
#include "apdu.h"
#include "ui_api.h"
#include "io.h"

int handle_mock_review(void) {
    PRINTF("handle_mock_review entered\n");
    if (G_command.message_length != 2) {
        PRINTF("Invalid mock review payload length %d\n", G_command.message_length);
        return io_send_sw(ApduReplySolanaInvalidMessageSize);
    }
    uint8_t contract = G_command.message[0];
    uint8_t version = G_command.message[1];
    ui_mock_review(contract, version);
    return 0;
}
