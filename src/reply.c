#include "reply.h"

#include <os.h>
#include "io.h"
#include "apdu.h"
#include "clear_signing/cs_transaction.h"
#include "handle_sign_message_preview.h"
#include "trusted_info.h"
#include "dynamic_token_info.h"
#ifdef HAVE_TRANSACTION_CHECKS
#include "handle_provide_transaction_check.h"
#endif

// Teardown performed just before every reply. A mid-assembly chunk ACK (success while the payload
// is still in progress) keeps its buffer; every other reply releases it. An error reply also
// abandons the whole signing session: the clear-signing session, the token-metadata pools the
// sign would have consumed, and the delayed-sign fingerprint.
static void pre_send_teardown(uint16_t sw) {
    if (sw != ApduReplySuccess || G_command.state != ApduStatePayloadInProgress) {
        apdu_free_message(&G_command);
    }
    if (sw != ApduReplySuccess) {
        PRINTF("reply error 0x%04x: abandoning signing session\n", sw);
        cs_session_reset();
        reset_trusted_info();
        reset_dynamic_token_info();
#ifdef HAVE_TRANSACTION_CHECKS
        clear_transaction_check();
#endif
        clear_preview_state();
    }
}

int reply_sw(uint16_t sw) {
    pre_send_teardown(sw);
    return io_send_sw(sw);
}

int reply_data(const uint8_t *rdata, size_t rdata_len, uint16_t sw) {
    pre_send_teardown(sw);
    return io_send_response_pointer(rdata, rdata_len, sw);
}
