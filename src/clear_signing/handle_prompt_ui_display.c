#include <os.h>
#include <string.h>

#include "handle_prompt_ui_display.h"
#include "cs_transaction.h"
#include "cs_merge_engine.h"
#include "cs_display_renderer.h"
#include "cs_instruction_template.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"
#include "ui_api.h"

int handle_prompt_ui_display(void) {
    PRINTF("handle_prompt_ui_display\n");

    int state_err = cs_check_state(CS_SESSION_FINALIZED);
    if (state_err != 0) {
        return io_send_sw(state_err);
    }

    if (G_command.instruction != InsPromptUiDisplay ||
        G_command.state != ApduStatePayloadComplete) {
        cs_transaction_reset();
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    if (cs_display_renderer_element_count() == 0) {
        PRINTF("prompt ui: no display elements produced\n");
        cs_transaction_reset();
        G_cs_session_state = CS_SESSION_IDLE;
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }

    // Signing is deferred to InsSignMessageDelayed
    G_command.is_preview_mode = true;
    ui_clear_signing_review();
    return 0;
}
