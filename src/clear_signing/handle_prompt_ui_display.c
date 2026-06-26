#include <os.h>
#include <string.h>

#include "handle_prompt_ui_display.h"
#include "clear_signing_context.h"
#include "cs_instruction_template.h"
#include "apdu.h"
#include "globals.h"
#include "io.h"

int handle_prompt_ui_display(void) {
    PRINTF("handle_prompt_ui_display\n");

    if (G_command.instruction != InsPromptUiDisplay ||
        G_command.state != ApduStatePayloadComplete) {
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    if (G_clear_signing_context == NULL) {
        PRINTF("prompt ui: no clear-signing context\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (!G_clear_signing_context->finalized) {
        PRINTF("prompt ui: session not finalized\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }

    // TODO: run merge engine + display review UI
    clear_signing_context_reset();
    return io_send_sw(ApduReplySuccess);
}
