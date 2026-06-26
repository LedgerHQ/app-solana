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

int handle_prompt_ui_display(void) {
    PRINTF("handle_prompt_ui_display\n");

    if (G_command.instruction != InsPromptUiDisplay ||
        G_command.state != ApduStatePayloadComplete) {
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    if (G_cs_transaction == NULL) {
        PRINTF("prompt ui: no clear-signing context\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (!cs_merge_engine_finalized()) {
        PRINTF("prompt ui: session not finalized\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }
    if (cs_display_renderer_element_count() == 0) {
        PRINTF("prompt ui: no display elements produced\n");
        return io_send_sw(ApduReplySolanaClearSigningIncomplete);
    }

    // TODO: display review UI using cs_display_renderer_element(i)
    cs_transaction_reset();
    return io_send_sw(ApduReplySuccess);
}
