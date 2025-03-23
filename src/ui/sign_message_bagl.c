#ifdef HAVE_BAGL

#include "io_utils.h"
#include "utils.h"
#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "apdu.h"

#include "handle_sign_message.h"

// Display offchain message screen
UX_STEP_NOCB(ux_sign_msg_text_step,
             bnnn_paging,
             {
                 .title = "Message",
                 .text = (const char *) G_command.message + OFFCHAIN_MESSAGE_HEADER_LENGTH,
             });

// Display dynamic transaction item screen
UX_STEP_NOCB_INIT(ux_summary_step,
                  bnnn_paging,
                  {
                      size_t step_index = G_ux.flow_stack[stack_slot].index;
                      enum DisplayFlags flags = DisplayFlagNone;
                      if (N_storage.settings.pubkey_display == PubkeyDisplayLong) {
                          flags |= DisplayFlagLongPubkeys;
                      }
                      if (transaction_summary_display_item(step_index, flags)) {
                          THROW(ApduReplySolanaSummaryUpdateFailed);
                      }
                  },
                  {
                      .title = G_transaction_summary_title,
                      .text = G_transaction_summary_text,
                  });

// Approve and sign screen
UX_STEP_CB(ux_approve_step,
           pb,
           sendResponse(set_result_sign_message(), ApduReplySuccess, true),
           {
               &C_icon_validate_14,
               "Approve",
           });

// Reject signature screen
UX_STEP_CB(ux_reject_step,
           pb,
           sendResponse(0, ApduReplyUserRefusal, true),
           {
               &C_icon_crossmark,
               "Reject",
           });

#define MAX_FLOW_STEPS_ONCHAIN                             \
    (MAX_TRANSACTION_SUMMARY_ITEMS + 1 /* approve */       \
     + 1                               /* reject */        \
     + 1                               /* FLOW_END_STEP */ \
    )
/*
OFFCHAIN UX Steps:
- Sign Message

if expert mode:
- Version
- Format
- Size
- Hash
- Signer
else if utf8:
- Hash

if ascii:
- message text
*/
#define MAX_FLOW_STEPS_OFFCHAIN \
    (7 + 1 /* approve */        \
     + 1   /* reject */         \
     + 1   /* FLOW_END_STEP */  \
    )
static ux_flow_step_t const *flow_steps[MAX(MAX_FLOW_STEPS_ONCHAIN, MAX_FLOW_STEPS_OFFCHAIN)];

void start_sign_tx_ui(size_t num_summary_steps) {
    MEMCLEAR(flow_steps);
    size_t num_flow_steps = 0;
    for (size_t i = 0; i < num_summary_steps; i++) {
        flow_steps[num_flow_steps++] = &ux_summary_step;
    }

    flow_steps[num_flow_steps++] = &ux_approve_step;
    flow_steps[num_flow_steps++] = &ux_reject_step;
    flow_steps[num_flow_steps++] = FLOW_END_STEP;

    ux_flow_init(0, flow_steps, NULL);
}

void start_sign_offchain_message_ui(bool is_ascii, size_t num_summary_steps) {
    MEMCLEAR(flow_steps);
    size_t num_flow_steps = 0;
    for (size_t i = 0; i < num_summary_steps; i++) {
        flow_steps[num_flow_steps++] = &ux_summary_step;
    }
    if (is_ascii) {
        flow_steps[num_flow_steps++] = &ux_sign_msg_text_step;
    }
    flow_steps[num_flow_steps++] = &ux_approve_step;
    flow_steps[num_flow_steps++] = &ux_reject_step;
    flow_steps[num_flow_steps++] = FLOW_END_STEP;

    ux_flow_init(0, flow_steps, NULL);
}

#endif