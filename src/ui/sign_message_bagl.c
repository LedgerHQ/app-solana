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

static bool G_has_warning;

// Display dynamic transaction item screen
UX_STEP_NOCB_INIT(ux_summary_step,
                  bnnn_paging,
                  {
                      size_t step_index = G_ux.flow_stack[stack_slot].index;
                      if (G_has_warning) {
                          step_index -= 2;
                      }
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

UX_STEP_NOCB(ux_hook_warning_p1_step,
             pbb,
             {
                 &C_icon_warning,
                 "Transfer Hook",
                 "cannot be verified",
             });

UX_STEP_NOCB(ux_hook_warning_p2_step,
             nnnn,
             {
                 "A custom program in",
                 "this transaction may",
                 "lead to unexpected",
                 "behaviour.",
             });

UX_STEP_NOCB(ux_fee_warning_p1_step,
             pbb,
             {
                 &C_icon_warning,
                 "Token Extensions",
                 "cannot be verified",
             });

UX_STEP_NOCB(ux_fee_warning_p2_step,
             nnn,
             {
                 "It may lead to",
                 "additional fees upon",
                 "broadcast.",
             });

#define MAX_FLOW_STEPS_ONCHAIN                           \
    (2                               /* warning */       \
     + MAX_TRANSACTION_SUMMARY_ITEMS /* Items */         \
     + 1                             /* approve */       \
     + 1                             /* reject */        \
     + 1                             /* FLOW_END_STEP */ \
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

    bool fee_warning;
    bool hook_warning;
    transaction_summary_get_token_warnings(&fee_warning, &hook_warning);
    if (hook_warning) {
        G_has_warning = true;
        flow_steps[num_flow_steps++] = &ux_hook_warning_p1_step;
        flow_steps[num_flow_steps++] = &ux_hook_warning_p2_step;
    } else {
        if (fee_warning) {
            G_has_warning = true;
            flow_steps[num_flow_steps++] = &ux_fee_warning_p1_step;
            flow_steps[num_flow_steps++] = &ux_fee_warning_p2_step;
        } else {
            G_has_warning = false;
        }
    }
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
    G_has_warning = false;
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
