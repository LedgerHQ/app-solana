#ifdef HAVE_BAGL

#include "io_utils.h"
#include "utils.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "apdu.h"


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

UX_STEP_NOCB_INIT(ux_summary_step_extended,
                  bnnn_paging,
                  {
                      size_t step_index = G_ux.flow_stack[stack_slot].index;
                      if (transaction_summary_display_item(step_index, DisplayFlagNone)) {
                          THROW(ApduReplySolanaSummaryUpdateFailed);
                      }
                      G_ux.externalText = G_transaction_summary_extended_text;
                  },
                  {
                      .title = G_transaction_summary_title,
                      //Text is set into the global buffer G_ux in transaction summary
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

void start_ui_common_end(size_t* num_flow_steps ){
    flow_steps[(*num_flow_steps)++] = &ux_reject_step;
    flow_steps[(*num_flow_steps)++] = FLOW_END_STEP;

    ux_flow_init(0, flow_steps, NULL);
}

void start_sign_tx_ui(size_t num_summary_steps) {
    MEMCLEAR(flow_steps);
    size_t num_flow_steps = 0;
    for (size_t i = 0; i < num_summary_steps; i++) {
        flow_steps[num_flow_steps++] = &ux_summary_step;
    }

    flow_steps[num_flow_steps++] = &ux_approve_step;
    start_ui_common_end(&num_flow_steps);
}


void start_sign_offchain_message_ui(size_t num_summary_steps, const enum SummaryItemKind* summary_step_kinds) {
    MEMCLEAR(flow_steps);
    size_t num_flow_steps = 0;
    for (size_t i = 0; i < num_summary_steps; i++) {
        if(summary_step_kinds[i] == SummaryItemExtendedString){
            flow_steps[num_flow_steps++] = &ux_summary_step_extended;
        }else{
            flow_steps[num_flow_steps++] = &ux_summary_step;
        }
    }

    flow_steps[num_flow_steps++] = &ux_approve_step;
    start_ui_common_end(&num_flow_steps);
}

#endif
