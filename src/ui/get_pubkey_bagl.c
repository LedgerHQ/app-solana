
/*****************************************************************************
 *   Ledger App Solana
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifdef HAVE_BAGL

#include "handle_get_pubkey.h"
#include "apdu.h"
#include "io_utils.h"
#include "ux.h"

UX_STEP_NOCB(ux_display_public_flow_5_step,
             bnnn_paging,
             {
                 .title = "Pubkey",
                 .text = G_publicKeyStr,
             });
UX_STEP_CB(ux_display_public_flow_6_step,
           pb,
           sendResponse(set_result_get_pubkey(), ApduReplySuccess, true),
           {
               &C_icon_validate_14,
               "Approve",
           });
UX_STEP_CB(ux_display_public_flow_7_step,
           pb,
           sendResponse(0, ApduReplyUserRefusal, true),
           {
               &C_icon_crossmark,
               "Reject",
           });

UX_FLOW(ux_display_public_flow,
        &ux_display_public_flow_5_step,
        &ux_display_public_flow_6_step,
        &ux_display_public_flow_7_step);

void ui_get_public_key(void) {
    ux_flow_init(0, ux_display_public_flow, NULL);
}

#endif
