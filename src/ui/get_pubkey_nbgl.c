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

#ifdef HAVE_NBGL

#include "handle_get_pubkey.h"
#include "io_utils.h"
#include "sol/printer.h"
#include "nbgl_use_case.h"
#include "ui_api.h"
#include "apdu.h"

static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    if (confirm) {
        sendResponse(set_result_get_pubkey(), ApduReplySuccess, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_idle);
    } else {
        sendResponse(0, ApduReplyUserRefusal, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_idle);
    }
}

void ui_get_public_key(void) {
    nbgl_useCaseAddressReview(G_publicKeyStr,
                              NULL,
                              &C_icon_solana_64x64,
                              "Verify Solana address",
                              NULL,
                              review_choice);
}

#endif
