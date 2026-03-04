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

#include "handle_get_pubkey.h"
#include "sol/printer.h"
#include "nbgl_use_case.h"
#include "ui_api.h"
#include "apdu.h"
#include "io.h"

static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    if (confirm) {
        uint8_t tx = set_result_get_pubkey();
        io_send_response_pointer(G_io_apdu_buffer, tx, ApduReplySuccess);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_idle);
    } else {
        io_send_sw(ApduReplyUserRefusal);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_idle);
    }
}

void ui_get_public_key(void) {
    nbgl_useCaseAddressReview(G_publicKeyStr,
                              NULL,
                              &ICON_HOME,
                              "Verify Solana address",
                              NULL,
                              review_choice);
}
