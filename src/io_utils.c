/*****************************************************************************
 *   Ledger App Solana.
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

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "ux.h"

#include "apdu.h"
#include "ui_api.h"
#include "handle_swap_sign_transaction.h"
#include "io_utils.h"

static void write_u16_be(uint8_t *ptr, size_t offset, uint16_t value) {
    ptr[offset + 0] = (uint8_t) (value >> 8);
    ptr[offset + 1] = (uint8_t) (value >> 0);
}

void sendResponse(uint8_t tx, uint16_t sw, bool display_menu) {
    // Write status word
    write_u16_be(G_io_apdu_buffer, tx, sw);
    tx += 2;

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

    // If started in swap mode and one TX request has been processed (success or fail),
    // we quit the app after sending the status reply
    if (G_called_from_swap && G_swap_response_ready) {
        PRINTF("Quitting app started in swap mode\n");
        // Quit app, we are in limited mode and our work is done
        finalize_exchange_sign_transaction(sw == ApduReplySuccess);
    }

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }
}
