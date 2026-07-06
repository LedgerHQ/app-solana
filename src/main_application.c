/*******************************************************************************
 *   Ledger Blue
 *   (c) 2016 Ledger
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
 ********************************************************************************/

#include "utils.h"
#include "handle_get_pubkey.h"
#include "handle_sign_message.h"
#include "handle_sign_offchain_message.h"
#include "handle_sign_message_preview.h"
#include "handle_provide_instruction_descriptor.h"
#include "handle_get_challenge.h"
#include "handle_provide_trusted_info.h"
#include "handle_provide_dynamic_descriptor.h"
#ifdef HAVE_TRANSACTION_CHECKS
#include "handle_provide_transaction_check.h"
#endif
#include "apdu.h"
#include "ui_api.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "mem_utils.h"
#include "main_std_app.h"

// Swap feature
#include "swap_lib_calls.h"
#include "handle_swap_sign_transaction.h"
#include "handle_get_printable_amount.h"
#include "handle_check_address.h"

apdu_command_t G_command;

const internalStorage_t N_storage_real;

static void reset_main_globals(void) {
    MEMCLEAR(G_command);
    MEMCLEAR(G_io_seproxyhal_spi_buffer);
}

static int handle_apdu(int rx) {
    if (rx < 0) {
        return io_send_sw(ApduReplySdkExceptionIoOverflow);
    }

    const int ret = apdu_handle_message(G_io_apdu_buffer, rx, &G_command);
    if (ret != 0) {
        PRINTF("Clear received invalid command\n");
        MEMCLEAR(G_command);
        return io_send_sw(ret);
    }

    if (G_command.state == ApduStatePayloadInProgress) {
        PRINTF("Received first chunk of split payload\n");
        return io_send_sw(ApduReplySuccess);
    }

    if (G_command.instruction != InsSignMessageDelayed) {
        PRINTF("Clearing preview state for non-delayed sign instruction\n");
        clear_preview_state();
    }

    switch (G_command.instruction) {
        case InsDeprecatedGetAppConfiguration:
        case InsGetAppConfiguration: {
            size_t offset = 0;
            G_io_apdu_buffer[offset++] = N_storage.settings.allow_blind_sign;
            G_io_apdu_buffer[offset++] = N_storage.settings.pubkey_display;
            G_io_apdu_buffer[offset++] = MAJOR_VERSION;
            G_io_apdu_buffer[offset++] = MINOR_VERSION;
            G_io_apdu_buffer[offset++] = PATCH_VERSION;
#ifdef HAVE_TRANSACTION_CHECKS
            G_io_apdu_buffer[offset++] = N_storage.settings.tx_check_opt_in;
            G_io_apdu_buffer[offset++] = N_storage.settings.tx_check_enable;
#endif
            return io_send_response_pointer(G_io_apdu_buffer, offset, ApduReplySuccess);
        }

        case InsDeprecatedGetPubkey:
        case InsGetPubkey:
            return handle_get_pubkey();

        case InsDeprecatedSignMessage:
        case InsSignMessage:
            return handle_sign_message_parse_message();

        case InsSignMessagePreview:
            if (G_called_from_swap) {
                PRINTF("Preview mode not supported in swap context\n");
                return io_send_sw(ApduReplySdkNotSupported);
            }
            // Set preview flag and call same handler as message signing
            G_command.is_preview_mode = true;
            return handle_sign_message_parse_message();

        case InsSignMessageDelayed:
            return handle_sign_message_delayed();

        case InsSignOffchainMessage:
            return handle_sign_offchain_message();

        case InsTrustedInfoProvideInstructionDescriptor:
            return handle_provide_instruction_descriptor();

        case InsTrustedInfoGetChallenge:
            return handle_get_challenge();

        case InsTrustedInfoProvideInfo:
            return handle_provide_trusted_info();

        case InsTrustedInfoProvideDynamicDescriptor:
            return handle_provide_dynamic_descriptor();

#ifdef HAVE_TRANSACTION_CHECKS
        case InsProvideTransactionCheck:
            if (G_called_from_swap) {
                PRINTF("Transaction check mode not supported in swap context\n");
                return io_send_sw(ApduReplySdkNotSupported);
            }
            return handle_provide_transaction_check();
#endif

        default:
            // Should have been caught by apdu_handle_message
            PRINTF("Received unknown instruction %d\n", G_command.instruction);
            return io_send_sw(ApduReplyUnimplementedInstruction);
    }
}

void nv_app_state_init() {
    if (N_storage.initialized != 0x01) {
        internalStorage_t storage;
        storage.settings.allow_blind_sign = BlindSignDisabled;
        storage.settings.pubkey_display = PubkeyDisplayLong;
        storage.settings.display_mode = DisplayModeUser;
#ifdef HAVE_TRANSACTION_CHECKS
        storage.settings.tx_check_enable = 0;
        storage.settings.tx_check_opt_in = 0;
#endif
        storage.initialized = 0x01;
        nvm_write((void *) &N_storage, (void *) &storage, sizeof(internalStorage_t));
    }
}

void app_main(void) {
    int input_len = 0;

    if (app_mem_init() != 0) {
        PRINTF("FATAL: Memory initialization failed\n");
        app_exit();
    }

    // Stores the information about the current command. Some commands expect
    // multiple APDUs before they become complete and executed.
    reset_getpubkey_globals();
    reset_main_globals();
    clear_preview_state();

    // to prevent it from having a fixed value at boot
    roll_challenge();

    if (!G_called_from_swap) {
        ui_idle();
    }

    nv_app_state_init();

    io_init();

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        // Receive command bytes in G_io_apdu_buffer
        if ((input_len = io_recv_command()) < 0) {
            PRINTF("=> io_recv_command failure\n");
            return;
        }

        if (input_len == 0) {
            io_send_sw(ApduReplyNoApduReceived);
            continue;
        }

        PRINTF("New APDU received:\n%.*H\n", input_len, G_io_apdu_buffer);

        if (handle_apdu(input_len) < 0) {
            // The handler itself has failed, most likely due to IO error. We don't even try to
            // recover from this.
            PRINTF("=> FATAL handle_apdu failure\n");
            return;
        }
    }
}
