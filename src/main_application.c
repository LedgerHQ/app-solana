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
#include "handle_provide_instruction_descriptor.h"
#include "handle_get_challenge.h"
#include "handle_provide_trusted_info.h"
#include "handle_provide_dynamic_descriptor.h"
#include "apdu.h"
#include "ui_api.h"
#include "nbgl_use_case.h"

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

void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx, int rx) {
    if (!flags || !tx) {
        THROW(ApduReplySdkInvalidParameter);
    }

    if (rx < 0) {
        THROW(ApduReplySdkExceptionIoOverflow);
    }

    const int ret = apdu_handle_message(G_io_apdu_buffer, rx, &G_command);
    if (ret != 0) {
        PRINTF("Clear received invalid command\n");
        MEMCLEAR(G_command);
        THROW(ret);
    }

    if (G_command.state == ApduStatePayloadInProgress) {
        PRINTF("Received first chunk of split payload\n");
        THROW(ApduReplySuccess);
    }

    switch (G_command.instruction) {
        case InsDeprecatedGetAppConfiguration:
        case InsGetAppConfiguration:
            G_io_apdu_buffer[0] = N_storage.settings.allow_blind_sign;
            G_io_apdu_buffer[1] = N_storage.settings.pubkey_display;
            G_io_apdu_buffer[2] = MAJOR_VERSION;
            G_io_apdu_buffer[3] = MINOR_VERSION;
            G_io_apdu_buffer[4] = PATCH_VERSION;
            *tx = 5;
            THROW(ApduReplySuccess);

        case InsDeprecatedGetPubkey:
        case InsGetPubkey:
            handle_get_pubkey(flags, tx);
            break;

        case InsDeprecatedSignMessage:
        case InsSignMessage:
            handle_sign_message_parse_message(flags, tx);
            break;

        case InsSignOffchainMessage:
            handle_sign_offchain_message(flags, tx);
            break;

        case InsTrustedInfoProvideInstructionDescriptor:
            handle_provide_instruction_descriptor();
            break;

        case InsTrustedInfoGetChallenge:
            handle_get_challenge(tx);
            break;

        case InsTrustedInfoProvideInfo:
            handle_provide_trusted_info();
            break;

        case InsTrustedInfoProvideDynamicDescriptor:
            handle_provide_dynamic_descriptor();
            break;

        default:
            // Should have been caught by apdu_handle_message
            PRINTF("Received unknown instruction %d\n", G_command.instruction);
            THROW(ApduReplyUnimplementedInstruction);
    }
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

void nv_app_state_init() {
    if (N_storage.initialized != 0x01) {
        internalStorage_t storage;
        storage.settings.allow_blind_sign = BlindSignDisabled;
        storage.settings.pubkey_display = PubkeyDisplayLong;
        storage.settings.display_mode = DisplayModeUser;
        storage.initialized = 0x01;
        nvm_write((void *) &N_storage, (void *) &storage, sizeof(internalStorage_t));
    }
}

void app_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // Stores the information about the current command. Some commands expect
    // multiple APDUs before they become complete and executed.
    reset_getpubkey_globals();
    reset_main_globals();

    // to prevent it from having a fixed value at boot
    roll_challenge();

    if (!G_called_from_swap) {
        ui_idle();
    }

    nv_app_state_init();

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;
        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0;  // ensure no race in catch_other if io_exchange throws
                         // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(ApduReplyNoApduReceived);
                }

                PRINTF("New APDU received:\n%.*H\n", rx, G_io_apdu_buffer);

                handleApdu(&flags, &tx, rx);
            }
            CATCH(ApduReplySdkExceptionIoReset) {
                THROW(ApduReplySdkExceptionIoReset);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                    case 0x6000:
                        sw = e;
                        break;
                    case 0x9000:
                        // All is well
                        sw = e;
                        break;
                    default:
                        // Internal error
                        sw = 0x6800 | (e & 0x7FF);
                        break;
                }
                if (e != 0x9000) {
                    flags &= ~IO_ASYNCH_REPLY;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}
