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
#include "clear_signing/handle_provide_instruction_info.h"
#include "clear_signing/handle_provide_instruction_substructure.h"
#include "clear_signing/handle_provide_enum_variant.h"
#include "clear_signing/handle_provide_token_account_state.h"
#include "clear_signing/handle_provide_alt_resolution.h"
#include "clear_signing/handle_provide_trusted_name.h"
#include "clear_signing/handle_start_generic_clear_signing_session.h"
#include "clear_signing/handle_finalize_generic_clear_signing.h"
#include "clear_signing/handle_prompt_ui_display.h"
#include "clear_signing/cs_transaction.h"
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
#include "reply.h"

apdu_command_t G_command;
cs_session_state_t G_cs_session_state;

const internalStorage_t N_storage_real;

static void reset_main_globals(void) {
    apdu_reset_command(&G_command);
    MEMCLEAR(G_io_seproxyhal_spi_buffer);
    G_cs_session_state = CS_SESSION_IDLE;
}

void reset_unrelated_sessions(uint8_t instruction) {
    if (instruction != InsSignMessageDelayed) {
        clear_preview_state();
    }

    // Any non-CS, non-stateless APDU resets an active CS session.
    // The delayed signing instruction DOES reset the CS session: InsPromptUiDisplay already stored
    // the validated fingerprint in the delayed signing storage, so the CS session is over.
    if (G_cs_session_state != CS_SESSION_IDLE
        // CS instructions
        && instruction != InsStartGenericClearSigningSession &&
        instruction != InsProvideInstructionInfo &&
        instruction != InsProvideInstructionSubstructure && instruction != InsProvideEnumVariant &&
        instruction != InsProvideTokenAccountState && instruction != InsProvideAltResolution &&
        instruction != InsProvideTrustedName && instruction != InsFinalizeGenericClearSigning &&
        instruction != InsPromptUiDisplay

        // Token CAL info
        && instruction != InsTrustedInfoGetChallenge && instruction != InsTrustedInfoProvideInfo &&
        instruction != InsTrustedInfoProvideDynamicDescriptor

        // Stateless queries: they answer from the seed or from settings and touch no
        // signing state, so a session parked mid-stream survives them untouched.
        && instruction != InsGetPubkey && instruction != InsDeprecatedGetPubkey &&
        instruction != InsGetAppConfiguration && instruction != InsDeprecatedGetAppConfiguration) {
        cs_session_reset();
    }
}

static int handle_apdu(int rx) {
    if (rx < 0) {
        return reply_sw(ApduReplySdkExceptionIoOverflow);
    }

    const int ret = apdu_handle_message(G_io_apdu_buffer, rx, &G_command);
    if (ret != 0) {
        PRINTF("Clear received invalid command\n");
        apdu_reset_command(&G_command);
        return reply_sw(ret);
    }

    if (G_command.state == ApduStatePayloadInProgress) {
        PRINTF("Received first chunk of split payload\n");
        return reply_sw(ApduReplySuccess);
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
            return reply_data(G_io_apdu_buffer, offset, ApduReplySuccess);
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
                return reply_sw(ApduReplySdkNotSupported);
            }
            G_command.is_preview_mode = true;
            return handle_sign_message_parse_message();

        case InsSignMessageDelayed:
            // This instruction is called after both InsSignMessagePreview and InsPromptUiDisplay
            if (G_called_from_swap) {
                PRINTF("Delayed signing is not supported in swap context\n");
                return reply_sw(ApduReplySdkNotSupported);
            }
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
                return reply_sw(ApduReplySdkNotSupported);
            }
            return handle_provide_transaction_check();
#endif

        case InsStartGenericClearSigningSession:
            if (G_called_from_swap) {
                PRINTF("Start generic clear signing session not supported in swap context\n");
                return reply_sw(ApduReplySdkNotSupported);
            }
            return handle_start_generic_clear_signing_session();
        case InsProvideInstructionInfo:
            return handle_provide_instruction_info();

        case InsProvideInstructionSubstructure:
            return handle_provide_instruction_substructure();

        case InsProvideEnumVariant:
            return handle_provide_enum_variant();

        case InsProvideTokenAccountState:
            return handle_provide_token_account_state();

        case InsProvideAltResolution:
            return handle_provide_alt_resolution();

        case InsProvideTrustedName:
            return handle_provide_trusted_name();

        case InsPromptUiDisplay:
            if (G_called_from_swap) {
                PRINTF("Prompt UI display not supported in swap context\n");
                return reply_sw(ApduReplySdkNotSupported);
            }
            return handle_prompt_ui_display();

        case InsFinalizeGenericClearSigning:
            if (G_called_from_swap) {
                PRINTF("Finalize generic clear signing not supported in swap context\n");
                return reply_sw(ApduReplySdkNotSupported);
            }
            return handle_finalize_generic_clear_signing();

        default:
            // Should have been caught by apdu_handle_message
            PRINTF("Received unknown instruction %d\n", G_command.instruction);
            return reply_sw(ApduReplyUnimplementedInstruction);
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
            reply_sw(ApduReplyNoApduReceived);
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
