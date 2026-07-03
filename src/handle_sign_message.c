#include "utils.h"
#include "handle_swap_sign_transaction.h"
#include "swap_common.h"
#include "swap_error_code_helpers.h"
#include "handle_provide_instruction_descriptor.h"

#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "trusted_info.h"
#include "dynamic_token_info.h"
#include "ed25519_helpers.h"

#include "handle_sign_message.h"
#include "handle_provide_instruction_descriptor.h"
#include "ui_api.h"
#include "io.h"

// Accept amount + recipient (+ fees)
static bool check_swap_validity_native(const SummaryItemKind_t kinds[MAX_TRANSACTION_SUMMARY_ITEMS],
                                       size_t num_summary_steps) {
    bool amount_ok = false;
    bool recipient_ok = false;
    uint8_t expected_steps = 2;

    // Accept base step number + optional fee step
    if (num_summary_steps != expected_steps && num_summary_steps != expected_steps + 1) {
        PRINTF("%d steps expected for transaction in swap context, not %u\n",
               expected_steps,
               num_summary_steps);
        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                    SWAP_EC_ERROR_WRONG_METHOD,
                                    SWAP_EC_APP_GENERIC,
                                    "%d steps expected, got %u",
                                    expected_steps,
                                    num_summary_steps);
    }

    for (size_t i = 0; i < num_summary_steps; ++i) {
        transaction_summary_display_item(i, DisplayFlagNone | DisplayFlagLongPubkeys);
        PRINTF("Item (%d) '%s', '%s'\n",
               kinds[i],
               G_transaction_summary_title,
               G_transaction_summary_text);
        switch (kinds[i]) {
            case SummaryItemAmount:
                if (strcmp(G_transaction_summary_title, "Max fees") == 0) {
                    if (!check_swap_fee(G_transaction_summary_text)) {
                        PRINTF("check_swap_fee failed\n");
                        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                    SWAP_EC_ERROR_WRONG_FEES,
                                                    SWAP_EC_APP_GENERIC,
                                                    "Fee mismatch: %s",
                                                    G_transaction_summary_text);
                    }
                } else if (strcmp(G_transaction_summary_title, "Amount") == 0) {
                    if (!check_swap_amount(G_transaction_summary_text)) {
                        PRINTF("check_swap_amount failed\n");
                        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                    SWAP_EC_ERROR_WRONG_AMOUNT,
                                                    SWAP_EC_APP_GENERIC,
                                                    "Amount mismatch: %s",
                                                    G_transaction_summary_text);
                    }
                } else {
                    PRINTF("Refused title '%s', expecting '%s'\n",
                           G_transaction_summary_title,
                           "Amount");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_AMOUNT,
                                                SWAP_EC_APP_GENERIC,
                                                "Unexpected amount title: %s",
                                                G_transaction_summary_title);
                }
                amount_ok = true;
                break;

            case SummaryItemPubkey:
                if (strcmp(G_transaction_summary_title, "To") != 0) {
                    PRINTF("Refused title '%s', expecting '%s'\n",
                           G_transaction_summary_title,
                           "To");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_DESTINATION,
                                                SWAP_EC_APP_GENERIC,
                                                "Unexpected pubkey title: %s",
                                                G_transaction_summary_title);
                }
                if (!check_swap_recipient(G_transaction_summary_text)) {
                    PRINTF("check_swap_recipient failed\n");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_DESTINATION,
                                                SWAP_EC_APP_GENERIC,
                                                "Recipient mismatch: %s",
                                                G_transaction_summary_text);
                }
                recipient_ok = true;
                break;

            default:
                PRINTF("Refused kind '%u'\n", kinds[i]);
                send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                            SWAP_EC_ERROR_WRONG_METHOD,
                                            SWAP_EC_APP_GENERIC,
                                            "Unexpected summary kind: %u",
                                            kinds[i]);
        }
    }
    if (!amount_ok || !recipient_ok) {
        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                    SWAP_EC_ERROR_WRONG_METHOD,
                                    SWAP_EC_APP_GENERIC,
                                    "Missing fields: amount=%d recipient=%d",
                                    amount_ok,
                                    recipient_ok);
    }

    // Reaching here means all checks passed
    return true;
}

// Accept token amount + SOL recipient + mint + from + ATA recipient (+ fees)
static bool check_swap_validity_token(const SummaryItemKind_t kinds[MAX_TRANSACTION_SUMMARY_ITEMS],
                                      size_t num_summary_steps,
                                      bool is_token_2022) {
    bool amount_ok = false;
    bool mint_ok = false;
    bool dest_ata_ok = false;
    bool dest_sol_address_ok = false;
    bool create_token_account_received = false;

    if (g_trusted_info == NULL || !g_trusted_info->received) {
        // This case should never happen because this is already checked at TX parsing
        PRINTF("Descriptor info is required for a SPL transfer\n");
        send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                               SWAP_EC_ERROR_GENERIC,
                               SWAP_EC_APP_DESCRIPTOR_INFO_MISSING);
    }
    if (!validate_associated_token_address(g_trusted_info->owner_address,
                                           g_trusted_info->mint_address,
                                           g_trusted_info->token_address,
                                           is_token_2022)) {
        // This case should never happen because this is already checked at TX parsing
        PRINTF("Failed to validate ATA\n");
        send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                               SWAP_EC_ERROR_GENERIC,
                               SWAP_EC_APP_ATA_VALIDATION_FAILED);
    }

    for (size_t i = 0; i < num_summary_steps; ++i) {
        transaction_summary_display_item(i, DisplayFlagNone | DisplayFlagLongPubkeys);
        PRINTF("Item (%d) '%s', '%s'\n",
               kinds[i],
               G_transaction_summary_title,
               G_transaction_summary_text);
        switch (kinds[i]) {
            case SummaryItemTokenAmount:
                if (strcmp(G_transaction_summary_title, "Amount") != 0) {
                    PRINTF("Refused title '%s', expecting '%s'\n",
                           G_transaction_summary_title,
                           "Amount");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_METHOD,
                                                SWAP_EC_APP_GENERIC,
                                                "Unexpected token amount title: %s",
                                                G_transaction_summary_title);
                }
                if (!check_swap_amount(G_transaction_summary_text)) {
                    PRINTF("check_swap_amount failed\n");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_AMOUNT,
                                                SWAP_EC_APP_GENERIC,
                                                "Token amount mismatch: %s",
                                                G_transaction_summary_text);
                }
                if (amount_ok) {
                    PRINTF("We have already parsed an amount, refusing signing multiple\n");
                    send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                           SWAP_EC_ERROR_WRONG_METHOD,
                                           SWAP_EC_APP_DUPLICATE_AMOUNT);
                }
                amount_ok = true;
                break;

            case SummaryItemAmount:
                if (strcmp(G_transaction_summary_title, "Max fees") == 0) {
                    if (!check_swap_fee(G_transaction_summary_text)) {
                        PRINTF("check_swap_fee failed\n");
                        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                    SWAP_EC_ERROR_WRONG_FEES,
                                                    SWAP_EC_APP_GENERIC,
                                                    "Token fee mismatch: %s",
                                                    G_transaction_summary_text);
                    }
                } else {
                    PRINTF("Refusing non fee amount in token swap context\n");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_METHOD,
                                                SWAP_EC_APP_GENERIC,
                                                "Non-fee amount in token swap: %s",
                                                G_transaction_summary_title);
                }
                break;

            case SummaryItemPubkey:
                if (strcmp(G_transaction_summary_title, "Create token account") == 0) {
                    if (strcmp(g_trusted_info->encoded_token_address, G_transaction_summary_text) !=
                        0) {
                        PRINTF("Create ATA address does not match with address in descriptor\n");
                        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                    SWAP_EC_ERROR_WRONG_METHOD,
                                                    SWAP_EC_APP_GENERIC,
                                                    "Create ATA address mismatch: %s",
                                                    G_transaction_summary_text);
                    }
                    create_token_account_received = true;
                } else if (strcmp(G_transaction_summary_title, "For") == 0) {
                    if (!create_token_account_received) {
                        PRINTF("'For' received out of create_token_account context\n");
                        send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                               SWAP_EC_ERROR_WRONG_METHOD,
                                               SWAP_EC_APP_UNEXPECTED_TOKEN_CONTEXT);
                    }
                    break;
                } else if (strcmp(G_transaction_summary_title, "Funded by") == 0) {
                    if (!create_token_account_received) {
                        PRINTF("'Funded by' received out of create_token_account context\n");
                        send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                               SWAP_EC_ERROR_WRONG_METHOD,
                                               SWAP_EC_APP_UNEXPECTED_TOKEN_CONTEXT);
                    }
                    break;
                } else if (strcmp(G_transaction_summary_title, "Token address") == 0) {
                    // MINT
                    if (strcmp(g_trusted_info->encoded_mint_address, G_transaction_summary_text) !=
                        0) {
                        // This case should never happen because this is already checked at TX
                        // parsing
                        PRINTF("Mint address does not match with mint address in descriptor\n");
                        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                    SWAP_EC_ERROR_GENERIC,
                                                    SWAP_EC_APP_GENERIC,
                                                    "Mint address mismatch: %s",
                                                    G_transaction_summary_text);
                    }
                    mint_ok = true;
                } else if (strcmp(G_transaction_summary_title, "From (token account)") == 0) {
                    // SRC ACCOUNT
                    break;
                } else if (strcmp(G_transaction_summary_title, "To (token account)") == 0) {
                    // Destination ATA
                    if (strcmp(g_trusted_info->encoded_token_address, G_transaction_summary_text) !=
                        0) {
                        // This case should never happen because this is already checked at TX
                        // parsing
                        PRINTF("Dest ATA address does not match with ATA in descriptor\n");
                        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                    SWAP_EC_ERROR_WRONG_DESTINATION,
                                                    SWAP_EC_APP_GENERIC,
                                                    "Dest ATA mismatch: %s",
                                                    G_transaction_summary_text);
                    }
                    dest_ata_ok = true;
                }
                break;

            case SummaryItemString:
                if (strcmp(G_transaction_summary_title, "To") != 0) {
                    PRINTF("Refuse string item != 'To'\n");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_METHOD,
                                                SWAP_EC_APP_GENERIC,
                                                "Unexpected string title: %s",
                                                G_transaction_summary_title);
                }
                if (strcmp(g_trusted_info->encoded_owner_address, G_transaction_summary_text) !=
                    0) {
                    // This case should never happen because this is already checked at TX parsing
                    PRINTF("Dest SOL address does not match with SOL address in descriptor\n");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_DESTINATION,
                                                SWAP_EC_APP_GENERIC,
                                                "Dest SOL address mismatch: %s",
                                                G_transaction_summary_text);
                }
                if (!check_swap_recipient(G_transaction_summary_text)) {
                    PRINTF("check_swap_recipient failed\n");
                    send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                                SWAP_EC_ERROR_WRONG_DESTINATION,
                                                SWAP_EC_APP_GENERIC,
                                                "Token recipient mismatch: %s",
                                                G_transaction_summary_text);
                }
                dest_sol_address_ok = true;
                break;

            default:
                PRINTF("Refused kind '%u'\n", kinds[i]);
                send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                            SWAP_EC_ERROR_WRONG_METHOD,
                                            SWAP_EC_APP_GENERIC,
                                            "Unexpected token summary kind: %u",
                                            kinds[i]);
        }
    }

    // All expected elements should have been received and validated
    PRINTF("amount_ok = %d\nmint_ok = %d\ndest_ata_ok = %d\ndest_sol_address_ok = %d\n",
           amount_ok,
           mint_ok,
           dest_ata_ok,
           dest_sol_address_ok);
    if (!amount_ok || !mint_ok || !dest_ata_ok || !dest_sol_address_ok) {
        send_swap_error_with_string(ApduReplySolanaSummaryFinalizeFailed,
                                    SWAP_EC_ERROR_GENERIC,
                                    SWAP_EC_APP_GENERIC,
                                    "Missing token fields: amount=%d mint=%d ata=%d sol_addr=%d",
                                    amount_ok,
                                    mint_ok,
                                    dest_ata_ok,
                                    dest_sol_address_ok);
    }

    // Reaching here means all checks passed
    return true;
}

static bool check_swap_validity(const SummaryItemKind_t kinds[MAX_TRANSACTION_SUMMARY_ITEMS],
                                size_t num_summary_steps) {
    // Check if we're in error mode due to invalid swap protocol
    swap_mode_t swap_mode = get_swap_mode();
    if (swap_mode == SWAP_MODE_ERROR) {
        PRINTF("Swap mode error - invalid or unknown swap protocol\n");
        send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                               SWAP_EC_ERROR_CROSSCHAIN_WRONG_MODE,
                               SWAP_EC_APP_INVALID_SWAP_PROTOCOL);
    } else if (swap_mode == SWAP_MODE_CROSSCHAIN) {
        PRINTF("Error, this function is for standard swap checking\n");
        send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                               SWAP_EC_ERROR_WRONG_METHOD,
                               SWAP_EC_APP_CROSSCHAIN_IN_STANDARD_CHECK);
    }

    if (is_token_transaction()) {
        bool is_token_2022;
        transaction_summary_get_is_token_2022_transfer(&is_token_2022);
        if (is_token_2022) {
            bool unknonw_transfer_fees;
            bool has_transfer_hook;
            transaction_summary_get_token_warnings(&unknonw_transfer_fees, &has_transfer_hook);
            if (unknonw_transfer_fees) {
                PRINTF(
                    "TransferChecked refused in swap context, TransferCheckedWithFees required\n");
                send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                       SWAP_EC_ERROR_WRONG_METHOD,
                                       SWAP_EC_APP_TRANSFER_CHECKED_WITH_FEES_REQUIRED);
            }
            if (has_transfer_hook) {
                PRINTF("Transaction with transfer hook refused\n");
                send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                       SWAP_EC_ERROR_WRONG_METHOD,
                                       SWAP_EC_APP_TRANSFER_HOOK_REFUSED);
            }
        }
        return check_swap_validity_token(kinds, num_summary_steps, is_token_2022);
    } else {
        return check_swap_validity_native(kinds, num_summary_steps);
    }
}

// Safe wrapper around signing
void __attribute__((noreturn)) swap_finalize(void) {
    if (G_swap_response_ready) {
        // Safety against trying to make the app sign multiple TX
        // This code should never be triggered as the app is supposed to exit after
        // sending the signed transaction
        PRINTF("Safety against double signing triggered\n");
        os_sched_exit(-1);
    } else {
        // We will quit the app after this transaction
        PRINTF("Swap response is ready, the app will quit after the next send\n");
        G_swap_response_ready = true;
    }

    PRINTF("Valid swap transaction received, signing and replying it\n");
    int tx_len = set_result_sign_message();
    if (tx_len <= 0) {
        // Unrealistic case but let's handle it gracefully just in case
        PRINTF("set_result_sign_message failed, sending error\n");
        send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                               SWAP_EC_ERROR_INTERNAL,
                               SWAP_EC_APP_GENERIC);
    }
    io_send_response_pointer(G_io_apdu_buffer, tx_len, ApduReplySuccess);

    // Unreachable, io_send_response_pointer should have returned to Exchange
    os_sched_exit(-1);
}

static int handle_sign_message_ui(void) {
    // Display the transaction summary
    SummaryItemKind_t summary_step_kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_summary_steps = 0;
    if (transaction_summary_finalize(summary_step_kinds, &num_summary_steps) != 0) {
        PRINTF("Error transaction_summary_finalize failed\n");
        // In theory all errors should have been caught at parsing step, not at finalize step
        // But let's handle it gracefully just in case
        return ApduReplySolanaSummaryFinalizeFailed;
    }

    // If we are in swap context, do not redisplay the message data
    // Instead, ensure they are identical with what was previously displayed
    if (G_called_from_swap) {
        if (G_command.is_preview_mode) {
            // Should have been caught at instruction parsing step but let's be safe
            PRINTF("Preview mode not supported in swap context\n");
            send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                   SWAP_EC_ERROR_WRONG_METHOD,
                                   SWAP_EC_APP_PREVIEW_NOT_SUPPORTED);
        }

        if (check_swap_validity(summary_step_kinds, num_summary_steps)) {
            PRINTF("Swap transaction summary validated successfully\n");
            // Reaching here means validation passed
            swap_finalize();
        }
        // check_swap_validity exits back to Exchange on error so this code is unreachable in theory
        os_sched_exit(-1);
    } else {
        // We have been started from the dashboard, prompt the UI to the user as usual
        start_sign_message_ui(num_summary_steps);
        return 0;
    }
}

static int scan_header_for_signer(const uint32_t *derivation_path,
                                  uint32_t derivation_path_length,
                                  size_t *signer_index,
                                  const MessageHeader *header) {
    Pubkey signer_pubkey;
    cx_err_t cx_err = get_public_key(signer_pubkey.data, derivation_path, derivation_path_length);
    if (cx_err != CX_OK) {
        return -1;
    }
    return get_pubkey_index(&signer_pubkey,
                            header->pubkeys,
                            header->pubkeys_header.num_required_signatures,
                            signer_index);
}

int handle_sign_message_parse_message(void) {
    if ((G_command.instruction != InsDeprecatedSignMessage &&
         G_command.instruction != InsSignMessage &&
         G_command.instruction != InsSignMessagePreview) ||
        G_command.state != ApduStatePayloadComplete) {
        return io_send_sw(ApduReplySdkInvalidParameter);
    }
    // Handle the transaction message signing
    Parser parser = {G_command.message, G_command.message_length};
    PrintConfig print_config;
    // Expert mode adds items purely for the human reviewer. In swap context the summary is not
    // shown to the user but compared against the trusted Exchange values, so those extra items
    // are useless noise. Force it off. Fields required for swap validation are guaranteed by
    // force_full_print below, independently from expert mode.
    print_config.expert_mode = (N_storage.settings.display_mode == DisplayModeExpert) &&
                               !G_called_from_swap;
    print_config.signer_pubkey = NULL;
    print_config.user_input_is_ata_or_token_account = G_command.user_input_is_ata_or_token_account;
    print_config.force_full_print = G_called_from_swap;
    MessageHeader *header = &print_config.header;
    size_t signer_index;

    if (parse_message_header(&parser, header) != 0) {
        // This is not a valid Solana message
        return io_send_sw(ApduReplySolanaInvalidMessage);
    }

    // Ensure the requested signer is present in the header
    if (scan_header_for_signer(G_command.derivation_path,
                               G_command.derivation_path_length,
                               &signer_index,
                               header) != 0) {
        PRINTF("scan_header_for_signer failed\n");
        return io_send_sw(ApduReplySolanaInvalidMessageHeader);
    }
    print_config.signer_pubkey = &header->pubkeys[signer_index];

    if (G_command.non_confirm) {
        // UI confirmation is not optional for message signing.
        PRINTF("G_command.non_confirm refused\n");
        return io_send_sw(ApduReplySdkNotSupported);
    }

    // Set the transaction summary
    transaction_summary_reset();

    if (instruction_descriptor_received()) {
        PRINTF("Using descriptors to validate transaction\n");
        if (!G_called_from_swap) {
            // Parser should have refused at parsing handler step but let's double check
            PRINTF("instruction_descriptor_received outside of swap context\n");
            reset_saved_descriptors();
            return io_send_sw(ApduReplySdkNotSupported);
        }

        if (G_command.is_preview_mode) {
            PRINTF("Preview mode not supported with instruction descriptors\n");
            reset_saved_descriptors();
            return io_send_sw(ApduReplySdkNotSupported);
        }

        PRINTF("Using instruction descriptor\n");
        if (process_message_body_with_descriptor(parser.buffer,
                                                 parser.buffer_length,
                                                 &print_config) != 0) {
            PRINTF("Error in process_message_body_with_descriptor\n");
            reset_saved_descriptors();
            reset_trusted_info();
            reset_dynamic_token_info();
            send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                   SWAP_EC_ERROR_GENERIC,
                                   SWAP_EC_APP_DESCRIPTOR_PROCESSING_FAILED);
            // Unreachable
        } else {
            // Successfully processed the message with descriptor (LiFi swap)
            // Verify the transaction hash matches what Exchange stored
            uint8_t computed_tx_hash[CX_SHA256_SIZE];
            cx_hash_sha256(G_command.message,
                           G_command.message_length,
                           computed_tx_hash,
                           CX_SHA256_SIZE);
            if (!check_swap_tx_hash(computed_tx_hash)) {
                PRINTF("Transaction hash mismatch\n");
                reset_saved_descriptors();
                reset_trusted_info();
                reset_dynamic_token_info();
                send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                       SWAP_EC_ERROR_CROSSCHAIN_WRONG_METHOD,
                                       SWAP_EC_APP_TX_HASH_MISMATCH);
                // Unreachable
            }
            reset_saved_descriptors();
            reset_trusted_info();
            reset_dynamic_token_info();
            swap_finalize();
            // Unreachable
        }
    } else {
        if (process_message_body(parser.buffer, parser.buffer_length, &print_config) == 0) {
            // Clear signing UI OR Swap bypass
            int ret = handle_sign_message_ui();
            if (ret != 0) {
                return io_send_sw(ret);
            }
            // If handle_sign_message_ui returned 0, it means it has started the UI and will send
            // the response async later, we just return here.
            return 0;
        } else {
            // Message not processed, throw if blind signing is not enabled or in swap context
            if (G_called_from_swap) {
                PRINTF("Refuse to process blind transaction in swap context\n");
                send_swap_error_simple(ApduReplySolanaSummaryFinalizeFailed,
                                       SWAP_EC_ERROR_WRONG_METHOD,
                                       SWAP_EC_APP_BLIND_SIGNING_REFUSED);
                // Unreachable
            } else if (N_storage.settings.allow_blind_sign != BlindSignEnabled) {
                PRINTF("Blind signing is not enabled\n");
                // Prompt the BS error + suggest settings change. We delegate this to UI module
                start_blind_sign_error_ui();
                return io_send_sw(ApduReplySdkNotSupported);
            } else {
                // Blind sign allowed. Prepare UI items content
                transaction_summary_set_blind_signing(true);

                SummaryItem *item = transaction_summary_primary_item();
                summary_item_set_string(item, "Unrecognized", "format");

                cx_hash_sha256(G_command.message,
                               G_command.message_length,
                               (uint8_t *) &G_command.message_hash,
                               HASH_LENGTH);

                item = transaction_summary_general_item();
                summary_item_set_hash(item, "Message Hash", &G_command.message_hash);

                // Add fee payer to summary if needed
                const Pubkey *fee_payer = &header->pubkeys[0];
                if (print_config_show_authority(&print_config, fee_payer)) {
                    PRINTF("Adding fee payer to displayable info\n");
                    transaction_summary_set_fee_payer_pubkey(fee_payer);
                }

                // Call the blind sign UI we prepared above
                int ret = handle_sign_message_ui();
                if (ret != 0) {
                    return io_send_sw(ret);
                }
                // If handle_sign_message_ui returned 0, it means it has started the UI and will
                // send the response async later, we just return here.
                return 0;
            }
        }
    }
}
