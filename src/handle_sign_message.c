#include "io_utils.h"
#include "utils.h"
#include "handle_swap_sign_transaction.h"

#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "trusted_info.h"
#include "ed25519_helpers.h"

#include "handle_sign_message.h"
#include "handle_provide_instruction_descriptor.h"
#include "ui_api.h"

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
        return false;
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
                        return false;
                    }
                } else if (strcmp(G_transaction_summary_title, "Amount") == 0) {
                    if (!check_swap_amount(G_transaction_summary_text)) {
                        PRINTF("check_swap_amount failed\n");
                        return false;
                    }
                } else {
                    PRINTF("Refused title '%s', expecting '%s'\n",
                           G_transaction_summary_title,
                           "Amount");
                    return false;
                }
                amount_ok = true;
                break;

            case SummaryItemPubkey:
                if (strcmp(G_transaction_summary_title, "To") != 0) {
                    PRINTF("Refused title '%s', expecting '%s'\n",
                           G_transaction_summary_title,
                           "To");
                    return false;
                }
                if (!check_swap_recipient(G_transaction_summary_text)) {
                    PRINTF("check_swap_recipient failed\n");
                    return false;
                }
                recipient_ok = true;
                break;

            default:
                PRINTF("Refused kind '%u'\n", kinds[i]);
                return false;
        }
    }
    return amount_ok && recipient_ok;
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

    if (!g_trusted_info.received) {
        // This case should never happen because this is already checked at TX parsing
        PRINTF("Descriptor info is required for a SPL transfer\n");
        return false;
    }
    if (!validate_associated_token_address(g_trusted_info.owner_address,
                                           g_trusted_info.mint_address,
                                           g_trusted_info.token_address,
                                           is_token_2022)) {
        // This case should never happen because this is already checked at TX parsing
        PRINTF("Failed to validate ATA\n");
        return false;
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
                    return false;
                }
                if (!check_swap_amount(G_transaction_summary_text)) {
                    PRINTF("check_swap_amount failed\n");
                    return false;
                }
                if (amount_ok) {
                    PRINTF("We have already parsed an amount, refusing signing multiple\n");
                    return false;
                }
                amount_ok = true;
                break;

            case SummaryItemAmount:
                if (strcmp(G_transaction_summary_title, "Max fees") == 0) {
                    if (!check_swap_fee(G_transaction_summary_text)) {
                        PRINTF("check_swap_fee failed\n");
                        return false;
                    }
                } else {
                    PRINTF("Refusing non fee amount in token swap context\n");
                    return false;
                }
                break;

            case SummaryItemPubkey:
                if (strcmp(G_transaction_summary_title, "Create token account") == 0) {
                    if (strcmp(g_trusted_info.encoded_token_address, G_transaction_summary_text) !=
                        0) {
                        PRINTF("Create ATA address does not match with address in descriptor\n");
                        return false;
                    }
                    create_token_account_received = true;
                } else if (strcmp(G_transaction_summary_title, "For") == 0) {
                    if (!create_token_account_received) {
                        PRINTF("'For' received out of create_token_account context\n");
                        return false;
                    }
                    break;
                } else if (strcmp(G_transaction_summary_title, "Funded by") == 0) {
                    if (!create_token_account_received) {
                        PRINTF("'Funded by' received out of create_token_account context\n");
                        return false;
                    }
                    break;
                } else if (strcmp(G_transaction_summary_title, "Token address") == 0) {
                    // MINT
                    if (strcmp(g_trusted_info.encoded_mint_address, G_transaction_summary_text) !=
                        0) {
                        // This case should never happen because this is already checked at TX
                        // parsing
                        PRINTF("Mint address does not match with mint address in descriptor\n");
                        return false;
                    }
                    mint_ok = true;
                } else if (strcmp(G_transaction_summary_title, "From (token account)") == 0) {
                    // SRC ACCOUNT
                    break;
                } else if (strcmp(G_transaction_summary_title, "To (token account)") == 0) {
                    // Destination ATA
                    if (strcmp(g_trusted_info.encoded_token_address, G_transaction_summary_text) !=
                        0) {
                        // This case should never happen because this is already checked at TX
                        // parsing
                        PRINTF("Dest ATA address does not match with ATA in descriptor\n");
                        return false;
                    }
                    dest_ata_ok = true;
                }
                break;

            case SummaryItemString:
                if (strcmp(G_transaction_summary_title, "To") != 0) {
                    PRINTF("Refuse string item != 'To'\n");
                    return false;
                }
                if (strcmp(g_trusted_info.encoded_owner_address, G_transaction_summary_text) != 0) {
                    // This case should never happen because this is already checked at TX parsing
                    PRINTF("Dest SOL address does not match with SOL address in descriptor\n");
                    return false;
                }
                if (!check_swap_recipient(G_transaction_summary_text)) {
                    PRINTF("check_swap_recipient failed\n");
                    return false;
                }
                dest_sol_address_ok = true;
                break;

            default:
                PRINTF("Refused kind '%u'\n", kinds[i]);
                return false;
        }
    }

    // All expected elements should have been received and validated
    PRINTF("amount_ok = %d\nmint_ok = %d\ndest_ata_ok = %d\ndest_sol_address_ok = %d\n",
           amount_ok,
           mint_ok,
           dest_ata_ok,
           dest_sol_address_ok);
    return amount_ok && mint_ok && dest_ata_ok && dest_sol_address_ok;
}

static bool check_swap_validity(const SummaryItemKind_t kinds[MAX_TRANSACTION_SUMMARY_ITEMS],
                                size_t num_summary_steps) {
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
                return false;
            }
            if (has_transfer_hook) {
                PRINTF("Transaction with transfer hook refused\n");
                return false;
            }
        }
        return check_swap_validity_token(kinds, num_summary_steps, is_token_2022);
    } else {
        return check_swap_validity_native(kinds, num_summary_steps);
    }
}

static void swap_finalize(bool is_valid) {
    if (G_swap_response_ready) {
        // Safety against trying to make the app sign multiple TX
        // This code should never be triggered as the app is supposed to exit after
        // sending the signed transaction
        PRINTF("Safety against double signing triggered\n");
        os_sched_exit(-1);
    } else {
        // We will quit the app after this transaction, whether it succeeds or fails
        PRINTF("Swap response is ready, the app will quit after the next send\n");
        G_swap_response_ready = true;
    }

    if (is_valid) {
        PRINTF("Valid swap transaction received, signing and replying it\n");
        sendResponse(set_result_sign_message(), ApduReplySuccess, false);
    } else {
        PRINTF("Refuse to sign an incorrect Swap transaction\n");
        sendResponse(0, ApduReplySolanaSummaryFinalizeFailed, false);
    }
}

// --8<-- [start:handle_sign_message_ui]
static void handle_sign_message_ui(volatile unsigned int *flags) {
    // Display the transaction summary
    SummaryItemKind_t summary_step_kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_summary_steps = 0;
    if (transaction_summary_finalize(summary_step_kinds, &num_summary_steps) == 0) {
        // If we are in swap context, do not redisplay the message data
        // Instead, ensure they are identical with what was previously displayed
        if (G_called_from_swap) {
            swap_finalize(check_swap_validity(summary_step_kinds, num_summary_steps));
        } else {
            // We have been started from the dashboard, prompt the UI to the user as usual
            start_sign_tx_ui(num_summary_steps);
        }
    } else {
        PRINTF("Error transaction_summary_finalize failed\n");
        THROW(ApduReplySolanaSummaryFinalizeFailed);
    }

    *flags |= IO_ASYNCH_REPLY;
}
// --8<-- [end:handle_sign_message_ui]

static int scan_header_for_signer(const uint32_t *derivation_path,
                                  uint32_t derivation_path_length,
                                  size_t *signer_index,
                                  const MessageHeader *header) {
    Pubkey signer_pubkey;
    get_public_key(signer_pubkey.data, derivation_path, derivation_path_length);
    return get_pubkey_index(&signer_pubkey,
                            header->pubkeys,
                            header->pubkeys_header.num_required_signatures,
                            signer_index);
}

void handle_sign_message_parse_message(volatile unsigned int *flags, volatile unsigned int *tx) {
    if (!tx ||
        (G_command.instruction != InsDeprecatedSignMessage &&
         G_command.instruction != InsSignMessage) ||
        G_command.state != ApduStatePayloadComplete) {
        THROW(ApduReplySdkInvalidParameter);
    }
    // Handle the transaction message signing
    Parser parser = {G_command.message, G_command.message_length};
    PrintConfig print_config;
    print_config.expert_mode = (N_storage.settings.display_mode == DisplayModeExpert);
    print_config.signer_pubkey = NULL;
    print_config.user_input_is_ata_or_token_account = G_command.user_input_is_ata_or_token_account;
    print_config.force_full_print = G_called_from_swap;
    MessageHeader *header = &print_config.header;
    size_t signer_index;

    if (parse_message_header(&parser, header) != 0) {
        // This is not a valid Solana message
        THROW(ApduReplySolanaInvalidMessage);
    }

    // Ensure the requested signer is present in the header
    if (scan_header_for_signer(G_command.derivation_path,
                               G_command.derivation_path_length,
                               &signer_index,
                               header) != 0) {
        PRINTF("scan_header_for_signer failed\n");
        THROW(ApduReplySolanaInvalidMessageHeader);
    }
    print_config.signer_pubkey = &header->pubkeys[signer_index];

    if (G_command.non_confirm) {
        PRINTF("G_command.non_confirm refused\n");
        // Uncomment this to allow unattended signing.
        //*tx = set_result_sign_message();
        // THROW(ApduReplySuccess);
        UNUSED(tx);
        THROW(ApduReplySdkNotSupported);
    }

    // Set the transaction summary
    transaction_summary_reset();

    if (instruction_descriptor_received()) {
        // Descriptor should not have been accepted so this code should never run but let's be safe
        if (!G_called_from_swap) {
            PRINTF("instruction_descriptor_received outside of swap context\n");
            THROW(ApduReplySdkNotSupported);
        }
        PRINTF("Using instruction descriptor\n");
        if (process_message_body_with_descriptor(parser.buffer,
                                                 parser.buffer_length,
                                                 &print_config) != 0) {
            PRINTF("Error in process_message_body_with_descriptor\n");
            swap_finalize(false);
        } else {
            swap_finalize(true);
        }
    } else {
        if (process_message_body(parser.buffer, parser.buffer_length, &print_config) == 0) {
            handle_sign_message_ui(flags);
        } else {
            // Message not processed, throw if blind signing is not enabled or in swap context
            if (G_called_from_swap) {
                PRINTF("Refuse to process blind transaction in swap context\n");
                swap_finalize(false);
            } else if (N_storage.settings.allow_blind_sign != BlindSignEnabled) {
                PRINTF("Blind signing is not enabled\n");
                start_blind_sign_error_ui();
                THROW(ApduReplySdkNotSupported);
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

                handle_sign_message_ui(flags);
            }
        }
    }
}
