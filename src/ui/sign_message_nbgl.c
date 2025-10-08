#include "io_utils.h"
#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "glyphs.h"
#include "apdu.h"
#include "utils.h"
#include "ui_api.h"

#include "nbgl_use_case.h"

#include "handle_sign_message.h"
#include "handle_sign_offchain_message.h"

// Content of the review flow
static nbgl_contentTagValueList_t content;
// Used by NBGL to display the reference the pair number N
static nbgl_layoutTagValue_t current_pair;
// Used to differentiate between message and transaction review
static nbgl_operationType_t operation_type;

// We will display at most 4 items on a Stax review screen
#define MAX_SIMULTANEOUS_DISPLAYED_SLOTS NB_MAX_DISPLAYED_PAIRS_IN_REVIEW
typedef struct dynamic_slot_s {
    char title[sizeof(G_transaction_summary_title)];
    char text[sizeof(G_transaction_summary_text)];
} dynamic_slot_t;
static dynamic_slot_t displayed_slots[MAX_SIMULTANEOUS_DISPLAYED_SLOTS];

// NBGL library has to know how many steps will be displayed
static size_t G_transaction_steps_number;
static bool G_last_step_is_ascii;

static inline void populate_displayed_slot_non_ascii(const size_t slot, const uint8_t index) {
    enum DisplayFlags flags = DisplayFlagNone;
    if (N_storage.settings.pubkey_display == PubkeyDisplayLong) {
        flags |= DisplayFlagLongPubkeys;
    }
    if (transaction_summary_display_item(index, flags)) {
        THROW(ApduReplySolanaSummaryUpdateFailed);
    }
    memcpy(&displayed_slots[slot].title,
           &G_transaction_summary_title,
           sizeof(displayed_slots[slot].title));
    memcpy(&displayed_slots[slot].text,
           &G_transaction_summary_text,
           sizeof(displayed_slots[slot].text));
}

// function called by NBGL to get the current_pair indexed by "index"
// current_pair will point at values stored in displayed_slots[]
// this will enable displaying at most sizeof(displayed_slots) values simultaneously
static nbgl_contentTagValue_t *get_single_action_review_pair(uint8_t index) {
    PRINTF("get_single_action_review_pair index = %d\n", index);
    uint8_t slot = index % ARRAY_COUNT(displayed_slots);
    // Final step is special for ASCII messages
    if (index == G_transaction_steps_number - 1 && G_last_step_is_ascii) {
        strlcpy(displayed_slots[slot].title, "Message", sizeof(displayed_slots[slot].title));
        strlcpy(displayed_slots[slot].text,
                (const char *) G_command.message + OFFCHAIN_MESSAGE_HEADER_LENGTH,
                sizeof(displayed_slots[slot].text));
    } else {
        populate_displayed_slot_non_ascii(slot, index);
    }
    current_pair.item = displayed_slots[slot].title;
    current_pair.value = displayed_slots[slot].text;
    return &current_pair;
}

static nbgl_contentTagValue_t *get_single_action_long_review_pair(uint8_t index) {
    uint8_t slot = index % ARRAY_COUNT(displayed_slots);
    // Final step is special for ASCII messages
    if (index == G_transaction_steps_number - 1 && G_last_step_is_ascii) {
        strlcpy(displayed_slots[slot].title, "Message", sizeof(displayed_slots[slot].title));
        current_pair.value = (const char *) G_command.message + OFFCHAIN_MESSAGE_HEADER_LENGTH;
    } else {
        populate_displayed_slot_non_ascii(slot, index);
        current_pair.value = displayed_slots[slot].text;
    }

    current_pair.item = displayed_slots[slot].title;

    return &current_pair;
}

static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    // validate_transaction(confirm);
    nbgl_reviewStatusType_t status_type;
    if (confirm) {
        sendResponse(set_result_sign_message(), ApduReplySuccess, false);
        if (operation_type == TYPE_MESSAGE) {
            status_type = STATUS_TYPE_MESSAGE_SIGNED;
        } else {
            status_type = STATUS_TYPE_TRANSACTION_SIGNED;
        }
        nbgl_useCaseReviewStatus(status_type, ui_idle);
    } else {
        sendResponse(0, ApduReplyUserRefusal, false);
        if (operation_type == TYPE_MESSAGE) {
            status_type = STATUS_TYPE_MESSAGE_REJECTED;
        } else {
            status_type = STATUS_TYPE_TRANSACTION_REJECTED;
        }
        nbgl_useCaseReviewStatus(status_type, ui_idle);
    }
}

nbgl_warning_t warning;

static void on_warning_choice(bool cancel) {
    if (cancel) {
        review_choice(false);
    } else {
        // Set the transaction type
        operation_type = TYPE_TRANSACTION;

        // Save steps number for later
        G_last_step_is_ascii = false;

        // Initialize the content structure
        content.nbMaxLinesForValue = 0;
        content.smallCaseForValue = false;
        content.wrapping = true;
        content.pairs = NULL;  // to indicate that callback should be used
        content.callback = get_single_action_review_pair;
        content.startIndex = 0;
        content.nbPairs = G_transaction_steps_number;
        const char *review_title = NULL;
        // On Nano devices we display only the default "Sign transaction?"
        // We forward NULL to let NBGL handle it
        const char *confirmation_text = NULL;

        bool is_blind_signing;
        transaction_summary_get_blind_signing(&is_blind_signing);
        if (is_blind_signing) {
            explicit_bzero(&warning, sizeof(nbgl_warning_t));
            warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
            nbgl_useCaseAdvancedReview(TYPE_TRANSACTION,
                                       &content,
                                       &ICON_SIGN_MENU,
                                       "Review transaction",
                                       NULL,
                                       "Accept risk and sign transaction?",
                                       NULL,
                                       &warning,
                                       review_choice);
        } else {
            transaction_type_t transaction_type;
            transaction_summary_get_transaction_type(&transaction_type);
            PRINTF("transaction_type = %d\n", transaction_type);
            switch (transaction_type) {
                case TRANSACTION_TYPE_SOL_TRANSFER:
                    review_title = "Review transaction to send SOL";
#ifdef SCREEN_SIZE_WALLET
                    confirmation_text = "Sign transaction to send SOL?";
#endif
                    break;
                case TRANSACTION_TYPE_SPL_TRANSFER:
                    review_title = "Review transaction to send tokens";
#ifdef SCREEN_SIZE_WALLET
                    confirmation_text = "Sign transaction to send tokens?";
#endif
                    break;
                case TRANSACTION_TYPE_SOL_STAKING:
                    review_title = "Review transaction to delegate stake";
#ifdef SCREEN_SIZE_WALLET
                    confirmation_text = "Sign transaction to delegate stake?";
#endif
                    break;
                case TRANSACTION_TYPE_SOL_DEACTIVATE_STAKE:
                    review_title = "Review transaction to deactivate stake";
#ifdef SCREEN_SIZE_WALLET
                    confirmation_text = "Sign transaction to deactivate stake?";
#endif
                    break;
                case TRANSACTION_TYPE_SOL_ACTIVATE_STAKE:
                    review_title = "Review transaction to activate stake";
#ifdef SCREEN_SIZE_WALLET
                    confirmation_text = "Sign transaction to activate stake?";
#endif
                    break;
                case TRANSACTION_TYPE_SOL_WITHDRAW:
                    review_title = "Review transaction to withdraw SOL";
#ifdef SCREEN_SIZE_WALLET
                    confirmation_text = "Sign transaction to withdraw SOL?";
#endif
                    break;
                case TRANSACTION_TYPE_BLIND_SIGNING:
                    review_title = "Review transaction";
#ifdef SCREEN_SIZE_WALLET
                    confirmation_text = "Accept risk and sign transaction?";
#else
                    confirmation_text = "Accept risk and sign transaction";
#endif
                    break;
                case TRANSACTION_TYPE_OTHER:
                default:
                    review_title = "Review transaction";
#ifdef SCREEN_SIZE_WALLET
                    confirmation_text = "Sign transaction?";
#endif
                    break;
            }

            nbgl_useCaseReview(operation_type,
                               &content,
                               &ICON_SIGN_MENU,
                               review_title,
                               NULL,
                               confirmation_text,
                               review_choice);
        }
    }
}

void start_sign_tx_ui(size_t num_summary_steps) {
    bool fee_warning;
    bool hook_warning;
    transaction_summary_get_token_warnings(&fee_warning, &hook_warning);
    G_transaction_steps_number = num_summary_steps;
    const char *warning_title = NULL;
    const char *warning_text = NULL;
    if (hook_warning) {
        warning_title = "Transfer Hook";
        warning_text =
            "This transaction invokes a custom program. It may lead to unexpected behaviour.";
    } else {
        if (fee_warning) {
            warning_title = "Token Extensions cannot be verified";
            warning_text =
                "A token in this transaction may contain Transfer Fee extension which would lead "
                "to additional fees upon broadcast.";
        } else {
            // No warning
        }
    }

    if (warning_title != NULL) {
        nbgl_useCaseChoice(&ICON_WARNING,
                           warning_title,
                           warning_text,
                           "Back to safety",
                           "Continue anyway",
                           on_warning_choice);
    } else {
        on_warning_choice(false);
    }
}

void start_sign_offchain_message_ui(bool is_ascii, size_t num_summary_steps) {
    // Set the operation type
    operation_type = TYPE_MESSAGE;

    // Save steps number for later
    G_transaction_steps_number = num_summary_steps;
    G_last_step_is_ascii = is_ascii;
    if (is_ascii) {
        ++G_transaction_steps_number;
    }

    // Initialize the content structure
    content.nbMaxLinesForValue = 0;
    content.smallCaseForValue = false;
    content.wrapping = true;
    content.pairs = NULL;  // to indicate that callback should be used
    content.callback = get_single_action_long_review_pair;
    content.startIndex = 0;
    content.nbPairs = G_transaction_steps_number;

    // Start review
    nbgl_useCaseReview(operation_type,
                       &content,
                       &ICON_REVIEW,
                       "Review message",
                       NULL,
#ifdef SCREEN_SIZE_WALLET
                       "Sign message?",
#else
                       NULL,
#endif
                       review_choice);
}

#ifdef SCREEN_SIZE_WALLET
static void ui_error_blind_signing_choice(bool confirm) {
    if (confirm) {
        ui_settings();
    } else {
        ui_idle();
    }
}
#endif

void start_blind_sign_error_ui(void) {
#ifdef SCREEN_SIZE_WALLET
    nbgl_useCaseChoice(&ICON_WARNING,
                       "This transaction cannot be clear-signed",
                       "Enable blind signing in the settings to sign this transaction.",
                       "Go to settings",
                       "Reject transaction",
                       ui_error_blind_signing_choice);
#else
    nbgl_useCaseAction(&ICON_WARNING, "Blind signing must\nbe enabled in\nsettings", NULL, ui_idle);
#endif
}
