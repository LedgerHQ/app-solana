#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "glyphs.h"
#include "apdu.h"
#include "utils.h"
#include "ui_api.h"
#include "io.h"
#include "main_std_app.h"

#include "nbgl_use_case.h"
#include "nbgl_fonts.h"
#include "nbgl_layout.h"

#include "handle_sign_message.h"
#include "handle_sign_offchain_message.h"
#include "handle_sign_message_preview.h"
#include "trusted_info.h"
#include "dynamic_token_info.h"

#ifdef HAVE_TRANSACTION_CHECKS
#include "handle_provide_transaction_check.h"
#endif

// Content of the review flow
static nbgl_contentTagValueList_t G_content;
// Used by NBGL to display the reference the pair number N
static nbgl_layoutTagValue_t G_current_pair;
// Used to differentiate between message and transaction review
static nbgl_operationType_t G_operation_type;
// Set when the review shows the message text itself instead of its hash
static bool G_is_clear_signed_message;

// The page index of the review flow is 8 bits wide. Stay below that range and keep
// headroom for the extra pages the flow adds when it substitutes "...".
#define MAX_REVIEW_TEXT_PAGES 200

#ifdef SCREEN_SIZE_WALLET
// A long value goes to the details flow, which fills NB_MAX_LINES_IN_DETAILS lines per page
#define REVIEW_TEXT_FONT           SMALL_REGULAR_FONT
#define REVIEW_TEXT_LINES_PER_PAGE NB_MAX_LINES_IN_DETAILS
#else
// A long value is split inside its own step, where the first line carries the tag
#define REVIEW_TEXT_FONT           BAGL_FONT_OPEN_SANS_REGULAR_11px_1bpp
#define REVIEW_TEXT_LINES_PER_PAGE (NB_MAX_LINES - 1)
#endif

// We will display at most 4 items on a Stax review screen
#define MAX_SIMULTANEOUS_DISPLAYED_SLOTS NB_MAX_DISPLAYED_PAIRS_IN_REVIEW
typedef struct dynamic_slot_s {
    char title[sizeof(G_transaction_summary_title)];
    char text[sizeof(G_transaction_summary_text)];
} dynamic_slot_t;
static dynamic_slot_t displayed_slots[MAX_SIMULTANEOUS_DISPLAYED_SLOTS];

// NBGL library has to know how many steps will be displayed
static size_t G_transaction_steps_number;

// Warning structure for blind signing reviews
static nbgl_warning_t G_warning;

// Returns true when the review flow can reach every part of the message text.
bool is_message_reviewable(const char *message) {
    if (message == NULL) {
        PRINTF("is_message_reviewable: NULL message\n");
        return false;
    }

    // Measure with the font, the width and the wrapping used by the review, then split the
    // lines into pages the same way the review does. The line count is 16 bits, so it holds
    // the whole message even when the page index of the review would not.
    uint16_t lines_number =
        nbgl_getTextNbLinesInWidth(REVIEW_TEXT_FONT, message, AVAILABLE_WIDTH, true);
    uint16_t pages_number =
        (lines_number + REVIEW_TEXT_LINES_PER_PAGE - 1) / REVIEW_TEXT_LINES_PER_PAGE;
    PRINTF("lines_number=%d pages_number=%d\n", lines_number, pages_number);

    return (pages_number <= MAX_REVIEW_TEXT_PAGES);
}

// function called by NBGL to get the G_current_pair indexed by "index"
// G_current_pair will point at values stored in displayed_slots[]
// this will enable displaying at most sizeof(displayed_slots) values simultaneously
static nbgl_contentTagValue_t *get_review_pair(uint8_t index) {
    PRINTF("get_review_pair index = %d\n", index);
    // We use a rotating access to the displayed_slots buffers to ensure there is no overwrite
    // by adjacent indexes
    uint8_t slot = index % ARRAY_COUNT(displayed_slots);
    // Final step is special for clear signed messages
    if (index == G_transaction_steps_number - 1 && G_operation_type == TYPE_MESSAGE &&
        G_is_clear_signed_message) {
        // For clear signed offchain messages, the last step points directly to the message
        // text to avoid truncation by the slot buffer and allow displaying long messages.
        strlcpy(displayed_slots[slot].title, "Message", sizeof(displayed_slots[slot].title));
        // G_command.message_text_start is NULL terminated by construct.
        G_current_pair.value = G_command.message_text_start;
    } else {
        enum DisplayFlags flags = DisplayFlagNone;
        if (N_storage.settings.pubkey_display == PubkeyDisplayLong) {
            flags |= DisplayFlagLongPubkeys;
        }
        if (transaction_summary_display_item(index, flags)) {
            // Should never happen as items were validated during finalization
            // TODO: investigate how to gracefully handle display errors in NBGL callbacks
            PRINTF("Fatal: transaction_summary_display_item failed for index %d\n", index);
            app_exit();
        }
        memcpy(&displayed_slots[slot].title,
               &G_transaction_summary_title,
               sizeof(displayed_slots[slot].title));
        memcpy(&displayed_slots[slot].text,
               &G_transaction_summary_text,
               sizeof(displayed_slots[slot].text));
        G_current_pair.value = displayed_slots[slot].text;
    }

    G_current_pair.item = displayed_slots[slot].title;
    return &G_current_pair;
}

static nbgl_reviewStatusType_t get_status_type(bool accepted) {
    // Solana "offchain message" is what we call "messages" in Ledger UI
    // Solana "onchain message" is what we call "transactions" in Ledger UI
    bool is_message = (G_operation_type == TYPE_MESSAGE);
    if (accepted) {
        return is_message ? STATUS_TYPE_MESSAGE_SIGNED : STATUS_TYPE_TRANSACTION_SIGNED;
    } else {
        return is_message ? STATUS_TYPE_MESSAGE_REJECTED : STATUS_TYPE_TRANSACTION_REJECTED;
    }
}

static void review_choice(bool confirm) {
    // Free dynamically allocated trusted info and dynamic token info
    reset_trusted_info();
    reset_dynamic_token_info();

    // Answer, display a status page and go back to main
#ifdef HAVE_TRANSACTION_CHECKS
    clear_transaction_check();
#endif
    if (confirm) {
        if (G_command.is_preview_mode) {
            // In preview mode, store fingerprint instead of signing
            if (store_preview_fingerprint() == 0) {
                io_send_sw(ApduReplySuccess);
                // We don't display the "Message signed" status page in preview mode as we have not
                // actually signed. The delayed signing step will sign and display it
                nbgl_useCaseSpinner("Signing");
            } else {
                // Can't really happen because store_preview_fingerprint cannot realistically fail
                io_send_sw(ApduReplySolanaInvalidMessage);
                nbgl_useCaseReviewStatus(get_status_type(false), ui_idle);
            };
        } else {
            int tx = set_result_sign_message();
            if (tx <= 0) {
                // User has accepted to sign but an error occurred during signing
                // This error is extremely unlikely but let's handle it gracefully just in case
                io_send_sw(ApduReplySdkException);
                nbgl_useCaseReviewStatus(get_status_type(false), ui_idle);
            } else {
                io_send_response_pointer(G_io_apdu_buffer, tx, ApduReplySuccess);
                nbgl_useCaseReviewStatus(get_status_type(true), ui_idle);
            }
        }
    } else {
        io_send_sw(ApduReplyUserRefusal);
        nbgl_useCaseReviewStatus(get_status_type(false), ui_idle);
    }
}

// Init the base elements of the UI flow common for message and offchain message signing
static void init_review_content(nbgl_opType_t operation_type,
                                size_t num_summary_steps,
                                bool is_clear_signed_message) {
    G_operation_type = operation_type;
    G_transaction_steps_number = num_summary_steps;
    G_is_clear_signed_message = is_clear_signed_message;

    G_content.nbMaxLinesForValue = 0;
    G_content.smallCaseForValue = false;
    G_content.wrapping = true;
    G_content.pairs = NULL;  // to indicate that callback should be used
    G_content.callback = get_review_pair;
    G_content.startIndex = 0;
    G_content.nbPairs = G_transaction_steps_number;
}

// Returns the appropriate confirmation text based on warning bits.
static const char *maybe_warning_confirmation(const char *default_confirmation) {
    if (G_warning.predefinedSet & SET_BIT(W3C_THREAT_DETECTED_WARN)) {
        PRINTF("Transaction_Check threat detected, override confirmation text\n");
        return "Accept threat and sign";
    } else if (G_warning.predefinedSet & SET_BIT(W3C_RISK_DETECTED_WARN)) {
        PRINTF("Transaction_Check risk detected, override confirmation text\n");
        return "Accept risk and sign";
    } else {
        return default_confirmation;
    }
}

static void start_blind_signing_ui(const char *review_title, const char *confirmation_text) {
    G_warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
#ifdef HAVE_TRANSACTION_CHECKS
    if (G_operation_type == TYPE_TRANSACTION) {
        PRINTF("Applying transaction check report to blind signing review\n");
        apply_transaction_check_report(&G_warning);
    }
#endif
    nbgl_useCaseAdvancedReview(G_operation_type,
                               &G_content,
                               &ICON_SIGN_MENU,
                               review_title,
                               NULL,
                               maybe_warning_confirmation(confirmation_text),
                               NULL,
                               &G_warning,
                               review_choice);
}

// This function handles post warnings UI for both onchain and offchain message signing
static void start_message_signing_review(void) {
#ifdef HAVE_TRANSACTION_CHECKS
    if (G_operation_type == TYPE_TRANSACTION) {
        PRINTF("Applying transaction check report to transaction review\n");
        apply_transaction_check_report(&G_warning);
    }
#endif
    const char *review_title = NULL;
    // On Nano devices we display only the default "Sign transaction?"
    // We forward NULL to let NBGL handle it
    const char *confirmation_text = NULL;
    const nbgl_icon_details_t *icon;

    if (G_operation_type == TYPE_TRANSACTION) {
        icon = &ICON_SIGN_MENU;
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
    } else {
        // Offchain message signing
        icon = &ICON_REVIEW;
        review_title = "Review message";
#ifdef SCREEN_SIZE_WALLET
        confirmation_text = "Sign message?";
#endif
    }

    nbgl_useCaseAdvancedReview(G_operation_type,
                               &G_content,
                               icon,
                               review_title,
                               NULL,
                               maybe_warning_confirmation(confirmation_text),
                               NULL,
                               &G_warning,
                               review_choice);
}

// Function called by the Transaction Hook / Unknown Transaction Fees flow
static void on_token_warning_choice(bool cancel) {
    if (cancel) {
        review_choice(false);
    } else {
        start_message_signing_review();
    }
}

void start_sign_message_ui(size_t num_summary_steps) {
    explicit_bzero(&G_warning, sizeof(nbgl_warning_t));
    init_review_content(TYPE_TRANSACTION, num_summary_steps, false);

    if (transaction_summary_is_blind_signing()) {
        start_blind_signing_ui("Review transaction", "Accept risk and sign transaction?");
    } else {
        bool fee_warning;
        bool hook_warning;
        transaction_summary_get_token_warnings(&fee_warning, &hook_warning);
        if (hook_warning || fee_warning) {
            const char *warning_title = NULL;
            const char *warning_text = NULL;
            if (hook_warning) {
                // Transfer hook is more dangerous than unverified fees, so its warning takes
                // priority
                warning_title = "Transfer Hook";
                warning_text =
                    "This transaction invokes a custom program. It may lead to unexpected "
                    "behaviour.";
            } else if (fee_warning) {
                warning_title = "Token Extensions cannot be verified";
                warning_text =
                    "A token in this transaction may contain Transfer Fee extension which would "
                    "lead "
                    "to additional fees upon broadcast.";
            }
            nbgl_useCaseChoice(
                &ICON_WARNING,
                warning_title,
                warning_text,
                "Back to safety",
                "Continue anyway",
                // on_token_warning_choice is a wrapper around start_message_signing_review
                on_token_warning_choice);
        } else {
            start_message_signing_review();
        }
    }
}

void start_sign_offchain_message_ui(bool is_clear_signable,
                                    bool is_ascii,
                                    size_t num_summary_steps) {
    explicit_bzero(&G_warning, sizeof(nbgl_warning_t));
    init_review_content(TYPE_MESSAGE, num_summary_steps, is_clear_signable);

    if (is_clear_signable) {
        PRINTF("Clear signing the message text\n");
        start_message_signing_review();
    } else if (!is_ascii) {
        PRINTF("Non-ASCII message, blind signing required\n");
        start_blind_signing_ui("Review UTF-8 message", "Accept risk and sign UTF-8 message");
    } else {
        PRINTF("Message text out of review reach, blind signing required\n");
        start_blind_signing_ui("Review message", "Accept risk and sign message");
    }
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

void ui_transaction_modal(bool is_success) {
    if (is_success) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}
