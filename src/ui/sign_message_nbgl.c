#ifdef HAVE_NBGL

#include "io.h"
#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "glyphs.h"
#include "apdu.h"
#include "utils.h"
#include "ui_api.h"

#include "nbgl_page.h"
#include "nbgl_use_case.h"

#include "handle_sign_message.h"
#include "handle_sign_offchain_message.h"

// Layout of the review flow
static nbgl_layoutTagValueList_t layout;
// Used by NBGL to display the reference the pair number N
static nbgl_layoutTagValue_t current_pair;

// We will display at most 4 items on a Stax review screen
#define MAX_SIMULTANEOUS_DISPLAYED_SLOTS NB_MAX_DISPLAYED_PAIRS_IN_REVIEW
typedef struct dynamic_slot_s {
    char title[sizeof(G_transaction_summary_title)];
    char text[sizeof(G_transaction_summary_text)];
} dynamic_slot_t;
static dynamic_slot_t displayed_slots[MAX_SIMULTANEOUS_DISPLAYED_SLOTS];

// Final review screen of the message signing flow
static nbgl_pageInfoLongPress_t review_final_long_press;

static const char reject_choice_message[] = "Message\nrejected";
static const char reject_choice_transaction[] = "Transaction\nrejected";
static const char *reject_choice_text;

static const char go_back_message[] = "Go back to message";
static const char go_back_transaction[] = "Go back to transaction";
static const char *go_back_text;

static const char option_reject_message[] = "Reject message";
static const char option_reject_transaction[] = "Reject transaction";
static const char *option_reject_text;

static const char ask_reject_message[] = "Reject message?";
static const char ask_reject_transaction[] = "Reject transaction?";
static const char *ask_reject_text;

static const char success_message[] = "MESSAGE\nSIGNED";
static const char success_transaction[] = "TRANSACTION\nSIGNED";
static const char *success_text;

// Callback called when the user confirms the message rejection
static void rejectChoice(void) {
    sendResponse(0, ApduReplyUserRefusal, false);
    nbgl_useCaseStatus(reject_choice_text, false, ui_idle);
}

// If the user asks for message rejection, ask for confirmation
static void rejectUseCaseChoice(void) {
    nbgl_useCaseConfirm(ask_reject_text, NULL, "Yes, reject", go_back_text, rejectChoice);
}

// Callback called on the final review screen
static void review_final_callback(bool confirmed) {
    if (confirmed) {
        sendResponse(set_result_sign_message(), ApduReplySuccess, false);
        nbgl_useCaseStatus(success_text, true, ui_idle);
    } else {
        rejectUseCaseChoice();
    }
}

// NBGL library has to know how many steps will be displayed
static size_t transaction_steps_number;
static bool last_step_is_ascii;

// function called by NBGL to get the current_pair indexed by "index"
// current_pair will point at values stored in displayed_slots[]
// this will enable displaying at most sizeof(displayed_slots) values simultaneously
static nbgl_layoutTagValue_t *get_single_action_review_pair(uint8_t index) {
    uint8_t slot = index % ARRAY_COUNT(displayed_slots);
    // Final step is special for ASCII messages
    if (index == transaction_steps_number - 1 && last_step_is_ascii) {
        strlcpy(displayed_slots[slot].title, "Message", sizeof(displayed_slots[slot].title));
        strlcpy(displayed_slots[slot].text,
                (const char *) G_command.message + OFFCHAIN_MESSAGE_HEADER_LENGTH,
                sizeof(displayed_slots[slot].text));
    } else {
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
    current_pair.item = displayed_slots[slot].title;
    current_pair.value = displayed_slots[slot].text;
    return &current_pair;
}

// Prepare the review layout structure and starts the review use_case
static void start_review(void) {
    layout.nbMaxLinesForValue = 0;
    layout.smallCaseForValue = false;
    layout.wrapping = true;
    layout.pairs = NULL;  // to indicate that callback should be used
    layout.callback = get_single_action_review_pair;
    layout.startIndex = 0;
    layout.nbPairs = transaction_steps_number;

    nbgl_useCaseStaticReview(&layout,
                             &review_final_long_press,
                             option_reject_text,
                             review_final_callback);
}

void start_sign_tx_ui(size_t num_summary_steps) {
    review_final_long_press.text = "Sign transaction on\nSolana network?";
    review_final_long_press.icon = &C_icon_solana_64x64;
    review_final_long_press.longPressText = "Hold to sign";
    review_final_long_press.longPressToken = 0;
    review_final_long_press.tuneId = TUNE_TAP_CASUAL;

    reject_choice_text = reject_choice_transaction;
    go_back_text = go_back_transaction;
    ask_reject_text = ask_reject_transaction;
    success_text = success_transaction;
    option_reject_text = option_reject_transaction;

    // Save steps number for later
    transaction_steps_number = num_summary_steps;
    last_step_is_ascii = false;
    // start display
    nbgl_useCaseReviewStart(&C_icon_solana_64x64,
                            "Review transaction",
                            NULL,
                            "Reject transaction",
                            start_review,
                            rejectUseCaseChoice);
}

void start_sign_offchain_message_ui(bool is_ascii, size_t num_summary_steps) {
    review_final_long_press.text = "Sign Off-Chain\nmessage on Solana\nnetwork?";
    review_final_long_press.icon = &C_icon_solana_64x64;
    review_final_long_press.longPressText = "Hold to sign";
    review_final_long_press.longPressToken = 0;
    review_final_long_press.tuneId = TUNE_TAP_CASUAL;

    reject_choice_text = reject_choice_message;
    go_back_text = go_back_message;
    ask_reject_text = ask_reject_message;
    success_text = success_message;
    option_reject_text = option_reject_message;

    // Save steps number for later
    transaction_steps_number = num_summary_steps;
    last_step_is_ascii = is_ascii;
    if (is_ascii) {
        ++transaction_steps_number;
    }
    // start display
    nbgl_useCaseReviewStart(&C_icon_solana_64x64,
                            "Review off-chain\nmessage",
                            NULL,
                            "Reject message",
                            start_review,
                            rejectUseCaseChoice);
}

#endif