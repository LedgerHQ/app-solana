// Block compilation of this part on Nano as it uses an EINK only API part
#include "feature_transaction_check.h"

#ifdef HAVE_TRANSACTION_CHECKS

#include "globals.h"
#include "apdu.h"
#include "io.h"
#include "nbgl_use_case.h"
#include "ui_api.h"
#include "transaction_check_ui.h"

#define HOW_TO_INFO_NB 3

enum {
    WARNING_CHOICE_TOKEN = FIRST_USER_TOKEN,
    WARNING_BUTTON_TOKEN,
    DISMISS_WARNING_TOKEN,
};

static bool g_response_expected;

// Forward declaration needed because opt_in_explain_cb calls this before its definition
void ui_transaction_check_opt_in(bool response_expected);

static void opt_in_explain_cb(int token, uint8_t index) {
    UNUSED(token);
    UNUSED(index);
    ui_transaction_check_opt_in(g_response_expected);
}

static void ui_transaction_check_explain(void) {
    nbgl_layout_t *layoutCtx = NULL;
    nbgl_layoutDescription_t layoutDescription = {0};
    nbgl_layoutHeader_t headerDesc = {.type = HEADER_BACK_AND_TEXT,
                                      .backAndText.tuneId = TUNE_TAP_CASUAL,
                                      .backAndText.token = DISMISS_WARNING_TOKEN};

    const char *rowTexts[HOW_TO_INFO_NB] = {
        "Transaction is checked for threats before signing.",
        "The result is displayed: Critical threat, potential risk or no threat.",
        "Scan the QR Code on your Ledger device for details on any threat or risk.",
    };
    const nbgl_icon_details_t *rowIcons[HOW_TO_INFO_NB] = {
        &PRIVACY_ICON,
        &WARNING_ICON,
        &QRCODE_ICON,
    };

    nbgl_layoutLeftContent_t leftContent = {0};

    layoutDescription.withLeftBorder = true;
    layoutDescription.onActionCallback = opt_in_explain_cb;
    layoutCtx = nbgl_layoutGet(&layoutDescription);

    nbgl_layoutAddHeader(layoutCtx, &headerDesc);

    leftContent.title = "How it works";
    leftContent.nbRows = HOW_TO_INFO_NB;
    leftContent.rowTexts = rowTexts;
    leftContent.rowIcons = rowIcons;
    nbgl_layoutAddLeftContent(layoutCtx, &leftContent);

    nbgl_layoutDraw(layoutCtx);
    nbgl_refresh();
}

static void finalise_opt_in(bool is_enabled, nbgl_callback_t callback) {
    if (is_enabled) {
        nbgl_useCaseStatus("Transaction Check\nenabled", true, callback);
    } else {
        callback();
    }
}

static void opt_in_action_cb(int token, uint8_t index) {
    uint8_t opt_in = 1;
    uint8_t enable;

    switch (token) {
        case WARNING_CHOICE_TOKEN:
            // Always mark as opted-in (user has seen the consent screen)
            nvm_write((void *) &N_storage.settings.tx_check_opt_in, &opt_in, sizeof(opt_in));
            // index 0 = "Yes, enable", index 1 = "Maybe later"
            enable = (index == 0) ? 1 : 0;
            if (enable != N_storage.settings.tx_check_enable) {
                nvm_write((void *) &N_storage.settings.tx_check_enable, &enable, sizeof(enable));
            }
            if (g_response_expected) {
                // If True, we are in this flow because of incoming TX_CHECK APDU
                G_io_apdu_buffer[0] = N_storage.settings.tx_check_enable;
                io_send_response_pointer(G_io_apdu_buffer, 1, ApduReplySuccess);
                finalise_opt_in(enable, ui_idle);
            } else {
                // If False, we are in this flow from the settings menu, so we just update the UI
                finalise_opt_in(enable, ui_settings);
            }
            break;
        case WARNING_BUTTON_TOKEN:
            ui_transaction_check_explain();
            break;
        default:
            break;
    }
}

void ui_transaction_check_opt_in(bool response_expected) {
    nbgl_layout_t *layoutCtx = NULL;
    nbgl_layoutDescription_t layoutDescription = {0};
    nbgl_contentCenter_t info = {0};
    nbgl_layoutChoiceButtons_t buttonsInfo = {.topText = "Yes, enable",
                                              .bottomText = "Maybe later",
                                              .token = WARNING_CHOICE_TOKEN,
                                              .style = ROUNDED_AND_FOOTER_STYLE,
                                              .tuneId = TUNE_TAP_CASUAL};
    nbgl_layoutHeader_t headerDesc = {.type = HEADER_EXTENDED_BACK,
                                      .separationLine = false,
                                      .extendedBack.actionIcon = &QUESTION_CIRCLE_ICON,
                                      .extendedBack.backToken = NBGL_INVALID_TOKEN,
                                      .extendedBack.tuneId = TUNE_TAP_CASUAL,
                                      .extendedBack.text = NULL,
                                      .extendedBack.actionToken = WARNING_BUTTON_TOKEN};

    // response_expected is true when this is triggered by a received APDU.
    g_response_expected = response_expected;
    layoutDescription.withLeftBorder = true;
    layoutDescription.onActionCallback = opt_in_action_cb;
    layoutCtx = nbgl_layoutGet(&layoutDescription);

    nbgl_layoutAddHeader(layoutCtx, &headerDesc);

    info.title = "Enable\nTransaction Check?";
    info.description =
        "Get real-time warnings about risky Solana transactions. "
        "Powered by service providers.";
    info.subText = "By enabling, you accept T&Cs: ledger.com/tx-check";
    nbgl_layoutAddContentCenter(layoutCtx, &info);

    nbgl_layoutAddChoiceButtons(layoutCtx, &buttonsInfo);

#ifdef HAVE_PIEZO_SOUND
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif
    nbgl_layoutDraw(layoutCtx);
    nbgl_refresh();
}

#endif  // HAVE_TRANSACTION_CHECKS
