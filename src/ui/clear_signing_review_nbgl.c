#include "nbgl_use_case.h"
#include "glyphs.h"
#include "ui_api.h"
#include "apdu.h"
#include "io.h"
#include "main_std_app.h"
#include "cs_display_renderer.h"
#include "cs_transaction.h"
#include "handle_sign_message_preview.h"
#include "dynamic_token_info.h"
#include "trusted_info.h"

static nbgl_contentTagValueList_t G_cs_review_content;
static nbgl_layoutTagValue_t G_cs_review_pair;

static int cs_review_confirm_internal(void) {
    const cs_transaction_t *cs_tx = cs_transaction_get();
    if (cs_tx == NULL) {
        PRINTF("cs_review_confirm: no transaction context\n");
        return -1;
    }
    if (store_preview_fingerprint(cs_tx->transaction,
                                  cs_tx->transaction_size,
                                  cs_tx->derivation_path,
                                  cs_tx->derivation_path_length) != 0) {
        PRINTF("cs_review_confirm: failed to store fingerprint\n");
        return -1;
    }
    return 0;
}

static void cs_review_choice(bool confirm) {
    int ret = confirm ? cs_review_confirm_internal() : -1;

    cs_transaction_reset();
    reset_trusted_info();
    reset_dynamic_token_info();

    if (confirm && ret == 0) {
        PRINTF("Clear signing review confirmed, fingerprint armed\n");
        io_send_sw(ApduReplySuccess);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
    } else if (confirm) {
        PRINTF("Clear signing review confirm failed\n");
        io_send_sw(ApduReplySolanaInvalidMessage);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    } else {
        PRINTF("Clear signing review rejected\n");
        io_send_sw(ApduReplyUserRefusal);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

static nbgl_contentTagValue_t *cs_get_review_pair(uint8_t index) {
    PRINTF("cs_get_review_pair index=%d\n", index);
    const cs_display_element_t *element = cs_display_renderer_element(index);
    if (element == NULL) {
        PRINTF("cs_get_review_pair: NULL element at index %d\n", index);
        app_exit();
    }
    G_cs_review_pair.item = element->title;
    G_cs_review_pair.value = element->value;
    return &G_cs_review_pair;
}

void ui_clear_signing_review(void) {
    size_t element_count = cs_display_renderer_element_count();
    PRINTF("ui_clear_signing_review: %d elements\n", (int) element_count);

    G_cs_review_content.nbMaxLinesForValue = 0;
    G_cs_review_content.smallCaseForValue = false;
    G_cs_review_content.wrapping = true;
    G_cs_review_content.pairs = NULL;
    G_cs_review_content.callback = cs_get_review_pair;
    G_cs_review_content.startIndex = 0;
    G_cs_review_content.nbPairs = element_count;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &G_cs_review_content,
                       &ICON_SIGN_MENU,
                       "Review transaction",
                       NULL,
#ifdef SCREEN_SIZE_WALLET
                       "Sign transaction on the Solana network?",
#else
                       NULL,
#endif
                       cs_review_choice);
}
