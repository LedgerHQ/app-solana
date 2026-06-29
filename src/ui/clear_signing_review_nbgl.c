#include "nbgl_use_case.h"
#include "glyphs.h"
#include "ui_api.h"
#include "apdu.h"
#include "io.h"
#include "main_std_app.h"
#include "cs_display_renderer.h"
#include "cs_transaction.h"

static nbgl_contentTagValueList_t G_cs_review_content;
static nbgl_layoutTagValue_t G_cs_review_pair;

static void cs_review_choice(bool confirm) {
    cs_transaction_reset();
    if (confirm) {
        PRINTF("Clear signing review confirmed\n");
        io_send_sw(ApduReplySuccess);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
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
