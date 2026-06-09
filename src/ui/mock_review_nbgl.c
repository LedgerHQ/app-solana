#include "nbgl_use_case.h"
#include "ui_api.h"
#include "apdu.h"
#include "io.h"
#include "main_std_app.h"

static uint8_t G_mock_contract;
static uint8_t G_mock_version;
static nbgl_contentTagValueList_t G_mock_content;
static nbgl_layoutTagValue_t G_mock_pair;

static void mock_review_choice(bool confirm) {
    if (confirm) {
        PRINTF("Mock review confirmed\n");
        io_send_sw(ApduReplySuccess);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
    } else {
        PRINTF("Mock review rejected\n");
        io_send_sw(ApduReplyUserRefusal);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

// Each filler returns the total number of pairs it handles.
// The callback index is guaranteed < this value by NBGL.

static uint8_t mock_contract_1_v1(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "1.5 SOL";
            break;
        case 1:
            G_mock_pair.item = "Recipient";
            G_mock_pair.value = "GrAkK...x4Jt8";
            break;
        case 2:
            G_mock_pair.item = "Fee";
            G_mock_pair.value = "0.000005 SOL";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 3;
}

static uint8_t mock_contract_1_v2(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "250 USDC";
            break;
        case 1:
            G_mock_pair.item = "Recipient";
            G_mock_pair.value = "5Hw8S...uQd3M";
            break;
        case 2:
            G_mock_pair.item = "Fee";
            G_mock_pair.value = "0.00001 SOL";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 3;
}

static uint8_t mock_contract_2_v1(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Stake Amount";
            G_mock_pair.value = "100 SOL";
            break;
        case 1:
            G_mock_pair.item = "Validator";
            G_mock_pair.value = "Certus One";
            break;
        case 2:
            G_mock_pair.item = "Stake Account";
            G_mock_pair.value = "Bkf6i...5VmRR";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 3;
}

static uint8_t mock_contract_2_v2(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Stake Amount";
            G_mock_pair.value = "5000 SOL";
            break;
        case 1:
            G_mock_pair.item = "Validator";
            G_mock_pair.value = "Everstake";
            break;
        case 2:
            G_mock_pair.item = "Stake Account";
            G_mock_pair.value = "9aE2r...kM7wD";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 3;
}

static uint8_t mock_contract_3_v1(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Collection";
            G_mock_pair.value = "DeGods";
            break;
        case 1:
            G_mock_pair.item = "Item";
            G_mock_pair.value = "DeGod #8821";
            break;
        case 2:
            G_mock_pair.item = "Price";
            G_mock_pair.value = "35.5 SOL";
            break;
        case 3:
            G_mock_pair.item = "Marketplace Fee";
            G_mock_pair.value = "1.5%";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 4;
}

static uint8_t mock_contract_3_v2(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Collection";
            G_mock_pair.value = "Mad Lads";
            break;
        case 1:
            G_mock_pair.item = "Item";
            G_mock_pair.value = "Mad Lad #4492";
            break;
        case 2:
            G_mock_pair.item = "Price";
            G_mock_pair.value = "120 SOL";
            break;
        case 3:
            G_mock_pair.item = "Marketplace Fee";
            G_mock_pair.value = "2%";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 4;
}

static uint8_t mock_contract_4_v1(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Send";
            G_mock_pair.value = "10 SOL";
            break;
        case 1:
            G_mock_pair.item = "Receive (est.)";
            G_mock_pair.value = "392.50 USDC";
            break;
        case 2:
            G_mock_pair.item = "Slippage";
            G_mock_pair.value = "0.5%";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 3;
}

static uint8_t mock_contract_4_v2(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Send";
            G_mock_pair.value = "500 USDC";
            break;
        case 1:
            G_mock_pair.item = "Receive (est.)";
            G_mock_pair.value = "12.75 SOL";
            break;
        case 2:
            G_mock_pair.item = "Slippage";
            G_mock_pair.value = "1%";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 3;
}

static uint8_t mock_contract_5_v1(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Program ID";
            G_mock_pair.value = "TokenkegQ...butj";
            break;
        case 1:
            G_mock_pair.item = "Buffer";
            G_mock_pair.value = "9xQeW...vEDjR";
            break;
        case 2:
            G_mock_pair.item = "Authority";
            G_mock_pair.value = "GrAkK...x4Jt8";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 3;
}

static uint8_t mock_contract_5_v2(uint8_t index) {
    switch (index) {
        case 0:
            G_mock_pair.item = "Program ID";
            G_mock_pair.value = "whirL...4Cnog";
            break;
        case 1:
            G_mock_pair.item = "Buffer";
            G_mock_pair.value = "6LfGh...87yGM";
            break;
        case 2:
            G_mock_pair.item = "Authority";
            G_mock_pair.value = "5Hw8S...uQd3M";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 3;
}

typedef uint8_t (*mock_fill_pair_t)(uint8_t index);

static const mock_fill_pair_t G_mock_fillers[5][2] = {
    {mock_contract_1_v1, mock_contract_1_v2},
    {mock_contract_2_v1, mock_contract_2_v2},
    {mock_contract_3_v1, mock_contract_3_v2},
    {mock_contract_4_v1, mock_contract_4_v2},
    {mock_contract_5_v1, mock_contract_5_v2},
};

static const char *const G_mock_titles[5] = {
    "Review token\ntransfer",
    "Review stake\ndelegation",
    "Review NFT\npurchase",
    "Review swap",
    "Review program\nupgrade",
};

static mock_fill_pair_t get_filler(void) {
    return (mock_fill_pair_t) PIC(G_mock_fillers[G_mock_contract - 1][G_mock_version - 1]);
}

static nbgl_contentTagValue_t *mock_get_review_pair(uint8_t index) {
    PRINTF("mock_get_review_pair index=%d\n", index);
    get_filler()(index);
    return &G_mock_pair;
}

void ui_mock_review(uint8_t contract, uint8_t version) {
    PRINTF("ui_mock_review contract=%d version=%d\n", contract, version);
    G_mock_contract = contract;
    G_mock_version = version;

    // Call filler with index 0 just to get nb_pairs from it
    uint8_t nb_pairs = get_filler()(0);

    G_mock_content.nbMaxLinesForValue = 0;
    G_mock_content.smallCaseForValue = false;
    G_mock_content.wrapping = true;
    G_mock_content.pairs = NULL;
    G_mock_content.callback = mock_get_review_pair;
    G_mock_content.startIndex = 0;
    G_mock_content.nbPairs = nb_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &G_mock_content,
                       &ICON_SIGN_MENU,
                       PIC(G_mock_titles[contract - 1]),
                       NULL,
                       NULL,
                       mock_review_choice);
}
