#include "nbgl_use_case.h"
#include "ui_api.h"
#include "apdu.h"
#include "io.h"
#include "main_std_app.h"

static uint8_t G_mock_contract;
static uint8_t G_mock_version;
static nbgl_contentTagValueList_t G_mock_content;
static nbgl_layoutTagValue_t G_mock_pair;

// Extension data for clickable swap item in contract 1 v1 (in RAM to avoid PIC issues)
static const char *G_swap_info_keys[2];
static const char *G_swap_info_values[2];
static nbgl_contentInfoList_t G_swap_info_list;
static nbgl_contentValueExt_t G_swap_extension;

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

#define TITLE_1_v1 "Review transaction"
static uint8_t mock_contract_1_v1(uint8_t index) {
    switch (index) {
        // [1/1] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz
        //   You Pay: 6.524386 USDC
        //   Minimum Received: 0.00412035 ETH
        //   Slippage Tolerance: 1%
        //   Platform Fee: 0%
        case 0:
            G_mock_pair.item = "[1/1] Swap";
            G_mock_pair.value = "Porgram: Jupiter";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Jupiter";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 1:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz";
            break;
        case 2:
            G_mock_pair.item = "You Pay";
            G_mock_pair.value = "6.524386 USDC";
            break;
        case 3:
            G_mock_pair.item = "Minimum Received";
            G_mock_pair.value = "0.00412035 ETH";
            break;
        case 4:
            G_mock_pair.item = "Slippage Tolerance";
            G_mock_pair.value = "1%";
            break;
        case 5:
            G_mock_pair.item = "Platform Fee";
            G_mock_pair.value = "0%";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 6;
}

#define TITLE_1_v2 "Review transaction"
static uint8_t mock_contract_1_v2(uint8_t index) {
    // Same
    return mock_contract_1_v1(index);
}

#define TITLE_2_v1 "Review transaction"
static uint8_t mock_contract_2_v1(uint8_t index) {
    switch (index) {
        // [1/3] Token (ATok...8knL)
        //   Intent: Create Token Account
        //   Token Account: Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC
        //   Owner: 6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk
        //   Token Mint: So11111111111111111111111111111111111111112 (SOL)
        case 0:
            G_mock_pair.item = "[1/3] Create Token Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 1:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC";
            break;
        case 2:
            G_mock_pair.item = "Owner";
            G_mock_pair.value = "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk";
            break;
        case 3:
            G_mock_pair.item = "Token Mint";
            G_mock_pair.value = "So11111111111111111111111111111111111111112";
            break;

        // [2/3] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC
        //   Destination Override: JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
        //   You Pay: 5638296.149973 TUG
        //   Minimum Received: 0.051118419 SOL
        //   Slippage Tolerance: 5%
        //   Platform Fee: 0%
        case 4:
            G_mock_pair.item = "[2/3] Swap";
            G_mock_pair.value = "Porgram: Jupiter";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Jupiter";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 5:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC";
            break;
        case 6:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            break;
        case 7:
            G_mock_pair.item = "You Pay";
            G_mock_pair.value = "5638296.149973 TUG";
            break;
        case 8:
            G_mock_pair.item = "Minimum Received";
            G_mock_pair.value = "0.051118419 SOL";
            break;
        case 9:
            G_mock_pair.item = "Slippage Tolerance";
            G_mock_pair.value = "5%";
            break;
        case 10:
            G_mock_pair.item = "Platform Fee";
            G_mock_pair.value = "0%";
            break;

        // [3/3] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC
        //   To: 6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk
        case 11:
            G_mock_pair.item = "[3/3] Close Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 12:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC";
            break;
        case 13:
            G_mock_pair.item = "To";
            G_mock_pair.value = "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk";
            break;

        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 14;
}

#define TITLE_2_v2 "Review transaction"
static uint8_t mock_contract_2_v2(uint8_t index) {
    switch (index) {
        // [1/1] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: 6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk
        //   Destination Override: 6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk
        //   You Pay: 5638296.149973 TUG
        //   Minimum Received: 0.051118419 SOL
        //   Slippage Tolerance: 5%
        //   Platform Fee: 0%
        case 0:
            G_mock_pair.item = "[1/1] Swap";
            G_mock_pair.value = "Porgram: Jupiter";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Jupiter";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 1:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk";
            break;
        case 2:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk";
            break;
        case 3:
            G_mock_pair.item = "You Pay";
            G_mock_pair.value = "5638296.149973 TUG";
            break;
        case 4:
            G_mock_pair.item = "Minimum Received";
            G_mock_pair.value = "0.051118419 SOL";
            break;
        case 5:
            G_mock_pair.item = "Slippage Tolerance";
            G_mock_pair.value = "5%";
            break;
        case 6:
            G_mock_pair.item = "Platform Fee";
            G_mock_pair.value = "0%";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 7;
}

#define TITLE_3_v1 "Review transaction"
static uint8_t mock_contract_3_v1(uint8_t index) {
    switch (index) {
        // [1/5] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: 4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA
        //   Owner: 9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj
        //   Token Mint: So11111111111111111111111111111111111111112 (SOL)
        case 0:
            G_mock_pair.item = "[1/5] Create Token Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 1:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA";
            break;
        case 2:
            G_mock_pair.item = "Owner";
            G_mock_pair.value = "9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj";
            break;
        case 3:
            G_mock_pair.item = "Token Mint";
            G_mock_pair.value = "So11111111111111111111111111111111111111112";
            break;

        // [2/5] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj
        //   To: 4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA
        //   Amount: 0.0001 SOL
        case 4:
            G_mock_pair.item = "[2/5] Transfer";
            G_mock_pair.value = "Porgram: System";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "11111111111111111111111111111111";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "System";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 5:
            G_mock_pair.item = "From";
            G_mock_pair.value = "9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj";
            break;
        case 6:
            G_mock_pair.item = "To";
            G_mock_pair.value = "4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA";
            break;
        case 7:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "0.0001 SOL";
            break;

        // [3/5] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Wrap SOL
        //   Token Account: 4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA
        case 8:
            G_mock_pair.item = "[3/5] Wrap SOL";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 9:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA";
            break;

        // [4/5] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP
        //   Destination Override: E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP
        //   You Pay: 100000
        //   Minimum Received: 8.121885 Pepe
        //   Slippage Tolerance: 10%
        //   Platform Fee: 0.96%
        case 10:
            G_mock_pair.item = "[4/5] Swap";
            G_mock_pair.value = "Porgram: Jupiter";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Jupiter";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 11:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP";
            break;
        case 12:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP";
            break;
        case 13:
            G_mock_pair.item = "You Pay";
            G_mock_pair.value = "100000";
            break;
        case 14:
            G_mock_pair.item = "Minimum Received";
            G_mock_pair.value = "8.121885 Pepe";
            break;
        case 15:
            G_mock_pair.item = "Slippage Tolerance";
            G_mock_pair.value = "10%";
            break;
        case 16:
            G_mock_pair.item = "Platform Fee";
            G_mock_pair.value = "0.96%";
            break;

        // [5/5] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: 4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA
        //   To: 9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj
        case 17:
            G_mock_pair.item = "[5/5] Close Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 18:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA";
            break;
        case 19:
            G_mock_pair.item = "To";
            G_mock_pair.value = "9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj";
            break;

        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 20;
}

#define TITLE_3_v2 "Review transaction"
static uint8_t mock_contract_3_v2(uint8_t index) {
    switch (index) {
        // [1/1] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP
        //   Destination Override: E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP
        //   You Pay: 0.0001 SOL
        //   Minimum Received: 8.121885 Pepe
        //   Slippage Tolerance: 10%
        //   Platform Fee: 0.96%
        case 0:
            G_mock_pair.item = "[1/1] Swap";
            G_mock_pair.value = "Porgram: Jupiter";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Jupiter";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 1:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP";
            break;
        case 2:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP";
            break;
        case 3:
            G_mock_pair.item = "You Pay";
            G_mock_pair.value = "0.0001 SOL";
            break;
        case 4:
            G_mock_pair.item = "Minimum Received";
            G_mock_pair.value = "8.121885 Pepe";
            break;
        case 5:
            G_mock_pair.item = "Slippage Tolerance";
            G_mock_pair.value = "10%";
            break;
        case 6:
            G_mock_pair.item = "Platform Fee";
            G_mock_pair.value = "0.96%";
            break;
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 7;
}

#define TITLE_4_v1 "Review transaction"
static uint8_t mock_contract_4_v1(uint8_t index) {
    switch (index) {
        // [1/8] LifiTracker (3i5JeuZuUxeKtVysUnwQNGerJP2bSMX9fTFfS4Nxe3Br)
        //   Intent: Track
        case 0:
            G_mock_pair.item = "[1/8] Track";
            G_mock_pair.value = "Porgram: LifiTracker";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "3i5JeuZuUxeKtVysUnwQNGerJP2bSMX9fTFfS4Nxe3Br";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "LifiTracker";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;

        // [2/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm
        //   Amount: 0.000045542 SOL
        case 1:
            G_mock_pair.item = "[2/8] Transfer";
            G_mock_pair.value = "Porgram: System";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "11111111111111111111111111111111";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "System";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 2:
            G_mock_pair.item = "From";
            G_mock_pair.value = "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj";
            break;
        case 3:
            G_mock_pair.item = "To";
            G_mock_pair.value = "34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm";
            break;
        case 4:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "0.000045542 SOL";
            break;

        // [3/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd
        //   Amount: 0.000865312 SOL
        case 5:
            G_mock_pair.item = "[3/8] Transfer";
            G_mock_pair.value = "Porgram: System";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "11111111111111111111111111111111";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "System";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 6:
            G_mock_pair.item = "From";
            G_mock_pair.value = "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj";
            break;
        case 7:
            G_mock_pair.item = "To";
            G_mock_pair.value = "6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd";
            break;
        case 8:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "0.000865312 SOL";
            break;

        // [4/8] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   Owner: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   Token Mint: So11111111111111111111111111111111111111112 (SOL)
        case 9:
            G_mock_pair.item = "[4/8] Create Token Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 10:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C";
            break;
        case 11:
            G_mock_pair.item = "Owner";
            G_mock_pair.value = "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj";
            break;
        case 12:
            G_mock_pair.item = "Token Mint";
            G_mock_pair.value = "So11111111111111111111111111111111111111112";
            break;

        // [5/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   Amount: 0.09017457 SOL
        case 13:
            G_mock_pair.item = "[5/8] Transfer";
            G_mock_pair.value = "Porgram: System";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "11111111111111111111111111111111";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "System";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 14:
            G_mock_pair.item = "From";
            G_mock_pair.value = "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj";
            break;
        case 15:
            G_mock_pair.item = "To";
            G_mock_pair.value = "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C";
            break;
        case 16:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "0.09017457 SOL";
            break;

        // [6/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Wrap SOL
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        case 17:
            G_mock_pair.item = "[6/8] Wrap SOL";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 18:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C";
            break;

        // [7/8] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb (WEN, signer)
        //   Destination Override: JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
        //   You Pay: 0.09017457 SOL (So11111111111111111111111111111111111111112)
        //   Minimum Received: 1413796.7697 WEN (WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk)
        //   Slippage Tolerance: 3%
        //   Platform Fee: 0%
        //   Positive Slippage: 0%
        case 19:
            G_mock_pair.item = "[7/8] Swap";
            G_mock_pair.value = "Porgram: Jupiter";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Jupiter";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 20:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb (WEN, signer)";
            break;
        case 21:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            break;
        case 22:
            G_mock_pair.item = "You Pay";
            G_mock_pair.value = "0.09017457 SOL (So11111111111111111111111111111111111111112)";
            break;
        case 23:
            G_mock_pair.item = "Minimum Received";
            G_mock_pair.value = "1413796.7697 WEN (WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk)";
            break;
        case 24:
            G_mock_pair.item = "Slippage Tolerance";
            G_mock_pair.value = "3%";
            break;
        case 25:
            G_mock_pair.item = "Platform Fee";
            G_mock_pair.value = "0%";
            break;
        case 26:
            G_mock_pair.item = "Positive Slippage";
            G_mock_pair.value = "0%";
            break;

        // [8/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   To: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        case 27:
            G_mock_pair.item = "[8/8] Close Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 28:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C";
            break;
        case 29:
            G_mock_pair.item = "To";
            G_mock_pair.value = "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj";
            break;

        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 30;
}

#define TITLE_4_v2 "Review transaction"
static uint8_t mock_contract_4_v2(uint8_t index) {
    switch (index) {
        // [1/3] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm
        //   Amount: 0.000045542 SOL
        case 0:
            G_mock_pair.item = "[1/3] Transfer";
            G_mock_pair.value = "Porgram: System";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "11111111111111111111111111111111";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "System";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 1:
            G_mock_pair.item = "From";
            G_mock_pair.value = "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj";
            break;
        case 2:
            G_mock_pair.item = "To";
            G_mock_pair.value = "34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm";
            break;
        case 3:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "0.000045542 SOL";
            break;

        // [2/3] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd
        //   Amount: 0.000865312 SOL
        case 4:
            G_mock_pair.item = "[2/3] Transfer";
            G_mock_pair.value = "Porgram: System";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "11111111111111111111111111111111";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "System";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 5:
            G_mock_pair.item = "From";
            G_mock_pair.value = "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj";
            break;
        case 6:
            G_mock_pair.item = "To";
            G_mock_pair.value = "6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd";
            break;
        case 7:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "0.000865312 SOL";
            break;

        // [3/3] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb
        //   Destination Override: AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb
        //   You Pay: 0.09017457 SOL
        //   Minimum Received: 1413796.7697 WEN
        //   Slippage Tolerance: 3%
        //   Platform Fee: 0%
        //   Positive Slippage: 0%
        case 8:
            G_mock_pair.item = "[3/3] Swap";
            G_mock_pair.value = "Porgram: Jupiter";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Jupiter";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 9:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb";
            break;
        case 10:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb";
            break;
        case 11:
            G_mock_pair.item = "You Pay";
            G_mock_pair.value = "0.09017457 SOL";
            break;
        case 12:
            G_mock_pair.item = "Minimum Received";
            G_mock_pair.value = "1413796.7697 WEN";
            break;
        case 13:
            G_mock_pair.item = "Slippage Tolerance";
            G_mock_pair.value = "3%";
            break;
        case 14:
            G_mock_pair.item = "Platform Fee";
            G_mock_pair.value = "0%";
            break;
        case 15:
            G_mock_pair.item = "Positive Slippage";
            G_mock_pair.value = "0%";
            break;

        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 16;
}

#define TITLE_5_v1 "Review transaction"
static uint8_t mock_contract_5_v1(uint8_t index) {
    switch (index) {
        // [1/8] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q
        //   Owner: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        //   Token Mint: 6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN (TRUMP)
        case 0:
            G_mock_pair.item = "[1/8] Create Token Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 1:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q";
            break;
        case 2:
            G_mock_pair.item = "Owner";
            G_mock_pair.value = "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2";
            break;
        case 3:
            G_mock_pair.item = "Token Mint";
            G_mock_pair.value = "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN (TRUMP)";
            break;

        // [2/8] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3
        //   Owner: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        //   Token Mint: GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU (kTRMP-SOL)
        case 4:
            G_mock_pair.item = "[2/8] Create Token Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 5:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3";
            break;
        case 6:
            G_mock_pair.item = "Owner";
            G_mock_pair.value = "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2";
            break;
        case 7:
            G_mock_pair.item = "Token Mint";
            G_mock_pair.value = "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU (kTRMP-SOL)";
            break;

        // [3/8] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   Owner: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        //   Token Mint: So11111111111111111111111111111111111111112 (SOL)
        case 8:
            G_mock_pair.item = "[3/8] Create Token Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 9:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj";
            break;
        case 10:
            G_mock_pair.item = "Owner";
            G_mock_pair.value = "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2";
            break;
        case 11:
            G_mock_pair.item = "Token Mint";
            G_mock_pair.value = "So11111111111111111111111111111111111111112 (SOL)";
            break;

        // [4/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        //   To: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   Amount: 63 SOL
        case 12:
            G_mock_pair.item = "[4/8] Transfer";
            G_mock_pair.value = "Porgram: System";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "11111111111111111111111111111111";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "System";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 13:
            G_mock_pair.item = "From";
            G_mock_pair.value = "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2";
            break;
        case 14:
            G_mock_pair.item = "To";
            G_mock_pair.value = "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj";
            break;
        case 15:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "63 SOL";
            break;

        // [5/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Wrap SOL
        //   Token Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        case 16:
            G_mock_pair.item = "[5/8] Wrap SOL";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 17:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj";
            break;

        // [6/8] Yvaults (6LtLpnUFNByNXLyCoK9wA2MykKAmQNZKBdY8s47dehDc)
        //   Intent: Deposit
        //   Strategy: EZCyRc4wzVCRXZqbBjCmdXwjErmrMLuQpKagU6baBkN9
        //   From Token A Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   From Token B Account: Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q
        //   Shares Recipient: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3
        //   Shares Token: GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU
        //   Maximum Token A: 63 SOL
        //   Maximum Token B: 1516.3592 TRUMP
        case 18:
            G_mock_pair.item = "[6/8] Deposit";
            G_mock_pair.value = "Porgram: Yvaults";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "6LtLpnUFNByNXLyCoK9wA2MykKAmQNZKBdY8s47dehDc";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Yvaults";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 19:
            G_mock_pair.item = "Strategy";
            G_mock_pair.value = "EZCyRc4wzVCRXZqbBjCmdXwjErmrMLuQpKagU6baBkN9";
            break;
        case 20:
            G_mock_pair.item = "From Token A Account";
            G_mock_pair.value = "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj";
            break;
        case 21:
            G_mock_pair.item = "From Token B Account";
            G_mock_pair.value = "Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q";
            break;
        case 22:
            G_mock_pair.item = "Shares Recipient";
            G_mock_pair.value = "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3";
            break;
        case 23:
            G_mock_pair.item = "Shares Token";
            G_mock_pair.value = "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU";
            break;
        case 24:
            G_mock_pair.item = "Maximum Token A";
            G_mock_pair.value = "63 SOL";
            break;
        case 25:
            G_mock_pair.item = "Maximum Token B";
            G_mock_pair.value = "1516.3592 TRUMP";
            break;

        // [7/8] Farms (FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr)
        //   Intent: Stake
        //   Farm: BSnjobKGgjdnsKaBR9k4gvUpTe5QJREPC3pDLpYXBynH
        //   From: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3
        //   Amount: Entire balance (GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU)
        case 26:
            G_mock_pair.item = "[7/8] Stake";
            G_mock_pair.value = "Porgram: Farms";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Farms";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 27:
            G_mock_pair.item = "Farm";
            G_mock_pair.value = "BSnjobKGgjdnsKaBR9k4gvUpTe5QJREPC3pDLpYXBynH";
            break;
        case 28:
            G_mock_pair.item = "From";
            G_mock_pair.value = "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3";
            break;
        case 29:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "Entire balance (GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU)";
            break;

        // [8/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   To: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        case 30:
            G_mock_pair.item = "[8/8] Close Account";
            G_mock_pair.value = "Porgram: Token";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Token";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 31:
            G_mock_pair.item = "Token Account";
            G_mock_pair.value = "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj";
            break;
        case 32:
            G_mock_pair.item = "To";
            G_mock_pair.value = "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2";
            break;

        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 33;
}

#define TITLE_5_v2 "Review transaction"
static uint8_t mock_contract_5_v2(uint8_t index) {
    switch (index) {
        // [1/3] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        //   To: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   Amount: 63 SOL
        case 0:
            G_mock_pair.item = "[1/3] Transfer";
            G_mock_pair.value = "Porgram: System";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "11111111111111111111111111111111";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "System";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 1:
            G_mock_pair.item = "From";
            G_mock_pair.value = "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2";
            break;
        case 2:
            G_mock_pair.item = "To";
            G_mock_pair.value = "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj";
            break;
        case 3:
            G_mock_pair.item = "Amount";
            G_mock_pair.value = "63 SOL";
            break;

        // [2/3] Yvaults (6LtLpnUFNByNXLyCoK9wA2MykKAmQNZKBdY8s47dehDc)
        //   Intent: Deposit
        //   Strategy: EZCyRc4wzVCRXZqbBjCmdXwjErmrMLuQpKagU6baBkN9
        //   From Token A Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   From Token B Account: Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q
        //   Shares Recipient: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3 (owner 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2)
        //   Shares Token: GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU (kTRMP-SOL)
        //   Maximum Token A: 63 SOL
        //   Maximum Token B: 1516.3592 TRUMP
        case 4:
            G_mock_pair.item = "[2/3] Deposit";
            G_mock_pair.value = "Porgram: Yvaults";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "6LtLpnUFNByNXLyCoK9wA2MykKAmQNZKBdY8s47dehDc";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Yvaults";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 5:
            G_mock_pair.item = "Strategy";
            G_mock_pair.value = "EZCyRc4wzVCRXZqbBjCmdXwjErmrMLuQpKagU6baBkN9";
            break;
        case 6:
            G_mock_pair.item = "From Token A Account";
            G_mock_pair.value = "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj";
            break;
        case 7:
            G_mock_pair.item = "From Token B Account";
            G_mock_pair.value = "Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q";
            break;
        case 8:
            G_mock_pair.item = "Shares Recipient";
            G_mock_pair.value = "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3 (owner 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2)";
            break;
        case 9:
            G_mock_pair.item = "Shares Token";
            G_mock_pair.value = "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU (kTRMP-SOL)";
            break;
        case 10:
            G_mock_pair.item = "Maximum Token A";
            G_mock_pair.value = "63 SOL";
            break;
        case 11:
            G_mock_pair.item = "Maximum Token B";
            G_mock_pair.value = "1516.3592 TRUMP";
            break;

        // [3/3] Farms (FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr)
        //   Intent: Stake
        //   Farm: BSnjobKGgjdnsKaBR9k4gvUpTe5QJREPC3pDLpYXBynH
        //   From: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3 (owner 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2)
        case 12:
            G_mock_pair.item = "[3/3] Stake";
            G_mock_pair.value = "Porgram: Farms";

            G_swap_info_keys[0] = "Program Address";
            G_swap_info_values[0] = "FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr";
            G_swap_info_list.nbInfos = 1;
            G_swap_info_list.infoTypes = G_swap_info_keys;
            G_swap_info_list.infoContents = G_swap_info_values;
            G_swap_extension.aliasType = INFO_LIST_ALIAS;
            G_swap_extension.backText = "Farms";
            G_swap_extension.infolist = &G_swap_info_list;
            G_mock_pair.aliasValue = 1;
            G_mock_pair.extension = &G_swap_extension;
            break;
        case 13:
            G_mock_pair.item = "Farm";
            G_mock_pair.value = "BSnjobKGgjdnsKaBR9k4gvUpTe5QJREPC3pDLpYXBynH";
            break;
        case 14:
            G_mock_pair.item = "From";
            G_mock_pair.value = "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3 (owner 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2)";
            break;

        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 15;
}

typedef uint8_t (*mock_fill_pair_t)(uint8_t index);

static const mock_fill_pair_t G_mock_fillers[5][2] = {
    {mock_contract_1_v1, mock_contract_1_v2},
    {mock_contract_2_v1, mock_contract_2_v2},
    {mock_contract_3_v1, mock_contract_3_v2},
    {mock_contract_4_v1, mock_contract_4_v2},
    {mock_contract_5_v1, mock_contract_5_v2},
};

static const char *const G_mock_titles[5][2] = {
    {TITLE_1_v1, TITLE_1_v2},
    {TITLE_2_v1, TITLE_2_v2},
    {TITLE_3_v1, TITLE_3_v2},
    {TITLE_4_v1, TITLE_4_v2},
    {TITLE_5_v1, TITLE_5_v2},
};

static mock_fill_pair_t get_filler(void) {
    return (mock_fill_pair_t) PIC(G_mock_fillers[G_mock_contract - 1][G_mock_version - 1]);
}

static nbgl_contentTagValue_t *mock_get_review_pair(uint8_t index) {
    PRINTF("mock_get_review_pair index=%d\n", index);
    // Clear extension fields so non-clickable items don't inherit stale state
    G_mock_pair.aliasValue = 0;
    G_mock_pair.extension = NULL;
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
                       PIC(G_mock_titles[contract - 1][version - 1]),
                       NULL,
#ifdef SCREEN_SIZE_WALLET
                       "Sign transaction on the Solana network?",
#else
                       NULL,
#endif
                       mock_review_choice);
}
