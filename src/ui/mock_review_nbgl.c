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

// clang-format off

// Plain non-clickable field
#define FIELD(label, val)       \
    G_mock_pair.item = (label); \
    G_mock_pair.value = (val);  \
    break

// Clickable instruction header: "Program: <name>" with program address detail
#define FIELD_PROG(label, prog_name, prog_addr)                    \
    G_mock_pair.item = (label);                                    \
    G_mock_pair.value = "Program: " prog_name;                     \
    G_swap_info_keys[0] = "Program Address";                       \
    G_swap_info_values[0] = (prog_addr);                           \
    G_swap_info_list.nbInfos = 1;                                  \
    G_swap_info_list.infoTypes = G_swap_info_keys;                 \
    G_swap_info_list.infoContents = G_swap_info_values;            \
    G_swap_extension.aliasType = INFO_LIST_ALIAS;                  \
    G_swap_extension.backText = (prog_name);                       \
    G_swap_extension.infolist = &G_swap_info_list;                 \
    G_mock_pair.aliasValue = 1;                                    \
    G_mock_pair.extension = &G_swap_extension;                     \
    break

// Clickable named address: value is a name, click expands the underlying address
#define FIELD_NAMED_ADDRESS(label, val, address)                    \
    G_mock_pair.item = (label);                                    \
    G_mock_pair.value = (val);                                     \
    G_swap_info_keys[0] = (val);                                   \
    G_swap_info_values[0] = (address);                             \
    G_swap_info_list.nbInfos = 1;                                  \
    G_swap_info_list.infoTypes = G_swap_info_keys;                 \
    G_swap_info_list.infoContents = G_swap_info_values;            \
    G_swap_extension.aliasType = INFO_LIST_ALIAS;                  \
    G_swap_extension.backText = (label);                           \
    G_swap_extension.infolist = &G_swap_info_list;                 \
    G_mock_pair.aliasValue = 1;                                    \
    G_mock_pair.extension = &G_swap_extension;                     \
    break

// Clickable address field: backText = label, shows Owner Address + Mint Address
#define FIELD_ADDR(label, val, owner, mint)                        \
    G_mock_pair.item = (label);                                    \
    G_mock_pair.value = (val);                                     \
    G_swap_info_keys[0] = "Owner Address";                         \
    G_swap_info_values[0] = (owner);                               \
    G_swap_info_keys[1] = "Mint Address";                          \
    G_swap_info_values[1] = (mint);                                \
    G_swap_info_list.nbInfos = 2;                                  \
    G_swap_info_list.infoTypes = G_swap_info_keys;                 \
    G_swap_info_list.infoContents = G_swap_info_values;            \
    G_swap_extension.aliasType = INFO_LIST_ALIAS;                  \
    G_swap_extension.backText = (label);                           \
    G_swap_extension.infolist = &G_swap_info_list;                 \
    G_mock_pair.aliasValue = 1;                                    \
    G_mock_pair.extension = &G_swap_extension;                     \
    break

// Clickable amount field: ticker extracted from val via strrchr (constant-folded by Clang)
#define FIELD_AMOUNT(label, val, account, mint)                     \
    G_mock_pair.item = (label);                                    \
    G_mock_pair.value = (val);                                     \
    G_swap_info_keys[0] = "Token Account";                         \
    G_swap_info_values[0] = (account);                             \
    G_swap_info_keys[1] = "Mint Address";                          \
    G_swap_info_values[1] = (mint);                                \
    G_swap_info_list.nbInfos = 2;                                  \
    G_swap_info_list.infoTypes = G_swap_info_keys;                 \
    G_swap_info_list.infoContents = G_swap_info_values;            \
    G_swap_extension.aliasType = INFO_LIST_ALIAS;                  \
    G_swap_extension.backText = strrchr((val), ' ') + 1;           \
    G_swap_extension.infolist = &G_swap_info_list;                 \
    G_mock_pair.aliasValue = 1;                                    \
    G_mock_pair.extension = &G_swap_extension;                     \
    break

// clang-format on

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
            FIELD_PROG("[1/1] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 1:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz";
            break;
        case 2:
            FIELD_AMOUNT("You Pay",
                         "6.524386 USDC",
                         "CapuXNQoDviLvU1PxFiizLgPNQCxrsag1uMeyk6zLVps",
                         "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        case 3:
            FIELD_AMOUNT("Minimum Received",
                         "0.00412035 ETH",
                         "BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz",
                         "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs");
        case 4:
            FIELD("Slippage Tolerance", "1%");
        case 5:
            FIELD("Platform Fee", "0%");
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 6;
}

#define TITLE_1_v2 "Review transaction"
static uint8_t mock_contract_1_v2(uint8_t index) {
    switch (index) {
        // [1/1] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz
        //   You Pay: 6.524386 USDC
        //   Minimum Received: 0.00412035 ETH
        //   Slippage Tolerance: 1%
        //   Platform Fee: 0%
        case 0:
            FIELD_PROG("[1/1] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 1:
            FIELD_ADDR("Destination",
                       "BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz",
                       "F3Br2652dZvcGUUHaj4VhVtRFcrWDoiMVKqsVn8KMjZT",
                       "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs");
        case 2:
            FIELD_AMOUNT("You Pay",
                         "6.524386 USDC",
                         "CapuXNQoDviLvU1PxFiizLgPNQCxrsag1uMeyk6zLVps",
                         "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        case 3:
            FIELD_AMOUNT("Minimum Received",
                         "0.00412035 WETH",
                         "BmDpgEq8fViLCYVfrJFwsivyMfgGL7g95NivUWqJjAnz",
                         "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs");
        case 4:
            FIELD("Slippage Tolerance", "1%");
        case 5:
            FIELD("Platform Fee", "0%");
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 6;
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
            FIELD_PROG("[1/3] Create Token Account", "Token", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        case 1:
            FIELD("Token Account", "Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC");
        case 2:
            FIELD("Owner", "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk");
        case 3:
            FIELD("Token Mint", "So11111111111111111111111111111111111111112");

        // [2/3] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC
        //   Destination Override: JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
        //   You Pay: 5638296.149973 TUG
        //   Minimum Received: 0.051118419 SOL
        //   Slippage Tolerance: 5%
        //   Platform Fee: 0%
        case 4:
            FIELD_PROG("[2/3] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 5:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC";
            break;
        case 6:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            break;
        case 7:
            FIELD_AMOUNT("You Pay",
                         "5638296.149973 TUG",
                         "CapuXNQoDviLvU1PxFiizLgPNQCxrsag1uMeyk6zLVps",
                         "G2fUfHeqzct3r2Jz61eqGqZgbK958aWzYojfZJBBVrrS");
        case 8:
            FIELD_AMOUNT("Minimum Received",
                         "0.051118419 SOL",
                         "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                         "So11111111111111111111111111111111111111111");
        case 9:
            FIELD("Slippage Tolerance", "5%");
        case 10:
            FIELD("Platform Fee", "0%");

        // [3/3] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC
        //   To: 6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk
        case 11:
            FIELD_PROG("[3/3] Close Account", "Token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 12:
            FIELD("Token Account", "Afqmz2opf59pWkLtzVgwPr3JPhpFxZrUUcsyGgtGq8GC");
        case 13:
            FIELD("To", "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk");

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
            FIELD_PROG("[1/1] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 1:
            FIELD_ADDR("Destination",
                       "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                       "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                       "So11111111111111111111111111111111111111111");
        case 2:
            FIELD_ADDR("Destination Override",
                       "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                       "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                       "So11111111111111111111111111111111111111111");
        case 3:
            FIELD_AMOUNT("You Pay",
                         "5638296.149973 TUG",
                         "CapuXNQoDviLvU1PxFiizLgPNQCxrsag1uMeyk6zLVps",
                         "G2fUfHeqzct3r2Jz61eqGqZgbK958aWzYojfZJBBVrrS");
        case 4:
            FIELD_AMOUNT("Minimum Received",
                         "0.051118419 SOL",
                         "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                         "So11111111111111111111111111111111111111111");
        case 5:
            FIELD("Slippage Tolerance", "5%");
        case 6:
            FIELD("Platform Fee", "0%");
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
            FIELD_PROG("[1/5] Create Token Account", "Token", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
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
            FIELD_PROG("[2/5] Transfer", "System", "11111111111111111111111111111111");
        case 5:
            FIELD("From", "9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj");
        case 6:
            FIELD("To", "4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA");
        case 7:
            FIELD("Amount", "0.0001 SOL");

        // [3/5] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Wrap SOL
        //   Token Account: 4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA
        case 8:
            FIELD_PROG("[3/5] Wrap SOL", "Token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 9:
            FIELD("Token Account", "4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA");

        // [4/5] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP
        //   Destination Override: E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP
        //   You Pay: 100000
        //   Minimum Received: 8.121885 Pepe
        //   Slippage Tolerance: 10%
        //   Platform Fee: 0.96%
        case 10:
            FIELD_PROG("[4/5] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 11:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP";
            break;
        case 12:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP";
            break;
        case 13:
            FIELD("You Pay", "100000");
        case 14:
            FIELD_AMOUNT("Minimum Received",
                         "8.121885 Pepe",
                         "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP",
                         "B5WTLaRwaUQpKk7ir1wniNB6m5o8GgMrimhKMYan2R6B");
        case 15:
            FIELD("Slippage Tolerance", "10%");
        case 16:
            FIELD("Platform Fee", "0.96%");

        // [5/5] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: 4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA
        //   To: 9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj
        case 17:
            FIELD_PROG("[5/5] Close Account", "Token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 18:
            FIELD("Token Account", "4AC6JSdH9biUFSqXRXdgnDFwpLwGbiBNEZZnEBMXYDSA");
        case 19:
            FIELD("To", "9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj");

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
            FIELD_PROG("[1/1] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 1:
            FIELD_ADDR("Destination",
                       "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP",
                       "9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj",
                       "B5WTLaRwaUQpKk7ir1wniNB6m5o8GgMrimhKMYan2R6B");
        case 2:
            FIELD_ADDR("Destination Override",
                       "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP",
                       "9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj",
                       "B5WTLaRwaUQpKk7ir1wniNB6m5o8GgMrimhKMYan2R6B");
        case 3:
            FIELD_AMOUNT("You Pay",
                         "0.0001 SOL",
                         "9JqWf5BVD2hEw6pHGcy4u3rFgSguxhjM5R33UZyDj5Vj",
                         "So11111111111111111111111111111111111111111");
        case 4:
            FIELD_AMOUNT("Minimum Received",
                         "8.121885 Pepe",
                         "E32WduVTqEuDZHMC4n9ggvKghjHk4P9fQ8w4evLxFWrP",
                         "B5WTLaRwaUQpKk7ir1wniNB6m5o8GgMrimhKMYan2R6B");
        case 5:
            FIELD("Slippage Tolerance", "10%");
        case 6:
            FIELD("Platform Fee", "0.96%");
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
            FIELD_PROG("[1/8] Track", "LifiTracker", "3i5JeuZuUxeKtVysUnwQNGerJP2bSMX9fTFfS4Nxe3Br");

        // [2/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm
        //   Amount: 0.000045542 SOL
        case 1:
            FIELD_PROG("[2/8] Transfer", "System", "11111111111111111111111111111111");
        case 2:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 3:
            FIELD("To", "34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm");
        case 4:
            FIELD("Amount", "0.000045542 SOL");

        // [3/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd
        //   Amount: 0.000865312 SOL
        case 5:
            FIELD_PROG("[3/8] Transfer", "System", "11111111111111111111111111111111");
        case 6:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 7:
            FIELD("To", "6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd");
        case 8:
            FIELD("Amount", "0.000865312 SOL");

        // [4/8] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   Owner: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   Token Mint: So11111111111111111111111111111111111111112 (SOL)
        case 9:
            FIELD_PROG("[4/8] Create Token Account", "Token", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        case 10:
            FIELD("Token Account", "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C");
        case 11:
            FIELD("Owner", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 12:
            FIELD("Token Mint", "So11111111111111111111111111111111111111112");

        // [5/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   Amount: 0.09017457 SOL
        case 13:
            FIELD_PROG("[5/8] Transfer", "System", "11111111111111111111111111111111");
        case 14:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 15:
            FIELD("To", "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C");
        case 16:
            FIELD("Amount", "0.09017457 SOL");

        // [6/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Wrap SOL
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        case 17:
            FIELD_PROG("[6/8] Wrap SOL", "Token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 18:
            FIELD("Token Account", "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C");

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
            FIELD_PROG("[7/8] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 20:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb";
            break;
        case 21:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            break;
        case 22:
            FIELD_AMOUNT("You Pay",
                         "0.09017457 SOL",
                         "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                         "So11111111111111111111111111111111111111111");
        case 23:
            FIELD_AMOUNT("Minimum Received",
                         "1413796.7697 WEN",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk");
        case 24:
            FIELD("Slippage Tolerance", "3%");
        case 25:
            FIELD("Platform Fee", "0%");
        case 26:
            FIELD("Positive Slippage", "0%");

        // [8/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   To: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        case 27:
            FIELD_PROG("[8/8] Close Account", "Token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 28:
            FIELD("Token Account", "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C");
        case 29:
            FIELD("To", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");

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
            FIELD_PROG("[1/3] Transfer", "System", "11111111111111111111111111111111");
        case 1:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 2:
            FIELD("To", "34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm");
        case 3:
            FIELD("Amount", "0.000045542 SOL");

        // [2/3] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd
        //   Amount: 0.000865312 SOL
        case 4:
            FIELD_PROG("[2/3] Transfer", "System", "11111111111111111111111111111111");
        case 5:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 6:
            FIELD("To", "6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd");
        case 7:
            FIELD("Amount", "0.000865312 SOL");

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
            FIELD_PROG("[3/3] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 9:
            FIELD_ADDR("Destination",
                       "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                       "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                       "WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk");
        case 10:
            FIELD_ADDR("Destination Override",
                       "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                       "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                       "WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk");
        case 11:
            FIELD_AMOUNT("You Pay",
                         "0.09017457 SOL",
                         "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                         "So11111111111111111111111111111111111111111");
        case 12:
            FIELD_AMOUNT("Minimum Received",
                         "1413796.7697 WEN",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk");
        case 13:
            FIELD("Slippage Tolerance", "3%");
        case 14:
            FIELD("Platform Fee", "0%");
        case 15:
            FIELD("Positive Slippage", "0%");
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
            FIELD_PROG("[1/8] Create Token Account",
                       "Token",
                       "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        case 1:
            FIELD("Token Account", "Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q");
        case 2:
            FIELD("Owner", "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2");
        case 3:
            FIELD("Token Mint", "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN (TRUMP)");

        // [2/8] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3
        //   Owner: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        //   Token Mint: GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU (kTRMP-SOL)
        case 4:
            FIELD_PROG("[2/8] Create Token Account",
                       "Token",
                       "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        case 5:
            FIELD("Token Account", "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3");
        case 6:
            FIELD("Owner", "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2");
        case 7:
            FIELD("Token Mint", "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU (kTRMP-SOL)");

        // [3/8] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   Owner: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        //   Token Mint: So11111111111111111111111111111111111111112 (SOL)
        case 8:
            FIELD_PROG("[3/8] Create Token Account",
                       "Token",
                       "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        case 9:
            FIELD("Token Account", "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj");
        case 10:
            FIELD("Owner", "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2");
        case 11:
            FIELD("Token Mint", "So11111111111111111111111111111111111111112 (SOL)");

        // [4/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        //   To: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   Amount: 63 SOL
        case 12:
            FIELD_PROG("[4/8] Transfer", "System", "11111111111111111111111111111111");
        case 13:
            FIELD("From", "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2");
        case 14:
            FIELD("To", "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj");
        case 15:
            FIELD("Amount", "63 SOL");

        // [5/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Wrap SOL
        //   Token Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        case 16:
            FIELD_PROG("[5/8] Wrap SOL", "Token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 17:
            FIELD("Token Account", "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj");

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
            FIELD_PROG("[6/8] Deposit",
                       "Yvaults",
                       "6LtLpnUFNByNXLyCoK9wA2MykKAmQNZKBdY8s47dehDc");
        case 19:
            FIELD_NAMED_ADDRESS("Strategy",
                                "Kamino (WSOL-TRUMP) Liquidity",
                                "EZCyRc4wzVCRXZqbBjCmdXwjErmrMLuQpKagU6baBkN9");
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
            FIELD_NAMED_ADDRESS("Shares Token",
                                "kTRMP-SOL",
                                "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU");
        case 24:
            FIELD_AMOUNT("Maximum Token A",
                         "63 SOL",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "So11111111111111111111111111111111111111111");
        case 25:
            FIELD_AMOUNT("Maximum Token B",
                         "1516.3592 TRUMP",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN");

        // [7/8] Farms (FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr)
        //   Intent: Stake
        //   Farm: BSnjobKGgjdnsKaBR9k4gvUpTe5QJREPC3pDLpYXBynH
        //   From: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3
        //   Amount: Entire balance (GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU)
        case 26:
            FIELD_PROG("[7/8] Stake", "Farms", "FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr");
        case 27:
            FIELD_NAMED_ADDRESS("Farm",
                                "Kamino Farm",
                                "BSnjobKGgjdnsKaBR9k4gvUpTe5QJREPC3pDLpYXBynH");
        case 28:
            G_mock_pair.item = "From";
            G_mock_pair.value = "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3";
            break;
        case 29:
            FIELD_AMOUNT("Amount",
                         "Entire balance kTRMP-SOL",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU");

        // [8/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   To: 9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2
        case 30:
            FIELD_PROG("[8/8] Close Account",
                       "Token",
                       "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 31:
            FIELD("Token Account", "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj");
        case 32:
            FIELD("To", "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2");

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
            FIELD_PROG("[1/3] Transfer", "System", "11111111111111111111111111111111");
        case 1:
            FIELD("From", "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2");
        case 2:
            FIELD("To", "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj");
        case 3:
            FIELD("Amount", "63 SOL");

        // [2/3] Yvaults (6LtLpnUFNByNXLyCoK9wA2MykKAmQNZKBdY8s47dehDc)
        //   Intent: Deposit
        //   Strategy: EZCyRc4wzVCRXZqbBjCmdXwjErmrMLuQpKagU6baBkN9
        //   From Token A Account: AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj
        //   From Token B Account: Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q
        //   Shares Recipient: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3 (owner
        //   9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2) Shares Token:
        //   GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU (kTRMP-SOL) Maximum Token A: 63 SOL
        //   Maximum Token B: 1516.3592 TRUMP
        case 4:
            FIELD_PROG("[2/3] Deposit", "Yvaults", "6LtLpnUFNByNXLyCoK9wA2MykKAmQNZKBdY8s47dehDc");
        case 5:
            FIELD_NAMED_ADDRESS("Strategy",
                                "Kamino (WSOL-TRUMP) Liquidity",
                                "EZCyRc4wzVCRXZqbBjCmdXwjErmrMLuQpKagU6baBkN9");
        case 6:
            FIELD_ADDR("From Token A Account",
                       "AxrzgZCphorz2BHQ9oAGDJGKA5XVGFWH2mU2DjAFPvXj",
                       "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                       "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU");
        case 7:
            FIELD_ADDR("From Token B Account",
                       "Fw4aqTfU6BuBGJzZ3ah5tzi5ERALoyWPK3Npwm1JXf4Q",
                       "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2",
                       "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN");
        case 8:
            FIELD_ADDR("Shares Recipient",
                       "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3",
                       "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2",
                       "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU");
        case 9:
            FIELD_NAMED_ADDRESS("Shares Token",
                                "kTRMP-SOL",
                                "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU");
        case 10:
            FIELD_AMOUNT("Maximum Token A",
                         "63 SOL",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "So11111111111111111111111111111111111111111");
        case 11:
            FIELD_AMOUNT("Maximum Token B",
                         "1516.3592 TRUMP",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN");

        // [3/3] Farms (FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr)
        //   Intent: Stake
        //   Farm: BSnjobKGgjdnsKaBR9k4gvUpTe5QJREPC3pDLpYXBynH
        //   From: FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3 (owner
        //   9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2)
        case 12:
            FIELD_PROG("[3/3] Stake", "Farms", "FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr");
        case 13:
            FIELD_NAMED_ADDRESS("Farm",
                                "Kamino Farm",
                                "BSnjobKGgjdnsKaBR9k4gvUpTe5QJREPC3pDLpYXBynH");
        case 14:
            FIELD_ADDR("From",
                       "FHr3LxGJ7aXFMtSaYQqFrNyxrpYUNjpLid4SmkYzQeY3",
                       "9cwywy4VbGZjwvJ7dXb8XMZ4AH4TaE27cRTUc6LH1GM2",
                       "GF8KQzYxt1Y2exRHubzK8qb8EbJa8DHs8Un35Rc1h6zU");
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 15;
}

// Contract 6 is same as 4 but we don't know the token ticker and decimal
#define TITLE_6_v1 "Review transaction"
static uint8_t mock_contract_6_v1(uint8_t index) {
    switch (index) {
        // [1/8] LifiTracker (3i5JeuZuUxeKtVysUnwQNGerJP2bSMX9fTFfS4Nxe3Br)
        //   Intent: Track
        case 0:
            FIELD_PROG("[1/8] Track", "LifiTracker", "3i5JeuZuUxeKtVysUnwQNGerJP2bSMX9fTFfS4Nxe3Br");

        // [2/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm
        //   Amount: 0.000045542 SOL
        case 1:
            FIELD_PROG("[2/8] Transfer", "System", "11111111111111111111111111111111");
        case 2:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 3:
            FIELD("To", "34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm");
        case 4:
            FIELD("Amount", "0.000045542 SOL");

        // [3/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd
        //   Amount: 0.000865312 SOL
        case 5:
            FIELD_PROG("[3/8] Transfer", "System", "11111111111111111111111111111111");
        case 6:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 7:
            FIELD("To", "6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd");
        case 8:
            FIELD("Amount", "0.000865312 SOL");

        // [4/8] Token (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL)
        //   Intent: Create Token Account
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   Owner: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   Token Mint: So11111111111111111111111111111111111111112 (SOL)
        case 9:
            FIELD_PROG("[4/8] Create Token Account", "Token", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        case 10:
            FIELD("Token Account", "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C");
        case 11:
            FIELD("Owner", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 12:
            FIELD("Token Mint", "So11111111111111111111111111111111111111112");

        // [5/8] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   Amount: 0.09017457 SOL
        case 13:
            FIELD_PROG("[5/8] Transfer", "System", "11111111111111111111111111111111");
        case 14:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 15:
            FIELD("To", "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C");
        case 16:
            FIELD("Amount", "0.09017457 SOL");

        // [6/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Wrap SOL
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        case 17:
            FIELD_PROG("[6/8] Wrap SOL", "Token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 18:
            FIELD("Token Account", "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C");

        // [7/8] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb (WEN, signer)
        //   Destination Override: JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
        //   You Pay: 0.09017457 SOL (So11111111111111111111111111111111111111112)
        //   Minimum Received: 14137967697 ??? (WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk)
        //   Slippage Tolerance: 3%
        //   Platform Fee: 0%
        //   Positive Slippage: 0%
        case 19:
            FIELD_PROG("[7/8] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 20:
            G_mock_pair.item = "Destination";
            G_mock_pair.value = "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb";
            break;
        case 21:
            G_mock_pair.item = "Destination Override";
            G_mock_pair.value = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
            break;
        case 22:
            FIELD_AMOUNT("You Pay",
                         "0.09017457 SOL",
                         "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                         "So11111111111111111111111111111111111111111");
        case 23:
            FIELD_AMOUNT("Minimum Received",
                         "14137967697 ???",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk");
        case 24:
            FIELD("Slippage Tolerance", "3%");
        case 25:
            FIELD("Platform Fee", "0%");
        case 26:
            FIELD("Positive Slippage", "0%");

        // [8/8] Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
        //   Intent: Close Account
        //   Token Account: 6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C
        //   To: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        case 27:
            FIELD_PROG("[8/8] Close Account", "Token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        case 28:
            FIELD("Token Account", "6xF1biKnqtz9fk7TJLSkPVdZUuu1BHPP5NbqSK8miZ3C");
        case 29:
            FIELD("To", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");

        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 30;
}

// Contract 6 is same as 4 but we don't know the token ticker and decimal
#define TITLE_6_v2 "Review transaction"
static uint8_t mock_contract_6_v2(uint8_t index) {
    switch (index) {
        // [1/3] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm
        //   Amount: 0.000045542 SOL
        case 0:
            FIELD_PROG("[1/3] Transfer", "System", "11111111111111111111111111111111");
        case 1:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 2:
            FIELD("To", "34FKjAdVcTax2DHqV2XnbXa9J3zmyKcFuFKWbcmgxjgm");
        case 3:
            FIELD("Amount", "0.000045542 SOL");

        // [2/3] System (11111111111111111111111111111111)
        //   Intent: Transfer
        //   From: 4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj
        //   To: 6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd
        //   Amount: 0.000865312 SOL
        case 4:
            FIELD_PROG("[2/3] Transfer", "System", "11111111111111111111111111111111");
        case 5:
            FIELD("From", "4MouUsUXSWzkKWn2mu427ikpoX5PmBdSNKxdxj2kJHAj");
        case 6:
            FIELD("To", "6ooVBXhnqAXaF91cu49YmWhoFuE6WLdZWTwNYvTuhyBd");
        case 7:
            FIELD("Amount", "0.000865312 SOL");

        // [3/3] Jupiter (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
        //   Intent: Swap
        //   Destination: AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb
        //   Destination Override: AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb
        //   You Pay: 0.09017457 SOL
        //   Minimum Received: 14137967697 ???
        //   Slippage Tolerance: 3%
        //   Platform Fee: 0%
        //   Positive Slippage: 0%
        case 8:
            FIELD_PROG("[3/3] Swap", "Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        case 9:
            FIELD_ADDR("Destination",
                       "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                       "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                       "WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk");
        case 10:
            FIELD_ADDR("Destination Override",
                       "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                       "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                       "WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk");
        case 11:
            FIELD_AMOUNT("You Pay",
                         "0.09017457 SOL",
                         "6qKCtrdDf3tAeMgJL8MX4n4jfLUhjt5xDusjtk3TaFAk",
                         "So11111111111111111111111111111111111111111");
        case 12:
            FIELD_AMOUNT("Minimum Received",
                         "14137967697 ???",
                         "AwzXYED61Un7szfT5ZtYmLF1vy2iTQzgVKLhS3pC1AGb",
                         "WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk");
        case 13:
            FIELD("Slippage Tolerance", "3%");
        case 14:
            FIELD("Platform Fee", "0%");
        case 15:
            FIELD("Positive Slippage", "0%");
        default:
            PRINTF("Fatal: unexpected index %d\n", index);
            app_exit();
    }
    return 16;
}

typedef uint8_t (*mock_fill_pair_t)(uint8_t index);

static const mock_fill_pair_t G_mock_fillers[6][2] = {
    {mock_contract_1_v1, mock_contract_1_v2},
    {mock_contract_2_v1, mock_contract_2_v2},
    {mock_contract_3_v1, mock_contract_3_v2},
    {mock_contract_4_v1, mock_contract_4_v2},
    {mock_contract_5_v1, mock_contract_5_v2},
    {mock_contract_6_v1, mock_contract_6_v2},
};

static const char *const G_mock_titles[6][2] = {
    {TITLE_1_v1, TITLE_1_v2},
    {TITLE_2_v1, TITLE_2_v2},
    {TITLE_3_v1, TITLE_3_v2},
    {TITLE_4_v1, TITLE_4_v2},
    {TITLE_5_v1, TITLE_5_v2},
    {TITLE_6_v1, TITLE_6_v2},
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
