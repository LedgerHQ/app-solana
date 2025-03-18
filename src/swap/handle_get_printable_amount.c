#include "handle_get_printable_amount.h"
#include "swap_lib_calls.h"
#include "swap_utils.h"
#include "utils.h"
#include "sol/printer.h"
#include "swap_common.h"

/* return 0 on error, 1 otherwise */
int handle_get_printable_amount(get_printable_amount_parameters_t *params) {
    PRINTF("Inside Solana handle_get_printable_amount\n");
    MEMCLEAR(params->printable_amount);

    uint64_t amount;
    if (!swap_str_to_u64(params->amount, params->amount_length, &amount)) {
        PRINTF("Amount is too big");
        return 0;
    }

    // Fees are displayed normally
    if (params->is_fee || params->coin_configuration == NULL) {
        PRINTF("Defaulting to native SOL amount\n");
        if (print_amount(amount, params->printable_amount, sizeof(params->printable_amount)) != 0) {
            PRINTF("print_amount failed");
            return 0;
        }
    } else {
        uint8_t decimals;
        char ticker[MAX_SWAP_TOKEN_LENGTH] = {0};
        if (!swap_parse_config(params->coin_configuration,
                               params->coin_configuration_length,
                               ticker,
                               sizeof(ticker),
                               &decimals)) {
            PRINTF("Fail to parse coin_configuration\n");
            return 0;
        }
        if (print_token_amount(amount,
                               ticker,
                               decimals,
                               params->printable_amount,
                               sizeof(params->printable_amount)) != 0) {
            PRINTF("print_amount failed");
            return 0;
        }
    }

    PRINTF("Amount %s\n", params->printable_amount);

    return 1;
}
