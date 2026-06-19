// --8<-- [start:copy_transaction_parameters]
#include "handle_swap_sign_transaction.h"
#include "utils.h"
#include "os.h"
#include "swap_lib_calls.h"
#include "swap_utils.h"
#include "sol/printer.h"
#include "swap_common.h"
#include "util.h"
#include "base58.h"

typedef struct swap_validated_s {
    bool initialized;
    swap_mode_t swap_mode;
    uint32_t template_id;
    uint8_t tx_hash[TX_HASH_SIZE];
    uint8_t decimals;
    char ticker[MAX_SWAP_TOKEN_LENGTH];
    uint64_t amount;
    uint64_t fee;
    char recipient[BASE58_PUBKEY_LENGTH];
} swap_validated_t;

static swap_validated_t G_swap_validated;

// Save the data validated during the Exchange app flow
bool swap_copy_transaction_parameters(create_transaction_parameters_t *params) {
    // first copy parameters to stack, and then to global data.
    // We need this "trick" as the input data position can overlap with app globals
    swap_validated_t swap_validated;
    memset(&swap_validated, 0, sizeof(swap_validated));

    // destination_address_extra_id: a raw pointer into Exchange's memory with no length field.
    //
    // SIZE CONTRACT (enforced by Exchange, cannot be verified here):
    //   EXTRA_ID_TYPE_NATIVE:          buffer must be >= EXTRA_ID_NATIVE_MIN_SIZE bytes
    //   EXTRA_ID_TYPE_SOLANA_TEMPLATE: buffer must be >= EXTRA_ID_SOLANA_TEMPLATE_MIN_SIZE bytes
    // See swap_common.h for the expected binary layout of each type.
    if (params->destination_address_extra_id != NULL) {
        switch (params->destination_address_extra_id[0]) {  // byte [0]: type
            case EXTRA_ID_TYPE_NATIVE:
                swap_validated.swap_mode = SWAP_MODE_STANDARD;
                PRINTF("Standard swap\n");
                break;
            case EXTRA_ID_TYPE_SOLANA_TEMPLATE:
                swap_validated.swap_mode = SWAP_MODE_CROSSCHAIN;
                // bytes [1..4]: template_id as big-endian uint32_t
                swap_validated.template_id = U4BE(
                    (uint8_t *) params->destination_address_extra_id + 1,
                    0);
                // bytes [5..36]: tx_hash (SHA256 of the transaction message)
                memcpy(swap_validated.tx_hash,
                       (uint8_t *) params->destination_address_extra_id + 1 + TEMPLATE_ID_SIZE,
                       TX_HASH_SIZE);
                PRINTF("Crosschain swap with template_id: %.*H\n",
                       TEMPLATE_ID_SIZE,
                       (uint8_t *) params->destination_address_extra_id + 1);
                PRINTF("Crosschain swap tx_hash: %.*H\n", TX_HASH_SIZE, swap_validated.tx_hash);
                break;
            default:
                PRINTF("Invalid or unknown swap protocol\n");
                swap_validated.swap_mode = SWAP_MODE_ERROR;
        }
    } else {
        swap_validated.swap_mode = SWAP_MODE_STANDARD;
    }

    // Parse config and save decimals and ticker
    // If there is no coin_configuration, consider that we are doing a SOL swap
    if (params->coin_configuration == NULL) {
        memcpy(swap_validated.ticker, "SOL", sizeof("SOL"));
        swap_validated.decimals = SOL_DECIMALS;
    } else {
        if (!swap_parse_config(params->coin_configuration,
                               params->coin_configuration_length,
                               swap_validated.ticker,
                               sizeof(swap_validated.ticker),
                               &swap_validated.decimals)) {
            PRINTF("Fail to parse coin_configuration\n");
            return false;
        }
    }

    // Save recipient
    strlcpy(swap_validated.recipient,
            params->destination_address,
            sizeof(swap_validated.recipient));
    if (swap_validated.recipient[sizeof(swap_validated.recipient) - 1] != '\0') {
        PRINTF("Address copy error\n");
        return false;
    }

    // Save amount
    if (!swap_str_to_u64(params->amount, params->amount_length, &swap_validated.amount)) {
        return false;
    }

    // Save amount
    if (!swap_str_to_u64(params->fee_amount, params->fee_amount_length, &swap_validated.fee)) {
        return false;
    }

    swap_validated.initialized = true;

    // Full reset the global variables
    os_explicit_zero_BSS_segment();

    // Commit the values read from exchange to the clean global space
    memcpy(&G_swap_validated, &swap_validated, sizeof(swap_validated));
    return true;
}
// --8<-- [end:copy_transaction_parameters]

// Check that the amount in parameter is the same as the previously saved amount
bool check_swap_amount(const char *text) {
    if (!G_swap_validated.initialized) {
        return false;
    }

    char validated_amount[MAX_PRINTABLE_AMOUNT_SIZE];
    if (print_token_amount(G_swap_validated.amount,
                           G_swap_validated.ticker,
                           G_swap_validated.decimals,
                           validated_amount,
                           sizeof(validated_amount)) != 0) {
        PRINTF("Conversion failed\n");
        return false;
    }

    if (strcmp(text, validated_amount) == 0) {
        return true;
    } else {
        PRINTF("Amount requested in this transaction = %s\n", text);
        PRINTF("Amount validated in swap = %s\n", validated_amount);
        return false;
    }
}

bool check_swap_amount_raw_less_or_equal(uint64_t amount) {
    if (!G_swap_validated.initialized) {
        PRINTF("check_swap_amount_raw_less_or_equal internal error\n");
        return false;
    }

    debug_print_u64("Received amount", amount);
    debug_print_u64("Validated G_swap_validated.amount", G_swap_validated.amount);
    if (amount > G_swap_validated.amount) {
        PRINTF("Amount exceeds the validated swap amount\n");
        return false;
    }

    PRINTF("Amount validated\n");
    return true;
}

int get_swap_amount_raw(uint64_t *amount) {
    if (!G_swap_validated.initialized) {
        PRINTF("get_swap_amount_raw internal error\n");
        return -1;
    }
    *amount = G_swap_validated.amount;
    return 0;
}

bool check_swap_ticker(const char *ticker) {
    if (ticker == NULL || !G_swap_validated.initialized) {
        PRINTF("check_swap_ticker internal error\n");
        return false;
    }

    if (strncmp(ticker, G_swap_validated.ticker, MAX_SWAP_TOKEN_LENGTH) != 0) {
        PRINTF("Ticker mismatch: received %s, validated %s\n", ticker, G_swap_validated.ticker);
        return false;
    }
    return true;
}

const char *get_swap_ticker() {
    if (!G_swap_validated.initialized) {
        PRINTF("check_swap_ticker internal error\n");
        return NULL;
    }
    return G_swap_validated.ticker;
}

bool check_swap_fee(const char *text) {
    if (!G_swap_validated.initialized) {
        return false;
    }

    char validated_fee[MAX_PRINTABLE_AMOUNT_SIZE] = {0};
    if (print_amount(G_swap_validated.fee, validated_fee, sizeof(validated_fee)) != 0) {
        PRINTF("Conversion failed\n");
        return false;
    }

    PRINTF("Fee requested in this transaction = %s\n", text);
    PRINTF("Fee validated in swap = %s\n", validated_fee);

    // The displayed fee must be less than or equal to the validated fee
    // amount_as_string_is_greater_or_equal returns true when first arg >= second arg
    return amount_as_string_is_greater_or_equal(validated_fee, text);
}

// Check that the recipient in parameter is the same as the previously saved recipient
bool check_swap_recipient(const char *text) {
    if (!G_swap_validated.initialized) {
        PRINTF("Error check_swap_recipient !G_swap_validated.initialized\n");
        return false;
    }

    PRINTF("Recipient requested in this transaction = %s\n", text);
    PRINTF("Recipient validated in swap = %s\n", G_swap_validated.recipient);

    if (strcmp(G_swap_validated.recipient, text) == 0) {
        return true;
    } else {
        PRINTF("Error check_swap_recipient mismatch\n");
        return false;
    }
}

// Check that the recipient in parameter is the same as the previously saved recipient
int get_swap_recipient(uint8_t recipient_address[PUBKEY_SIZE]) {
    if (!G_swap_validated.initialized) {
        PRINTF("Error get_swap_recipient !G_swap_validated.initialized\n");
        return -1;
    }
    PRINTF("G_swap_validated.recipient = %s\n", G_swap_validated.recipient);
    explicit_bzero(recipient_address, PUBKEY_SIZE);
    int res = base58_decode(G_swap_validated.recipient,
                            strlen(G_swap_validated.recipient),
                            recipient_address,
                            PUBKEY_SIZE);
    if (res != PUBKEY_SIZE) {
        PRINTF("base58_decode error, %d != PUBKEY_SIZE %d\n", res, PUBKEY_SIZE);
        return -1;
    }

    return 0;
}

bool is_token_transaction() {
    return (memcmp(G_swap_validated.ticker, "SOL", sizeof("SOL")) != 0);
}

swap_mode_t get_swap_mode(void) {
    return G_swap_validated.swap_mode;
}

bool check_template_id(uint32_t template_id) {
    if (!G_swap_validated.initialized) {
        PRINTF("check_template_id: swap not initialized\n");
        return false;
    }

    if (G_swap_validated.template_id != template_id) {
        PRINTF("check_template_id: mismatch - expected %u, got %u\n",
               G_swap_validated.template_id,
               template_id);
        return false;
    }

    return true;
}

bool check_swap_tx_hash(const uint8_t *computed_hash) {
    if (!G_swap_validated.initialized) {
        PRINTF("check_swap_tx_hash: swap not initialized\n");
        return false;
    }

    if (memcmp(G_swap_validated.tx_hash, computed_hash, TX_HASH_SIZE) != 0) {
        PRINTF("check_swap_tx_hash: mismatch\n");
        PRINTF("Expected: %.*H\n", TX_HASH_SIZE, G_swap_validated.tx_hash);
        PRINTF("Got:      %.*H\n", TX_HASH_SIZE, computed_hash);
        return false;
    }

    return true;
}
