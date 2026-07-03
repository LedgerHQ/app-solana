#include <os.h>
#include <string.h>

#include "cs_transaction.h"
#include "cs_instruction_template.h"
#include "cs_display_renderer.h"
#include "cs_enum_cache.h"
#include "cs_token_account_cache.h"
#include "cs_alt_cache.h"
#include "apdu.h"
#include "app_mem_utils.h"

static cs_transaction_t *G_cs_transaction;

void cs_session_reset(void) {
    cs_transaction_reset();
    G_cs_session_state = CS_SESSION_IDLE;
}

int cs_check_state(cs_session_state_t expected) {
    if (G_cs_session_state != expected) {
        PRINTF("cs state: expected %d, got %d\n", expected, G_cs_session_state);
        cs_session_reset();
        return ApduReplySolanaClearSigningInvalidState;
    }
    return 0;
}

void cs_transaction_reset(void) {
    cs_display_renderer_reset();
    cs_instruction_template_table_reset();
    cs_enum_cache_reset();
    cs_token_account_cache_reset();
    cs_alt_cache_reset();
    if (G_cs_transaction != NULL) {
        if (G_cs_transaction->transaction != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &G_cs_transaction->transaction);
        }
        APP_MEM_FREE_AND_NULL((void **) &G_cs_transaction);
    }
}

int cs_transaction_begin(const uint8_t *transaction,
                         size_t transaction_size,
                         const uint32_t *derivation_path,
                         uint32_t derivation_path_length) {
    cs_transaction_reset();

    if (transaction == NULL || transaction_size == 0) {
        PRINTF("cs_transaction_begin: empty transaction\n");
        return -1;
    }

    if (derivation_path == NULL || derivation_path_length == 0 ||
        derivation_path_length > MAX_BIP32_PATH_LENGTH) {
        PRINTF("cs_transaction_begin: invalid derivation path\n");
        return -1;
    }

    if (!APP_MEM_CALLOC((void **) &G_cs_transaction, sizeof(cs_transaction_t))) {
        PRINTF("cs_transaction_begin: context allocation failed\n");
        return -1;
    }

    G_cs_transaction->transaction = APP_MEM_ALLOC(transaction_size);
    if (G_cs_transaction->transaction == NULL) {
        PRINTF("cs_transaction_begin: transaction copy allocation failed\n");
        cs_transaction_reset();
        return -1;
    }

    memcpy(G_cs_transaction->transaction, transaction, transaction_size);
    G_cs_transaction->transaction_size = transaction_size;
    memcpy(G_cs_transaction->derivation_path, derivation_path, derivation_path_length * sizeof(uint32_t));
    G_cs_transaction->derivation_path_length = derivation_path_length;
    return 0;
}

const cs_transaction_t *cs_transaction_get(void) {
    return G_cs_transaction;
}
