#include <os.h>
#include <string.h>

#include "cs_transaction.h"
#include "cs_instruction_template.h"
#include "cs_display_renderer.h"
#include "app_mem_utils.h"

static cs_transaction_t *G_cs_transaction;

void cs_transaction_reset(void) {
    cs_display_renderer_reset();
    cs_instruction_template_table_reset();
    if (G_cs_transaction != NULL) {
        if (G_cs_transaction->transaction != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &G_cs_transaction->transaction);
        }
        APP_MEM_FREE_AND_NULL((void **) &G_cs_transaction);
    }
}

int cs_transaction_begin(const uint8_t *transaction, size_t transaction_size) {
    cs_transaction_reset();

    if (transaction == NULL || transaction_size == 0) {
        PRINTF("cs_transaction_begin: empty transaction\n");
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
    return 0;
}

const cs_transaction_t *cs_transaction_get(void) {
    return G_cs_transaction;
}
