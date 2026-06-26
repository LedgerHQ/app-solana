#include <os.h>
#include <string.h>

#include "clear_signing_context.h"
#include "cs_instruction_template.h"
#include "app_mem_utils.h"

clear_signing_context_t *G_clear_signing_context;

void clear_signing_context_reset(void) {
    cs_instruction_template_table_reset();
    if (G_clear_signing_context != NULL) {
        if (G_clear_signing_context->transaction != NULL) {
            APP_MEM_FREE_AND_NULL((void **) &G_clear_signing_context->transaction);
        }
        APP_MEM_FREE_AND_NULL((void **) &G_clear_signing_context);
    }
}

int clear_signing_context_begin(const uint8_t *transaction, size_t transaction_size) {
    clear_signing_context_reset();

    if (transaction == NULL || transaction_size == 0) {
        PRINTF("clear_signing_context_begin: empty transaction\n");
        return -1;
    }

    if (!APP_MEM_CALLOC((void **) &G_clear_signing_context, sizeof(clear_signing_context_t))) {
        PRINTF("clear_signing_context_begin: context allocation failed\n");
        return -1;
    }

    G_clear_signing_context->transaction = APP_MEM_ALLOC(transaction_size);
    if (G_clear_signing_context->transaction == NULL) {
        PRINTF("clear_signing_context_begin: transaction copy allocation failed\n");
        clear_signing_context_reset();
        return -1;
    }

    memcpy(G_clear_signing_context->transaction, transaction, transaction_size);
    G_clear_signing_context->transaction_size = transaction_size;
    return 0;
}
