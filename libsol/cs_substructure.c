// Clear-signing substructure hash accumulator. See cs_substructure.h.
//
// Owns the running SHA-256 over the substructure TLVs streamed for the current
// instruction template, and compares it against the target digest committed by
// the signed INSTRUCTION_INFO descriptor.

#include <string.h>

#include "cs_substructure.h"
#include "util.h"

// =============================================================================
// Module-global accumulator
// =============================================================================

// Running hash of substructures
static cx_sha256_t G_substructure_ctx;
// Target substructure hash from top structure descriptor
static uint8_t G_substructure_target[CX_SHA256_SIZE];
static bool G_substructure_active = false;

void cs_substructure_begin(const uint8_t target_hash[CX_SHA256_SIZE]) {
    cx_sha256_init(&G_substructure_ctx);
    memcpy(G_substructure_target, target_hash, CX_SHA256_SIZE);
    G_substructure_active = true;
    PRINTF("cs_substructure: begin, target=%.*H\n", CX_SHA256_SIZE, G_substructure_target);
}

int cs_substructure_update(const uint8_t *data, size_t size) {
    if (!G_substructure_active) {
        PRINTF("cs_substructure: update called with no accumulation in progress\n");
        return -1;
    }
    CX_ASSERT(cx_hash_update((cx_hash_t *) &G_substructure_ctx, data, size));
    PRINTF("cs_substructure: folded %u bytes into running hash\n", (unsigned int) size);
    return 0;
}

int cs_substructure_check_complete(bool *complete) {
    if (!G_substructure_active) {
        PRINTF("cs_substructure: completeness check with no accumulation in progress\n");
        return -1;
    }
    // Compute on local sha copy to avoid consuming the live context, so repeated polls are safe.
    cx_sha256_t finalize_ctx;
    memcpy(&finalize_ctx, &G_substructure_ctx, sizeof(finalize_ctx));
    uint8_t current_hash[CX_SHA256_SIZE];
    CX_ASSERT(cx_hash_final((cx_hash_t *) &finalize_ctx, current_hash));
    *complete = memcmp(current_hash, G_substructure_target, CX_SHA256_SIZE) == 0;
    PRINTF("cs_substructure: running=%.*H target=%.*H match=%d\n",
           CX_SHA256_SIZE,
           current_hash,
           CX_SHA256_SIZE,
           G_substructure_target,
           *complete);
    return 0;
}

void cs_substructure_reset(void) {
    memset(&G_substructure_ctx, 0, sizeof(G_substructure_ctx));
    memset(G_substructure_target, 0, sizeof(G_substructure_target));
    G_substructure_active = false;
}
