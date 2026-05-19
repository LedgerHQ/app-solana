#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "globals.h"

// Preview state for delayed signing
typedef struct {
    bool initialized;

    // SHA-512 hash of the message with zeroed blockhash
    uint8_t message_hash_with_zero_blockhash[CX_SHA512_SIZE];

    // Not technically needed because we check that the hash matches but reduces probability of
    // finding a collision
    int message_length;

    // Needed because not in the hashed data itself
    uint32_t derivation_path_length;
    uint32_t derivation_path[MAX_BIP32_PATH_LENGTH];
} preview_state_t;

extern preview_state_t *G_preview_state;

int store_preview_fingerprint(void);
int handle_sign_message_delayed(void);
void clear_preview_state(void);
