#pragma once

#define MAX_SWAP_TOKEN_LENGTH 15
#define TEMPLATE_ID_SIZE      8

typedef enum swap_mode_e {
    SWAP_MODE_STANDARD,
    SWAP_MODE_CROSSCHAIN,
    SWAP_MODE_ERROR,
} swap_mode_t;

typedef enum extra_id_type_e {
    EXTRA_ID_TYPE_NATIVE = 0x00,
    // There are others but they are not relevant for the Solana application
    EXTRA_ID_TYPE_SOLANA_TEMPLATE = 0x03,
} extra_id_type_t;
