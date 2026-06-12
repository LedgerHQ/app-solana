#pragma once

#define MAX_SWAP_TOKEN_LENGTH 15
#define TEMPLATE_ID_SIZE      4
#define TX_HASH_SIZE          32

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

// Binary layout of create_transaction_parameters_t::destination_address_extra_id.
// The API provides no length field, so the minimum required sizes are defined here.
// Exchange is responsible for ensuring the buffer is at least this large.
//
// EXTRA_ID_TYPE_NATIVE (0x00):
//   [0]     type byte (0x00)
//   Total:  EXTRA_ID_NATIVE_MIN_SIZE bytes
//
// EXTRA_ID_TYPE_SOLANA_TEMPLATE (0x03):
//   [0]      type byte (0x03)
//   [1..4]   template_id, big-endian uint32_t (TEMPLATE_ID_SIZE bytes)
//   [5..36]  tx_hash, SHA256 of the transaction message (TX_HASH_SIZE bytes)
//   Total:   EXTRA_ID_SOLANA_TEMPLATE_MIN_SIZE bytes (37)
#define EXTRA_ID_NATIVE_MIN_SIZE          1
#define EXTRA_ID_SOLANA_TEMPLATE_MIN_SIZE (1 + TEMPLATE_ID_SIZE + TX_HASH_SIZE)
