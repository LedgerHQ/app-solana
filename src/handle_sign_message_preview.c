#include "os.h"
#include "cx.h"
#include "handle_sign_message_preview.h"
#include "handle_sign_message.h"
#ifdef HAVE_TRANSACTION_CHECKS
#include "handle_provide_transaction_check.h"
#endif
#include "apdu.h"
#include "globals.h"
#include "utils.h"
#include "sol/parser.h"
#include "sol/message.h"
#include "ui_api.h"
#include "io.h"
#include "app_mem_utils.h"

preview_state_t *G_preview_state;

void clear_preview_state(void) {
    APP_MEM_FREE_AND_NULL((void **) &G_preview_state);
}

// Compute SHA-512 of message with blockhash region replaced by zeros,
// without modifying the input buffer.
// Parses the header to locate the blockhash, then hashes in 3 parts:
// before blockhash, zeroed blockhash, after blockhash.
static int hash_message_with_zeroed_blockhash(const uint8_t *message,
                                              size_t message_length,
                                              uint8_t output[CX_SHA512_SIZE]) {
    Parser parser = {message, message_length};
    MessageHeader header;
    if (parse_message_header(&parser, &header) != 0) {
        PRINTF("Failed to parse message header\n");
        return -1;
    }

    const uint8_t *blockhash_ptr = (const uint8_t *) header.blockhash;
    size_t before_len = blockhash_ptr - message;
    size_t after_offset = before_len + HASH_LENGTH;
    size_t after_len = message_length - after_offset;
    uint8_t zeroed_blockhash[HASH_LENGTH];
    explicit_bzero(zeroed_blockhash, HASH_LENGTH);

    cx_sha512_t hash_ctx;
    cx_sha512_init_no_throw(&hash_ctx);
    if (cx_hash_update((cx_hash_t *) &hash_ctx, message, before_len) != CX_OK) {
        return -1;
    }
    if (cx_hash_update((cx_hash_t *) &hash_ctx, zeroed_blockhash, HASH_LENGTH) != CX_OK) {
        return -1;
    }
    if (cx_hash_update((cx_hash_t *) &hash_ctx, message + after_offset, after_len) != CX_OK) {
        return -1;
    }
    if (cx_hash_final((cx_hash_t *) &hash_ctx, output) != CX_OK) {
        return -1;
    }
    return 0;
}

// Verify delayed message matches preview fingerprint
// Returns ApduReplySuccess on match, error code otherwise
static uint16_t verify_delayed_message_matches_preview(void) {
    // Verify message length matches
    if (G_command.message_length != G_preview_state->message_length) {
        PRINTF("Message length mismatch: preview=%d, delayed=%d\n",
               G_preview_state->message_length,
               G_command.message_length);
        return ApduReplySolanaDelayedLengthMismatch;
    }

    // Verify derivation path matches
    if (G_command.derivation_path_length != G_preview_state->derivation_path_length) {
        PRINTF("Derivation path length mismatch\n");
        return ApduReplySolanaDelayedDerivationMismatch;
    }
    for (size_t i = 0; i < G_command.derivation_path_length; i++) {
        if (G_command.derivation_path[i] != G_preview_state->derivation_path[i]) {
            PRINTF("Derivation path mismatch at index %d\n", i);
            return ApduReplySolanaDelayedDerivationMismatch;
        }
    }

    uint8_t computed_hash[CX_SHA512_SIZE];
    if (hash_message_with_zeroed_blockhash(G_command.message,
                                           G_command.message_length,
                                           computed_hash) != 0) {
        return ApduReplySolanaInvalidMessage;
    }

    // Verify hash matches preview
    if (memcmp(computed_hash, G_preview_state->message_hash_with_zero_blockhash, CX_SHA512_SIZE) !=
        0) {
        PRINTF("Fingerprint mismatch, saved %.*H != received %.*H\n",
               CX_SHA512_SIZE,
               G_preview_state->message_hash_with_zero_blockhash,
               CX_SHA512_SIZE,
               computed_hash);
        return ApduReplySolanaDelayedHashMismatch;
    }

    PRINTF("Fingerprint verified\n");
    return ApduReplySuccess;
}

int store_preview_fingerprint(void) {
    if (!APP_MEM_CALLOC((void **) &G_preview_state, sizeof(preview_state_t))) {
        PRINTF("Failed to allocate preview state\n");
        return -1;
    }

    // Compute SHA-512 hash of the message with blockhash treated as zeros
    // without modifying the input buffer
    if (hash_message_with_zeroed_blockhash(G_command.message,
                                           G_command.message_length,
                                           G_preview_state->message_hash_with_zero_blockhash) !=
        0) {
        PRINTF("Failed to compute message hash\n");
        clear_preview_state();
        return -1;
    }

    PRINTF("zeroed blockhash fingerprint = %.*H\n",
           sizeof(G_preview_state->message_hash_with_zero_blockhash),
           G_preview_state->message_hash_with_zero_blockhash);

    // Store derivation path
    PRINTF("Storing derivation path (length=%d)\n", G_command.derivation_path_length);
    G_preview_state->derivation_path_length = G_command.derivation_path_length;
    for (size_t i = 0; i < G_command.derivation_path_length; i++) {
        G_preview_state->derivation_path[i] = G_command.derivation_path[i];
        PRINTF("  path[%d] = %08x\n", i, G_command.derivation_path[i]);
    }

    // Store message length for verification
    G_preview_state->message_length = G_command.message_length;
    PRINTF("Storing message length: %d bytes\n", G_preview_state->message_length);

    G_preview_state->initialized = true;
    PRINTF("Preview fingerprint initialized\n");

    return 0;
}

static int handle_sign_message_delayed_internal(void) {
    int ret;
    if (G_command.instruction != InsSignMessageDelayed ||
        G_command.state != ApduStatePayloadComplete) {
        // Small sanity check, should never happen but let's double check
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    // Verify preview was initialized
    if (G_preview_state == NULL || !G_preview_state->initialized) {
        PRINTF("No preview state found - must preview before delayed sign\n");
        return io_send_sw(ApduReplySolanaDelayedPreviewNotFound);
    }

    // Delayed signing does not make sense in swap context.
    // It should never happen because preview is always refused in swap context so
    // G_preview_state->initialized is always false but let's double check
    if (G_called_from_swap) {
        PRINTF("Delayed signing not supported in swap context\n");
        return io_send_sw(ApduReplySdkNotSupported);
    }

    // Verify the delayed message matches the preview fingerprint
    uint16_t verification_result = verify_delayed_message_matches_preview();
    if (verification_result != ApduReplySuccess) {
        ui_transaction_modal(false);
        return io_send_sw(verification_result);
    }

    // Sign the message directly (with real blockhash)
    int tx_len = set_result_sign_message();
    if (tx_len < 0) {
        PRINTF("set_result_sign_message failed\n");
        ui_transaction_modal(false);
        return io_send_sw(ApduReplySdkException);
    }

    PRINTF("Delayed signing complete\n");
    ret = io_send_response_pointer(G_io_apdu_buffer, tx_len, ApduReplySuccess);
    ui_transaction_modal(ret >= 0);
    return ret;
}

// Simple wrapper function to ensure state is cleared
int handle_sign_message_delayed(void) {
    int ret = handle_sign_message_delayed_internal();
    clear_preview_state();
#ifdef HAVE_TRANSACTION_CHECKS
    clear_transaction_check();
#endif
    return ret;
}
