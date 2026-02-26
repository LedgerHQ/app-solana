#include "os.h"
#include "cx.h"
#include "handle_sign_message_preview.h"
#include "handle_sign_message.h"
#include "apdu.h"
#include "globals.h"
#include "utils.h"
#include "sol/parser.h"
#include "sol/message.h"

// Global preview state
preview_state_t G_preview_state = {0};

void clear_preview_state(void) {
    explicit_bzero(&G_preview_state, sizeof(G_preview_state));
}

// Verify delayed message matches preview fingerprint
// Returns ApduReplySuccess on match, error code otherwise
static uint16_t verify_delayed_message_matches_preview(void) {
    // Verify message length matches
    if (G_command.message_length != G_preview_state.message_length) {
        PRINTF("Message length mismatch: preview=%d, delayed=%d\n",
               G_preview_state.message_length,
               G_command.message_length);
        return ApduReplySolanaDelayedLengthMismatch;
    }

    // Verify derivation path matches
    if (G_command.derivation_path_length != G_preview_state.derivation_path_length) {
        PRINTF("Derivation path length mismatch\n");
        return ApduReplySolanaDelayedDerivationMismatch;
    }
    for (size_t i = 0; i < G_command.derivation_path_length; i++) {
        if (G_command.derivation_path[i] != G_preview_state.derivation_path[i]) {
            PRINTF("Derivation path mismatch at index %d\n", i);
            return ApduReplySolanaDelayedDerivationMismatch;
        }
    }

    // Parse the message to locate blockhash
    Parser msg_parser = {G_command.message, G_command.message_length};
    MessageHeader msg_header;
    if (parse_message_header(&msg_parser, &msg_header) != 0) {
        PRINTF("Failed to parse message header\n");
        return ApduReplySolanaInvalidMessage;
    }

    PRINTF("Real blockhash = %.*H\n", HASH_LENGTH, msg_header.blockhash->data);

    // Compute SHA-512 hash with zeroed blockhash without copying the message.
    // Hash in 3 parts: before blockhash, zeroed blockhash, after blockhash.
    const uint8_t *blockhash_ptr = (const uint8_t *) msg_header.blockhash;
    size_t before_len = blockhash_ptr - G_command.message;
    size_t after_offset = before_len + HASH_LENGTH;
    size_t after_len = G_command.message_length - after_offset;
    uint8_t zeroed_blockhash[HASH_LENGTH];
    explicit_bzero(zeroed_blockhash, HASH_LENGTH);

    cx_sha512_t hash_ctx;
    cx_sha512_init_no_throw(&hash_ctx);
    if (cx_hash_update((cx_hash_t *) &hash_ctx, G_command.message, before_len) != CX_OK) {
        return ApduReplySolanaInvalidMessage;
    }
    if (cx_hash_update((cx_hash_t *) &hash_ctx, zeroed_blockhash, HASH_LENGTH) != CX_OK) {
        return ApduReplySolanaInvalidMessage;
    }
    if (cx_hash_update((cx_hash_t *) &hash_ctx, G_command.message + after_offset, after_len) !=
        CX_OK) {
        return ApduReplySolanaInvalidMessage;
    }
    uint8_t computed_hash[CX_SHA512_SIZE];
    if (cx_hash_final((cx_hash_t *) &hash_ctx, computed_hash)) {
        return ApduReplySolanaInvalidMessage;
    }

    // Verify hash matches preview
    if (memcmp(computed_hash, G_preview_state.message_hash_with_zero_blockhash, CX_SHA512_SIZE) !=
        0) {
        PRINTF("Fingerprint mismatch, saved %.*H != received %.*H\n",
               CX_SHA512_SIZE,
               G_preview_state.message_hash_with_zero_blockhash,
               CX_SHA512_SIZE,
               computed_hash);
        return ApduReplySolanaDelayedHashMismatch;
    }

    PRINTF("Fingerprint verified\n");
    return ApduReplySuccess;
}

void store_preview_fingerprint(void) {
    // Message blockhash has already been zeroed by handle_sign_message_parse_message
    // Just compute SHA-512 hash of the zeroed message
    cx_hash_sha512(G_command.message,
                   G_command.message_length,
                   G_preview_state.message_hash_with_zero_blockhash,
                   sizeof(G_preview_state.message_hash_with_zero_blockhash));

    PRINTF("zeroed blockhash fingerprint = %.*H\n",
           sizeof(G_preview_state.message_hash_with_zero_blockhash),
           G_preview_state.message_hash_with_zero_blockhash);

    // Store derivation path
    PRINTF("Storing derivation path (length=%d)\n", G_command.derivation_path_length);
    G_preview_state.derivation_path_length = G_command.derivation_path_length;
    for (size_t i = 0; i < G_command.derivation_path_length; i++) {
        G_preview_state.derivation_path[i] = G_command.derivation_path[i];
        PRINTF("  path[%d] = %08x\n", i, G_command.derivation_path[i]);
    }

    // Store message length for verification
    G_preview_state.message_length = G_command.message_length;
    PRINTF("Storing message length: %d bytes\n", G_preview_state.message_length);

    G_preview_state.initialized = true;
    PRINTF("Preview fingerprint initialized\n");
}

static uint16_t handle_sign_message_delayed_internal(volatile unsigned int *tx) {
    if (!tx || G_command.instruction != InsSignMessageDelayed ||
        G_command.state != ApduStatePayloadComplete) {
        // Small sanity check, should never happen but let's double check
        return ApduReplySdkInvalidParameter;
    }

    // Verify preview was initialized
    if (!G_preview_state.initialized) {
        PRINTF("No preview state found - must preview before delayed sign\n");
        return ApduReplySolanaDelayedPreviewNotFound;
    }

    // Delayed signing does not make sense in swap context.
    // It should never happen because preview is always refused in swap context so
    // G_preview_state.initialized is always false but let's double check
    if (G_called_from_swap) {
        PRINTF("Delayed signing not supported in swap context\n");
        return ApduReplySdkNotSupported;
    }

    // Verify the delayed message matches the preview fingerprint
    uint16_t verification_result = verify_delayed_message_matches_preview();
    if (verification_result != ApduReplySuccess) {
        return verification_result;
    }

    // Sign the message directly (with real blockhash)
    *tx = set_result_sign_message();

    PRINTF("Delayed signing complete\n");
    return ApduReplySuccess;
}

// Simple wrapper function to ensure state is cleared
void handle_sign_message_delayed(volatile unsigned int *tx) {
    uint16_t result = handle_sign_message_delayed_internal(tx);
    clear_preview_state();
    THROW(result);
}
