#include "os.h"
#include "cx.h"
#include "utils.h"
#include "sol/string_utils.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "globals.h"
#include "apdu.h"
#include "handle_sign_offchain_message.h"
#include "ui_api.h"
#include "io.h"

// message_text_start is consumed as a NULL-terminated C string by NBGL / PRINTF.
// apdu_handle_message() writes the NULL at message[message_length], which requires
// message_length < MAX_MESSAGE_LENGTH.  Verify that the offchain limit satisfies this.
CASSERT(MAX_OFFCHAIN_MESSAGE_LENGTH < MAX_MESSAGE_LENGTH, global_h);

void ui_application_domain(const OffchainMessageHeader *header) {
    // V1 has no application domain
    if (header->application_domain == NULL) {
        return;
    }

    if (is_offchain_application_domain_empty(header->application_domain)) {
        summary_item_set_string(transaction_summary_general_item(),
                                "Application",
                                "Domain not provided");
    } else {
        summary_item_set_offchain_message_application_domain(transaction_summary_general_item(),
                                                             "Application",
                                                             header->application_domain);
    }
}

static bool prepare_primary_items(const OffchainMessageHeader *header,
                                  const bool is_ascii,
                                  const size_t signer_index) {
    if (N_storage.settings.display_mode == DisplayModeExpert) {
        SummaryItem *item = transaction_summary_primary_or_general_item();
        // First signer
        summary_item_set_pubkey(item, "Signer", &header->signers[signer_index]);

        if (header->signers_length > 1) {
            summary_item_set_u64(transaction_summary_general_item(),
                                 "Other signers",
                                 header->signers_length);
        }

        ui_application_domain(header);

        summary_item_set_u64(transaction_summary_general_item(), "Version", header->version);
        // V0 only: display format
        if (header->version == 0) {
            summary_item_set_u64(transaction_summary_general_item(), "Format", header->format);
        }
        summary_item_set_u64(transaction_summary_general_item(), "Size", header->length);
        summary_item_set_hash(transaction_summary_general_item(), "Hash", &G_command.message_hash);
        return true;
    } else if (!is_ascii) {
        summary_item_set_hash(transaction_summary_primary_or_general_item(),
                              "Hash",
                              &G_command.message_hash);
        return true;
    } else {
        return false;
    }
}

static int setup_offchain_signing_ui(const OffchainMessageHeader *header,
                                     const bool is_ascii,
                                     const size_t signer_index) {
    // fill out UI steps
    transaction_summary_reset();

    // prepare_primary_items returns true if it set primary item
    bool has_primary_item = prepare_primary_items(header, is_ascii, signer_index);

    enum SummaryItemKind summary_step_kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_summary_steps = 0;

    if (has_primary_item) {
        PRINTF("Primary item set, finalizing summary items\n");
        // Items were set in prepare_primary_items(), finalize them
        if (transaction_summary_finalize(summary_step_kinds, &num_summary_steps) != 0) {
            PRINTF("Error finalizing transaction summary\n");
            return ApduReplySolanaSummaryFinalizeFailed;
        }
    }
    // else: no items set (user mode + ASCII) - num_summary_steps stays 0

    if (is_ascii) {
        // Last step of ASCII messages is not computed by the parser therefore is not taken into
        // account in num_summary_steps
        ++num_summary_steps;
    }

    start_sign_offchain_message_ui(is_ascii, num_summary_steps);
    return 0;
}

int handle_sign_offchain_message(void) {
    if (G_command.instruction != InsSignOffchainMessage ||
        G_command.state != ApduStatePayloadComplete) {
        return io_send_sw(ApduReplySdkInvalidParameter);
    }

    if (G_command.non_confirm) {
        // UI confirmation is not optional for message signing.
        PRINTF("G_command.non_confirm refused\n");
        return io_send_sw(ApduReplySdkNotSupported);
    }

    if (G_command.message_length > MAX_OFFCHAIN_MESSAGE_LENGTH) {
        return io_send_sw(ApduReplySolanaInvalidMessageSize);
    }

    // parse header
    Parser parser = {G_command.message, G_command.message_length};
    OffchainMessageHeader header;
    Pubkey public_key;

    if (parse_offchain_message_header(&parser, &header)) {
        return io_send_sw(ApduReplySolanaInvalidMessageHeader);
    }

    // Compute start of message content for later use in UI
    G_command.message_text_start = (const char *) G_command.message +
                                   get_offchain_message_header_length(&header);
    PRINTF("Offchain message %s\n", G_command.message_text_start);

    // validate message
    if (header.version > 1 || header.length == 0 || header.length != parser.buffer_length ||
        header.signers_length == 0) {
        return io_send_sw(ApduReplySolanaInvalidMessageHeader);
    }
    // V0: format must be 0 (RestrictedAscii) or 1 (LimitedUtf8).
    // Format 2 (ExtendedUtf8) is explicitly not intended for hardware wallet support per the spec.
    if (header.version == 0 && header.format > 1) {
        return io_send_sw(ApduReplySolanaInvalidMessageHeader);
    }

    cx_err_t cx_err = get_public_key(public_key.data,
                                     G_command.derivation_path,
                                     G_command.derivation_path_length);
    if (cx_err != CX_OK) {
        return io_send_sw(ApduReplySdkException);
    }

    // assert that the requested signer exists in the signers list
    size_t signer_index;
    if (get_pubkey_index(&public_key, header.signers, header.signers_length, &signer_index) != 0) {
        return io_send_sw(ApduReplySolanaInvalidMessageHeader);
    }

    bool is_ascii = is_data_ascii(parser.buffer, parser.buffer_length);
    bool is_utf8 = is_ascii || is_data_utf8(parser.buffer, parser.buffer_length);
    if (!is_utf8) {
        // Message is not valid UTF-8
        return io_send_sw(ApduReplySolanaInvalidMessageFormat);
    }

    // V0: non-ASCII requires format 1 (LimitedUtf8)
    if (header.version == 0 && !is_ascii && header.format == 0) {
        return io_send_sw(ApduReplySolanaInvalidMessageFormat);
    }
    // Non-ASCII messages cannot be displayed by NBGL, require blind signing
    if (!is_ascii && N_storage.settings.allow_blind_sign != BlindSignEnabled) {
        PRINTF("Blind signing is disabled, cannot sign non-ASCII message.\n");
        start_blind_sign_error_ui();
        return io_send_sw(ApduReplySdkNotSupported);
    }

    // compute message hash if needed
    if (!is_ascii || N_storage.settings.display_mode == DisplayModeExpert) {
        // Only message content is hashed
        // We reuse the blind signing buffer for hashing
        cx_hash_sha256(parser.buffer,
                       header.length,
                       (uint8_t *) &G_command.message_hash,
                       HASH_LENGTH);
    }

    int ret = setup_offchain_signing_ui(&header, is_ascii, signer_index);
    if (ret != 0) {
        return io_send_sw(ret);
    }

    // If setup_offchain_signing_ui returned 0, it means it has started the UI and will send
    // the response async later, we just return here.
    return 0;
}
