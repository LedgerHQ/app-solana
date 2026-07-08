#include "feature_transaction_check.h"

#ifdef HAVE_TRANSACTION_CHECKS

#include <os.h>
#include <stdint.h>
#include <string.h>

#include "apdu.h"
#include "globals.h"
#include "handle_provide_transaction_check.h"
#include "io.h"
#include "utils.h"
#include "transaction_check_ui.h"

typedef struct transaction_check_info_s {
    bool received;
    uint8_t tx_hash[TRANSACTION_CHECK_HASH_SIZE];
    char address[TRANSACTION_CHECK_MAX_ADDRESS_SIZE + 1];
    char provider_msg[TRANSACTION_CHECK_MSG_SIZE + 1];
    char tiny_url[TRANSACTION_CHECK_URL_SIZE + 1];
    char partner[TRANSACTION_CHECK_PARTNER_SIZE + 1];
    transaction_check_risk_t risk;
    transaction_check_type_t type;
    transaction_check_category_t category;
    uint64_t chain_id;
    bool chain_id_received;
} transaction_check_info_t;

static transaction_check_info_t G_transaction_check_info;

void clear_transaction_check(void) {
    explicit_bzero(&G_transaction_check_info, sizeof(G_transaction_check_info));
}

static int handle_provide_transaction_check_internal(void) {
    clear_transaction_check();

    tlv_transaction_check_out_t tlv_output = {0};

    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    tlv_transaction_check_status_t status = tlv_use_case_transaction_check(&payload, &tlv_output);
    if (status != TLV_TRANSACTION_CHECK_SUCCESS) {
        PRINTF("tlv_use_case_transaction_check failed with status %d\n", status);
        return -1;
    }

    // Reject additional_data — we don't understand it yet
    if (tlv_output.additional_data_received) {
        PRINTF("Error: unexpected ADDITIONAL_DATA tag\n");
        return -1;
    }

    // Reject typed data (no EIP-712 on Solana)
    if (tlv_output.type != TRANSACTION_CHECK_TYPE_TRANSACTION) {
        PRINTF("Error: unsupported transaction check type %d\n", tlv_output.type);
        return -1;
    }

    // Copy parsed fields to globals
    G_transaction_check_info.risk = tlv_output.risk;
    G_transaction_check_info.type = tlv_output.type;
    G_transaction_check_info.category = tlv_output.category;
    G_transaction_check_info.chain_id = tlv_output.chain_id;
    G_transaction_check_info.chain_id_received = tlv_output.chain_id_received;

    memcpy(G_transaction_check_info.tx_hash, tlv_output.tx_hash.ptr, TRANSACTION_CHECK_HASH_SIZE);
    // Store address as null-terminated string (base58 for Solana, up to 44 chars)
    if (tlv_output.address.size > TRANSACTION_CHECK_MAX_ADDRESS_SIZE) {
        PRINTF("Error: address too long %llu\n", tlv_output.address.size);
        return -1;
    }
    memcpy(G_transaction_check_info.address, tlv_output.address.ptr, tlv_output.address.size);
    G_transaction_check_info.address[tlv_output.address.size] = '\0';

    memcpy(G_transaction_check_info.provider_msg,
           tlv_output.provider_msg,
           sizeof(G_transaction_check_info.provider_msg));
    memcpy(G_transaction_check_info.tiny_url,
           tlv_output.tiny_url,
           sizeof(G_transaction_check_info.tiny_url));
    memcpy(G_transaction_check_info.partner,
           tlv_output.partner,
           sizeof(G_transaction_check_info.partner));

    G_transaction_check_info.received = true;

    PRINTF("=== TRANSACTION CHECK ===\n");
    PRINTF("risk         = %d\n", G_transaction_check_info.risk);
    PRINTF("category     = %d\n", G_transaction_check_info.category);
    PRINTF("type         = %d\n", G_transaction_check_info.type);
    PRINTF("address      = %s\n", G_transaction_check_info.address);
    PRINTF("tiny_url     = %s\n", G_transaction_check_info.tiny_url);
    PRINTF("provider_msg = %s\n", G_transaction_check_info.provider_msg);
    PRINTF("partner      = %s\n", G_transaction_check_info.partner);
    PRINTF("tx_hash      = %.*H\n", TRANSACTION_CHECK_HASH_SIZE, G_transaction_check_info.tx_hash);

    return 0;
}

int handle_provide_transaction_check(void) {
    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];

    switch (p1) {
        case 0x00:
            // TX check data payload
            if (!N_storage.settings.tx_check_enable) {
                PRINTF("Error: Transaction Check is disabled\n");
                return io_send_sw(ApduReplySdkNotSupported);
            }
            if (handle_provide_transaction_check_internal() == 0) {
                return io_send_sw(ApduReplySuccess);
            } else {
                return io_send_sw(ApduReplySolanaInvalidTransactionCheck);
            }
        case 0x01:
            // Opt-in request
            return handle_transaction_check_opt_in();
        default:
            PRINTF("Error: unknown P1 %d for Transaction Check\n", p1);
            return io_send_sw(ApduReplySdkInvalidParameter);
    }
}

// Signing-time validation: compare TX check data against the actual transaction.
static bool check_transaction_check_report_validity(void) {
    if (!G_transaction_check_info.received) {
        PRINTF("[TX CHECK] No transaction check data received, forcing W3C_ISSUE_WARN\n");
        return false;
    }

    // Check type is TRANSACTION (already enforced at reception, but be defensive)
    if (G_transaction_check_info.type != TRANSACTION_CHECK_TYPE_TRANSACTION) {
        PRINTF("[TX CHECK] Type mismatch: %d\n", G_transaction_check_info.type);
        return false;
    }

    // Mainnet-only: the device can't bind a message to a network, so a devnet/testnet
    // report could downgrade the risk of a mainnet transaction.
    if (!G_transaction_check_info.chain_id_received) {
        PRINTF("[TX CHECK] No chain_id in report\n");
        return false;
    }
    if (G_transaction_check_info.chain_id != SOLANA_CHAIN_ID_MAINNET) {
        PRINTF("[TX CHECK] Non-mainnet chain_id rejected: %llu\n",
               G_transaction_check_info.chain_id);
        return false;
    }

    // Check tx_hash: SHA-256 of the raw transaction message
    uint8_t computed_hash[HASH_LENGTH];
    cx_hash_sha256(G_command.message, G_command.message_length, computed_hash, HASH_LENGTH);
    if (memcmp(G_transaction_check_info.tx_hash, computed_hash, HASH_LENGTH) != 0) {
        PRINTF("[TX CHECK] TX_HASH mismatch: %.*H != %.*H\n",
               HASH_LENGTH,
               G_transaction_check_info.tx_hash,
               HASH_LENGTH,
               computed_hash);
        return false;
    }
    PRINTF("[TX CHECK] TX_HASH match OK\n");

    // Check address: derive pubkey from derivation path and compare base58
    uint8_t signer_pubkey[PUBKEY_LENGTH];
    cx_err_t cx_err = get_public_key(signer_pubkey,
                                     G_command.derivation_path,
                                     G_command.derivation_path_length);
    if (cx_err != CX_OK) {
        PRINTF("[TX CHECK] Unable to derive public key, err=%d\n", cx_err);
        return false;
    }
    char signer_base58[BASE58_PUBKEY_LENGTH];
    if (encode_base58(signer_pubkey, PUBKEY_LENGTH, signer_base58, sizeof(signer_base58)) < 0) {
        PRINTF("[TX CHECK] encode_base58 failed\n");
        return false;
    }
    if (strcmp(G_transaction_check_info.address, signer_base58) != 0) {
        PRINTF("[TX CHECK] ADDRESS mismatch: %s != %s\n",
               G_transaction_check_info.address,
               signer_base58);
        return false;
    }
    PRINTF("[TX CHECK] ADDRESS match OK\n");

    return true;
}

static const char *determine_tx_check_warning_text(transaction_check_risk_t risk,
                                                   transaction_check_category_t category) {
    switch (risk) {
        case TRANSACTION_CHECK_RISK_WARNING:
            switch (category) {
                case TRANSACTION_CHECK_CATEGORY_ADDRESS:
                    return "This transaction involves a suspicious address. "
                           "It might not be safe to continue.";
                case TRANSACTION_CHECK_CATEGORY_DAPP:
                    return "This transaction involves a suspicious dApp. "
                           "It might not be safe to continue.";
                case TRANSACTION_CHECK_CATEGORY_LOSING_OPERATION:
                    return "This transaction could end in a loss. "
                           "Check transaction details carefully before signing.";
                default:
                    return "This transaction might be malicious. It might not be safe to continue. "
                           "Tap the QR code icon for more details.";
            }
        case TRANSACTION_CHECK_RISK_MALICIOUS:
            switch (category) {
                case TRANSACTION_CHECK_CATEGORY_ADDRESS:
                    return "This transaction involves a malicious address. "
                           "Your assets will most likely be stolen.";
                case TRANSACTION_CHECK_CATEGORY_DAPP:
                    return "This dApp is linked to a scammer. "
                           "Your assets will most likely be stolen.";
                default:
                    return "This request is malicious. Your assets will most likely be stolen. "
                           "View full report for details.";
            }
        case TRANSACTION_CHECK_RISK_BENIGN:
            // BENIGN level does not trigger the warning screen
            return NULL;
        default:
            // Unreachable
            return NULL;
    }
}

// Validate TX check data against the transaction and populate NBGL warning bits.
// Must be called after the transaction message is fully received and parsed,
// with the warning struct already zeroed (and blind signing bits set if applicable).
void apply_transaction_check_report(nbgl_warning_t *warning) {
    if (!N_storage.settings.tx_check_enable) {
        PRINTF("[TX CHECK] Transaction Checks are disabled, skipping with no effect\n");
        return;
    }

    if (!check_transaction_check_report_validity()) {
        PRINTF("[TX CHECK] Invalid transaction check data received, forcing W3C_ISSUE_WARN\n");
        warning->predefinedSet |= SET_BIT(W3C_ISSUE_WARN);
        return;
    }

    PRINTF("[TX CHECK] Validation PASSED, risk=%d\n", G_transaction_check_info.risk);

    switch (G_transaction_check_info.risk) {
        case TRANSACTION_CHECK_RISK_BENIGN:
            warning->predefinedSet |= SET_BIT(W3C_NO_THREAT_WARN);
            break;
        case TRANSACTION_CHECK_RISK_WARNING:
            warning->predefinedSet |= SET_BIT(W3C_RISK_DETECTED_WARN);
            break;
        case TRANSACTION_CHECK_RISK_MALICIOUS:
            warning->predefinedSet |= SET_BIT(W3C_THREAT_DETECTED_WARN);
            break;
        default:
            break;
    }
    warning->reportProvider = G_transaction_check_info.partner;
    warning->providerMessage = determine_tx_check_warning_text(G_transaction_check_info.risk,
                                                               G_transaction_check_info.category);
    warning->reportUrl = G_transaction_check_info.tiny_url;
}

int handle_transaction_check_opt_in(void) {
    if (N_storage.settings.tx_check_opt_in) {
        PRINTF("Transaction Checks already opted in\n");
        // Already opted-in, respond immediately with current enable state
        G_io_apdu_buffer[0] = N_storage.settings.tx_check_enable;
        return io_send_response_pointer(G_io_apdu_buffer, 1, ApduReplySuccess);
    } else {
        PRINTF("Opting in to Transaction Checks\n");
        // Show opt-in UI, response will be sent asynchronously
        ui_transaction_check_opt_in(true);
        return 0;
    }
}

#endif  // HAVE_TRANSACTION_CHECKS
