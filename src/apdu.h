#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "globals.h"
#include "sol/parser.h"

typedef enum ApduState {
    ApduStateUninitialized = 0,
    ApduStatePayloadInProgress,
    ApduStatePayloadComplete,
} ApduState;

typedef enum ApduReply {
    /* ApduReplySdk* come from nanos-secure-sdk/include/os.h.  Here we add the
     * 0x68__ prefix that app_main() ORs into those values before sending them
     * over the wire
     */
    ApduReplySdkException = 0x6801,
    ApduReplySdkInvalidParameter = 0x6802,
    ApduReplySdkExceptionOverflow = 0x6803,
    ApduReplySdkExceptionSecurity = 0x6804,
    ApduReplySdkInvalidCrc = 0x6805,
    ApduReplySdkInvalidChecksum = 0x6806,
    ApduReplySdkInvalidCounter = 0x6807,
    ApduReplySdkNotSupported = 0x6808,
    ApduReplySdkInvalidState = 0x6809,
    ApduReplySdkTimeout = 0x6810,
    ApduReplySdkExceptionPIC = 0x6811,
    ApduReplySdkExceptionAppExit = 0x6812,
    ApduReplySdkExceptionIoOverflow = 0x6813,
    ApduReplySdkExceptionIoHeader = 0x6814,
    ApduReplySdkExceptionIoState = 0x6815,
    ApduReplySdkExceptionIoReset = 0x6816,
    ApduReplySdkExceptionCxPort = 0x6817,
    ApduReplySdkExceptionSystem = 0x6818,
    ApduReplySdkNotEnoughSpace = 0x6819,

    ApduReplyNoApduReceived = 0x6982,
    ApduReplyUserRefusal = 0x6985,

    ApduReplySolanaInvalidMessage = 0x6a80,
    ApduReplySolanaInvalidMessageHeader = 0x6a81,
    ApduReplySolanaInvalidMessageFormat = 0x6a82,
    ApduReplySolanaInvalidMessageSize = 0x6a83,
    ApduReplySolanaInvalidDerivationPath = 0x6a84,
    ApduReplySolanaSummaryFinalizeFailed = 0x6f00,
    ApduReplySolanaSummaryUpdateFailed = 0x6f01,

    ApduReplySolanaInvalidInstructionDescriptor = 0x6b00,
    ApduReplySolanaInvalidTrustedInfo = 0x6c00,
    ApduReplySolanaInvalidDynamicToken = 0x6ca0,
    ApduReplySolanaInvalidTransactionCheck = 0x6cb0,

    ApduReplySolanaDelayedPreviewNotFound = 0x6f10,
    ApduReplySolanaDelayedHashMismatch = 0x6f11,
    ApduReplySolanaDelayedLengthMismatch = 0x6f12,
    ApduReplySolanaDelayedDerivationMismatch = 0x6f13,

    ApduReplyUnimplementedInstruction = 0x6d00,
    ApduReplyInvalidCla = 0x6e00,

    ApduReplySuccess = 0x9000,
} ApduReply;

typedef enum swap_error_application_specific_code_e {
    SWAP_EC_APP_GENERIC = 0x00,

    SWAP_EC_APP_TEMPLATE_ID_MISMATCH = 0x01,
    SWAP_EC_APP_DESCRIPTOR_PARSE_FAILED = 0x02,
    SWAP_EC_APP_DESCRIPTOR_MISSING_STRUCT_TYPE = 0x03,
    SWAP_EC_APP_DESCRIPTOR_UNEXPECTED_STRUCT_TYPE = 0x04,
    SWAP_EC_APP_DESCRIPTOR_MISSING_FIELDS = 0x05,
    SWAP_EC_APP_DESCRIPTOR_UNSUPPORTED_VERSION = 0x06,
    SWAP_EC_APP_DESCRIPTOR_SIGNATURE_FAILED = 0x07,
    SWAP_EC_APP_DESCRIPTOR_SAVE_FAILED = 0x08,

    SWAP_EC_APP_INVALID_SWAP_PROTOCOL = 0x09,
    SWAP_EC_APP_CROSSCHAIN_IN_STANDARD_CHECK = 0x0A,
    SWAP_EC_APP_TRANSFER_CHECKED_WITH_FEES_REQUIRED = 0x0B,
    SWAP_EC_APP_TRANSFER_HOOK_REFUSED = 0x0C,

    SWAP_EC_APP_DESCRIPTOR_INFO_MISSING = 0x0D,
    SWAP_EC_APP_ATA_VALIDATION_FAILED = 0x0E,
    SWAP_EC_APP_DUPLICATE_AMOUNT = 0x0F,
    SWAP_EC_APP_UNEXPECTED_TOKEN_CONTEXT = 0x10,

    SWAP_EC_APP_PREVIEW_NOT_SUPPORTED = 0x11,
    SWAP_EC_APP_DESCRIPTOR_PROCESSING_FAILED = 0x12,
    SWAP_EC_APP_BLIND_SIGNING_REFUSED = 0x13,

    SWAP_EC_APP_DESCRIPTOR_INVALID_CAPPED_FIELDS = 0x14,
    SWAP_EC_APP_TX_HASH_MISMATCH = 0x15,
} swap_error_application_specific_code_t;

typedef struct ApduHeader {
    uint8_t class;
    uint8_t instruction;
    uint8_t p1;
    uint8_t p2;
    const uint8_t *data;
    size_t data_length;
    bool deprecated_host;
} ApduHeader;

typedef struct apdu_command_s {
    ApduState state;
    InstructionCode instruction;
    uint8_t num_derivation_paths;
    uint32_t derivation_path[MAX_BIP32_PATH_LENGTH];
    uint32_t derivation_path_length;
    bool non_confirm;
    bool is_preview_mode;  // True when displaying preview (not signing)
    bool deprecated_host;
    bool user_input_is_ata_or_token_account;
    Hash message_hash;
    // Raw message payload assembled from (possibly split) APDUs and NULL terminated by construct.
    uint8_t message[MAX_MESSAGE_LENGTH];
    int message_length;
    // Pointer into message[] past the offchain header
    const char *message_text_start;
} apdu_command_t;

extern apdu_command_t G_command;

int apdu_handle_message(const uint8_t *apdu_message,
                        size_t apdu_message_len,
                        apdu_command_t *apdu_command);
