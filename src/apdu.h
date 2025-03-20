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
    ApduReplySolanaSummaryFinalizeFailed = 0x6f00,
    ApduReplySolanaSummaryUpdateFailed = 0x6f01,

    ApduReplySolanaInvalidTrustedInfo = 0x6c00,

    ApduReplyUnimplementedInstruction = 0x6d00,
    ApduReplyInvalidCla = 0x6e00,

    ApduReplySuccess = 0x9000,
} ApduReply;

typedef struct ApduHeader {
    uint8_t class;
    uint8_t instruction;
    uint8_t p1;
    uint8_t p2;
    const uint8_t *data;
    size_t data_length;
    bool deprecated_host;
} ApduHeader;

typedef struct ApduCommand {
    ApduState state;
    InstructionCode instruction;
    uint8_t num_derivation_paths;
    uint32_t derivation_path[MAX_BIP32_PATH_LENGTH];
    uint32_t derivation_path_length;
    bool non_confirm;
    bool deprecated_host;
    uint8_t message[MAX_MESSAGE_LENGTH];
    int message_length;
    Hash message_hash;
} ApduCommand;

extern ApduCommand G_command;

int apdu_handle_message(const uint8_t *apdu_message,
                        size_t apdu_message_len,
                        ApduCommand *apdu_command);
