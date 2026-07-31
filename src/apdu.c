#include "apdu.h"
#include "utils.h"
#include "app_mem_utils.h"

static int parse_apdu_header(const uint8_t *apdu_message,
                             size_t apdu_message_len,
                             ApduHeader *header) {
    explicit_bzero(header, sizeof(*header));
    if (apdu_message_len <= OFFSET_INS) {
        PRINTF("Error, apdu must at least hold the class and instruction, %d received\n",
               apdu_message_len);
        return ApduReplySolanaInvalidMessageSize;
    }

    header->class = apdu_message[OFFSET_CLA];
    if (header->class != CLA) {
        PRINTF("Error, wrong CLA %d\n", header->class);
        return ApduReplySolanaInvalidMessageHeader;
    }

    header->instruction = apdu_message[OFFSET_INS];

    uint32_t data_offset = 0;
    uint32_t max_len = 0;
    uint32_t data_length_size = 0;

    switch (header->instruction) {
        case InsDeprecatedGetAppConfiguration:
        case InsDeprecatedGetPubkey:
        case InsDeprecatedSignMessage:
            PRINTF("Handling deprecated instruction %d\n", header->instruction);
            header->deprecated_host = true;
            data_offset = DEPRECATED_OFFSET_CDATA;
            max_len = UINT16_MAX;
            data_length_size = 2;
            break;

        case InsGetAppConfiguration:
        case InsGetPubkey:
        case InsSignMessage:
        case InsSignOffchainMessage:
        case InsSignMessagePreview:
        case InsSignMessageDelayed:
        case InsStartGenericClearSigningSession:
        case InsPromptUiDisplay:
        case InsFinalizeGenericClearSigning:
        case InsTrustedInfoProvideInstructionDescriptor:
        case InsTrustedInfoGetChallenge:
        case InsTrustedInfoProvideInfo:
        case InsTrustedInfoProvideDynamicDescriptor:
#ifdef HAVE_TRANSACTION_CHECKS
        case InsProvideTransactionCheck:
#endif
        case InsProvideInstructionSubstructure:
        case InsProvideEnumVariant:
        case InsProvideInstructionInfo:
        case InsProvideTokenAccountState:
        case InsProvideAltResolution:
        case InsProvideTrustedName:
            PRINTF("Handling modern instruction %d\n", header->instruction);
            header->deprecated_host = false;
            data_offset = OFFSET_CDATA;
            max_len = UINT8_MAX + OFFSET_CDATA;
            data_length_size = 1;
            break;

        default:
            PRINTF("Received unknown instruction %d\n", header->instruction);
            return ApduReplyUnimplementedInstruction;
    }

    if (apdu_message_len < data_offset) {
        PRINTF("Error, must at least hold a full header, %d received\n", apdu_message_len);
        return ApduReplySolanaInvalidMessageSize;
    }

    if (apdu_message_len > max_len) {
        PRINTF("Error, data may be up to %d bytes, %d received\n", max_len, apdu_message_len);
        return ApduReplySolanaInvalidMessageSize;
    }

    if (data_length_size == 2) {
        header->data_length = U2BE(apdu_message, OFFSET_LC);
    } else {
        header->data_length = apdu_message[OFFSET_LC];
    }

    if (apdu_message_len != header->data_length + data_offset) {
        PRINTF("Error, data length mismatch %d != %d\n",
               apdu_message_len,
               header->data_length + data_offset);
        return ApduReplySolanaInvalidMessageSize;
    }

    if (header->data_length > 0) {
        header->data = apdu_message + data_offset;
    } else {
        header->data = NULL;
    }

    header->p1 = apdu_message[OFFSET_P1];
    header->p2 = apdu_message[OFFSET_P2];

    return 0;
}

// clang-format off
static bool split_allowed_for_instruction(uint8_t instruction) {
    return (instruction == InsDeprecatedSignMessage ||
            instruction == InsSignMessage ||
            instruction == InsSignOffchainMessage ||
            instruction == InsSignMessagePreview ||
            instruction == InsSignMessageDelayed ||
            instruction == InsStartGenericClearSigningSession ||
            instruction == InsTrustedInfoProvideInfo ||
            instruction == InsTrustedInfoProvideDynamicDescriptor ||
            instruction == InsProvideInstructionSubstructure ||
            instruction == InsProvideEnumVariant ||
            instruction == InsProvideInstructionInfo ||
            instruction == InsProvideTokenAccountState ||
            instruction == InsProvideAltResolution ||
            instruction == InsProvideTrustedName
#ifdef HAVE_TRANSACTION_CHECKS
            || instruction == InsProvideTransactionCheck
#endif
    );
}

static bool instruction_with_derivation_path_in_first_apdu(uint8_t instruction) {
    // All but these ones
    return (instruction != InsTrustedInfoProvideInfo &&
            instruction != InsTrustedInfoProvideDynamicDescriptor &&
            instruction != InsTrustedInfoProvideInstructionDescriptor &&
            instruction != InsPromptUiDisplay &&
            instruction != InsFinalizeGenericClearSigning &&
            instruction != InsProvideInstructionSubstructure &&
            instruction != InsProvideEnumVariant &&
            instruction != InsProvideInstructionInfo &&
            instruction != InsProvideTokenAccountState &&
            instruction != InsProvideAltResolution &&
            instruction != InsProvideTrustedName
#ifdef HAVE_TRANSACTION_CHECKS
            && instruction != InsProvideTransactionCheck
#endif
    );
}

static bool instruction_without_payload(uint8_t instruction) {
    return (instruction == InsDeprecatedGetAppConfiguration ||
            instruction == InsPromptUiDisplay ||
            instruction == InsFinalizeGenericClearSigning ||
            instruction == InsGetAppConfiguration ||
            instruction == InsTrustedInfoGetChallenge);
}

static bool instruction_with_only_derivation_path_in_payload(uint8_t instruction) {
    return (instruction == InsDeprecatedGetPubkey ||
            instruction == InsGetPubkey);
}
// clang-format on

// Frees the dynamic message buffer, leaving the rest of the command struct untouched.
void apdu_free_message(apdu_command_t *apdu_command) {
    APP_MEM_FREE_AND_NULL((void **) &apdu_command->message);
    apdu_command->message_capacity = 0;
    apdu_command->message_length = 0;
    apdu_command->message_text_start = NULL;
}

// Frees the dynamic message buffer and clears the whole command struct.
void apdu_reset_command(apdu_command_t *apdu_command) {
    APP_MEM_FREE_AND_NULL((void **) &apdu_command->message);
    explicit_bzero(apdu_command, sizeof(*apdu_command));
}

// Ensures message can hold message_length + incoming_length bytes plus a trailing NUL, growing the
// buffer as needed. Payloads grow dynamically and are bounded only by allocation success, except a
// chunked offchain message which preallocates its full cap once (realloc cannot grow a large buffer
// in the pool, as growth needs the old and new blocks resident simultaneously) and cannot exceed
// it.
static int ensure_message_capacity(apdu_command_t *apdu_command,
                                   uint8_t instruction,
                                   bool first_data_chunk,
                                   bool more,
                                   size_t incoming_length) {
    size_t needed = (size_t) apdu_command->message_length + incoming_length;

    size_t target_capacity = needed;
    if (instruction == InsSignOffchainMessage) {
        if (needed > MAX_OFFCHAIN_MESSAGE_LENGTH) {
            PRINTF("Offchain message length %u exceeds preallocation %u\n",
                   (unsigned) needed,
                   (unsigned) MAX_OFFCHAIN_MESSAGE_LENGTH);
            return ApduReplySolanaInvalidMessageSize;
        }
        if (first_data_chunk && more) {
            target_capacity = MAX_OFFCHAIN_MESSAGE_LENGTH;
        }
    }

    if (apdu_command->message == NULL) {
        apdu_command->message = APP_MEM_ALLOC(target_capacity + 1);
        if (apdu_command->message == NULL) {
            PRINTF("Message allocation of %u bytes failed\n", (unsigned) (target_capacity + 1));
            return ApduReplySolanaInvalidMessageSize;
        }
        apdu_command->message_capacity = target_capacity;
    } else if (target_capacity > apdu_command->message_capacity) {
        uint8_t *grown = APP_MEM_REALLOC(apdu_command->message, target_capacity + 1);
        if (grown == NULL) {
            PRINTF("Message realloc to %u bytes failed\n", (unsigned) (target_capacity + 1));
            return ApduReplySolanaInvalidMessageSize;
        }
        apdu_command->message = grown;
        apdu_command->message_capacity = target_capacity;
    }
    return 0;
}

/**
 * Deserialize APDU into apdu_command_t structure.
 *
 * @param[in] apdu_message
 *   Pointer to raw APDU buffer.
 * @param[in] apdu_message_len
 *   Size of the APDU buffer.
 * @param[out] apdu_command
 *   Pointer to apdu_command_t structure.
 *
 * @return zero on success, ApduReply error code otherwise.
 *
 */
int apdu_handle_message(const uint8_t *apdu_message,
                        size_t apdu_message_len,
                        apdu_command_t *apdu_command) {
    if (apdu_command == NULL || apdu_message == NULL) {
        PRINTF("apdu_handle_message internal error, NULL argument\n");
        return ApduReplySdkInvalidParameter;
    }

    // parse header
    ApduHeader header;
    int ret = parse_apdu_header(apdu_message, apdu_message_len, &header);
    if (ret != 0) {
        PRINTF("Error %d while trying to parse header\n", ret);
        return ret;
    }

    // Probably not necessary
    if (instruction_without_payload(header.instruction)) {
        PRINTF("instruction_without_payload early return\n");
        // return early if no data is expected for the command
        apdu_reset_command(apdu_command);
        reset_unrelated_sessions(header.instruction);
        apdu_command->state = ApduStatePayloadComplete;
        apdu_command->instruction = header.instruction;
        apdu_command->non_confirm = (header.p1 == P1_NON_CONFIRM);
        apdu_command->deprecated_host = header.deprecated_host;
        return 0;
    }

    // P2_EXTEND is set to signal that this APDU buffer extends, rather
    // than replaces, the current message buffer
    // Drop extension flag if the instruction does not allow it
    bool first_data_chunk = !(header.p2 & P2_EXTEND);
    if (!first_data_chunk && !split_allowed_for_instruction(header.instruction)) {
        PRINTF("Split APDU is not allowed for this instruction\n");
        first_data_chunk = true;
    }

    if (first_data_chunk) {
        PRINTF("Overwrite any split context we may have\n");
        apdu_reset_command(apdu_command);
        reset_unrelated_sessions(header.instruction);
        apdu_command->state = ApduStatePayloadInProgress;
        apdu_command->instruction = header.instruction;
        apdu_command->non_confirm = (header.p1 == P1_NON_CONFIRM);
        apdu_command->deprecated_host = header.deprecated_host;
    } else {
        // Split APDU reception, validate the command in progress
        if (apdu_command->state != ApduStatePayloadInProgress) {
            PRINTF("Concatenate error: state %d != ApduStatePayloadInProgress\n",
                   apdu_command->state);
            return ApduReplySolanaInvalidMessage;
        }
        if (apdu_command->instruction != header.instruction) {
            PRINTF("Concatenate error: ins %d != %d\n",
                   apdu_command->instruction,
                   header.instruction);
            return ApduReplySolanaInvalidMessage;
        }
        if (apdu_command->non_confirm != (header.p1 == P1_NON_CONFIRM)) {
            PRINTF("Concatenate error: NC %d != %d\n",
                   apdu_command->non_confirm,
                   (header.p1 == P1_NON_CONFIRM));
            return ApduReplySolanaInvalidMessage;
        }
        if (apdu_command->deprecated_host != header.deprecated_host) {
            PRINTF("Concatenate error: DH %d != %d\n",
                   apdu_command->deprecated_host,
                   header.deprecated_host);
            return ApduReplySolanaInvalidMessage;
        }
    }

    // Read the path here before calling the function handlers as they almost all need it
    if (instruction_with_derivation_path_in_first_apdu(header.instruction)) {
        if (first_data_chunk) {
            // read derivation path
            if (!header.deprecated_host && header.instruction != InsGetPubkey) {
                // Shift num_derivation_paths
                if (header.data_length == 0) {
                    PRINTF("Not enough data length for num_derivation_paths\n");
                    return ApduReplySolanaInvalidMessageSize;
                }
                apdu_command->num_derivation_paths = header.data[0];
                header.data++;
                header.data_length--;
                // We only support one derivation path ATM
                if (apdu_command->num_derivation_paths != 1) {
                    PRINTF("Only 1 derivation path supported, not %d\n",
                           apdu_command->num_derivation_paths);
                    return ApduReplySolanaInvalidMessage;
                }
            } else {
                apdu_command->num_derivation_paths = 1;
            }
            ret = read_derivation_path(header.data,
                                       header.data_length,
                                       apdu_command->derivation_path,
                                       &apdu_command->derivation_path_length);
            if (ret) {
                PRINTF("Error %d in read_derivation_path\n", ret);
                return ret;
            }
            header.data += 1 + apdu_command->derivation_path_length * 4;
            header.data_length -= 1 + apdu_command->derivation_path_length * 4;
        } else {
            // Check that the derivation path was received
            if (apdu_command->num_derivation_paths != 1) {
                PRINTF("Concatenate error: derivation path number %d != 1\n",
                       apdu_command->num_derivation_paths);
                return ApduReplySolanaInvalidMessage;
            }
        }
    }

    // deprecated signmessage had a u16 data length prefix, shift it
    if (header.instruction == InsDeprecatedSignMessage) {
        if (header.data_length < 2) {
            PRINTF("Error header.data_length %d too small for u16 length prefix\n",
                   header.data_length);
            return ApduReplySolanaInvalidMessageSize;
        }
        const size_t data_len = header.data ? U2BE(header.data, 0) : 0;
        header.data += 2;
        header.data_length -= 2;
        if (header.data_length != data_len) {
            PRINTF("Error header.data_length mismatch %d != %d\n", header.data_length, data_len);
            return ApduReplySolanaInvalidMessageSize;
        }
    }

    // Copy header data into the message buffer, growing it and reserving room for the NUL
    // terminator
    if (header.data != NULL) {
        ret = ensure_message_capacity(apdu_command,
                                      header.instruction,
                                      first_data_chunk,
                                      (header.p2 & P2_MORE),
                                      header.data_length);
        if (ret != 0) {
            return ret;
        }
        memcpy(apdu_command->message + apdu_command->message_length,
               header.data,
               header.data_length);
        apdu_command->message_length += header.data_length;
    } else if (!instruction_without_payload(header.instruction) &&
               !instruction_with_only_derivation_path_in_payload(header.instruction)) {
        // This two instructions only have the derivation path, no remaining data expected
        PRINTF("Error message expected for this instruction\n");
        return ApduReplySolanaInvalidMessageSize;
    }

    // check if more data is expected
    if (!(header.p2 & P2_MORE)) {
        PRINTF("Received APDU is complete\n");
        apdu_command->state = ApduStatePayloadComplete;
        // OCMS preallocated its full cap; shrink to the received size now that it is known
        if (apdu_command->instruction == InsSignOffchainMessage && apdu_command->message != NULL &&
            apdu_command->message_capacity > (size_t) apdu_command->message_length) {
            uint8_t *shrunk = APP_MEM_REALLOC(apdu_command->message,
                                              (size_t) apdu_command->message_length + 1);
            if (shrunk != NULL) {
                apdu_command->message = shrunk;
                apdu_command->message_capacity = apdu_command->message_length;
            }
        }
        // NUL-terminate so that handlers can safely expose message content as C strings
        // (e.g. offchain message text passed to NBGL / PRINTF).  Capacity always reserves the +1.
        if (apdu_command->message != NULL) {
            apdu_command->message[apdu_command->message_length] = '\0';
        }

        apdu_command->user_input_is_ata_or_token_account = (header.p2 & P2_IS_ATA_OR_TOKEN_ACCOUNT);
    }

    return 0;
}
