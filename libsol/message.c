#include "os.h"
#include "instruction.h"
#include "sol/parser.h"
#include "sol/message.h"
#include "sol/print_config.h"
#include "spl_associated_token_account_instruction.h"
#include "spl_token_instruction.h"
#include "system_instruction.h"
#include "stake_instruction.h"
#include "vote_instruction.h"
#include "transaction_printers.h"
#include "util.h"
#include "compute_budget_instruction.h"
#include <string.h>

#include "handle_provide_instruction_descriptor.h"
#include "app_mem_utils.h"

static void debug_print_header(const MessageHeader *header) {
    PRINTF("instructions_length = %d\n", header->instructions_length);
    PRINTF("num_required_signatures = %d\n", header->pubkeys_header.num_required_signatures);
    PRINTF("num_readonly_signed_accounts = %d\n",
           header->pubkeys_header.num_readonly_signed_accounts);
    PRINTF("num_readonly_unsigned_accounts = %d\n",
           header->pubkeys_header.num_readonly_unsigned_accounts);
    PRINTF("pubkeys_length = %d\n", header->pubkeys_header.pubkeys_length);
    if (header->pubkeys != NULL) {
        for (uint16_t i = 0; i < header->pubkeys_header.pubkeys_length; ++i) {
            PRINTF("pubkeys[%d] = %.*H\n", i, PUBKEY_SIZE, header->pubkeys[i].data);
        }
    }
}

static int parse_validate_and_debug_instruction_accounts(Parser *parser,
                                                         Instruction *instruction,
                                                         const MessageHeader *header,
                                                         bool allow_alt) {
    if (parse_instruction(parser, instruction) != 0) {
        PRINTF("Error in parse_instruction\n");
        return -1;
    }
    if (allow_alt) {
        if (instruction_validate_allow_ALT(instruction, header) != 0) {
            PRINTF("Error in instruction_validate_allow_ALT\n");
            return -1;
        }
    } else {
        if (instruction_validate(instruction, header) != 0) {
            PRINTF("Error in instruction_validate\n");
            return -1;
        }
    }
    // size_t counter: accounts_length is a size_t (compact-u16) and can exceed 255;
    // a uint8_t index would wrap and loop forever.
    for (size_t i = 0; i < instruction->accounts_length; ++i) {
        if (instruction->accounts[i] >= header->pubkeys_header.pubkeys_length) {
            // ALT-loaded account: not present in the wire format, cannot be resolved on device
            PRINTF("accounts[%d] = pubkeys[%d] = <ALT loaded>\n",
                   (int) i,
                   instruction->accounts[i]);
        } else {
            PRINTF("accounts[%d] = pubkeys[%d] = %.*H\n",
                   (int) i,
                   instruction->accounts[i],
                   PUBKEY_SIZE,
                   header->pubkeys[instruction->accounts[i]].data);
        }
    }
    return 0;
}

// Inner worker: the instruction buffers are caller-owned (allocated and freed by
// process_message_body), sized to the transaction's instruction count.
static int process_message_body_inner(const uint8_t *message_body,
                                      int message_body_length,
                                      const PrintConfig *print_config,
                                      InstructionInfo *instruction_info,
                                      InstructionInfo **display_instruction_info) {
    const MessageHeader *header = &print_config->header;

    // Track if given transaction contains token2022 extensions that are not fully supported
    // Needed to display user proper warning
    bool generate_extension_warning = false;

    size_t display_instruction_count = 0;

    Parser parser = {message_body, message_body_length};
    for (size_t ins_idx = 0; ins_idx < header->instructions_length; ins_idx++) {
        Instruction instruction;
        // Every account is displayed to the user and therefore must be resolvable in the statically
        // listed keys. An ALT-loaded index is rejected and no account is returned.
        if (parse_validate_and_debug_instruction_accounts(&parser, &instruction, header, false) !=
            0) {
            PRINTF("Error in parse_validate_and_debug_instruction_accounts for ins %d\n",
                   (int) ins_idx);
            return -1;
        }

        InstructionInfo *info = &instruction_info[ins_idx];
        bool ignore_instruction_info = false;
        enum ProgramId program_id = instruction_program_id(&instruction, header);
        switch (program_id) {
            case ProgramIdSerumAssertOwner: {
                // Serum assert-owner only has one instruction and we ignore it
                PRINTF("Instruction uses program ProgramIdSerumAssertOwner\n");
                info->kind = program_id;
                break;
            }
            case ProgramIdSplAssociatedTokenAccount: {
                PRINTF("Instruction uses program ProgramIdSplAssociatedTokenAccount\n");
                if (parse_spl_associated_token_account_instructions(
                        &instruction,
                        header,
                        &info->spl_associated_token_account) == 0) {
                    info->kind = program_id;
                }
                break;
            }
            case ProgramIdSplMemo: {
                // SPL Memo only has one instruction, and we ignore it for now
                PRINTF("Instruction uses program ProgramIdSplMemo\n");
                info->kind = program_id;
                break;
            }
            case ProgramIdSplToken:
                PRINTF("Instruction uses program ProgramIdSplToken\n");
                if (parse_spl_token_instructions(&instruction,
                                                 header,
                                                 &info->spl_token,
                                                 &ignore_instruction_info) == 0) {
                    info->kind = program_id;
                    generate_extension_warning |= info->spl_token.generate_extension_warning;
                }
                break;
            case ProgramIdSystem: {
                PRINTF("Instruction uses program ProgramIdSystem\n");
                if (parse_system_instructions(&instruction, header, &info->system) == 0) {
                    info->kind = program_id;
                }
                break;
            }
            case ProgramIdStake: {
                PRINTF("Instruction uses program ProgramIdStake\n");
                if (parse_stake_instructions(&instruction, header, &info->stake) == 0) {
                    info->kind = program_id;
                }
                break;
            }
            case ProgramIdVote: {
                PRINTF("Instruction uses program ProgramIdVote\n");
                if (parse_vote_instructions(&instruction, header, &info->vote) == 0) {
                    info->kind = program_id;
                }
                break;
            }
            case ProgramIdComputeBudget: {
                PRINTF("Instruction uses program ProgramIdComputeBudget\n");
                if (parse_compute_budget_instructions(&instruction,
                                                      header,
                                                      &info->compute_budget) == 0) {
                    info->kind = program_id;
                }
                break;
            }
            case ProgramIdUnknown:
                PRINTF("Instruction uses program ProgramIdUnknown\n");
                break;
        }

        // Bump info to display count if applicable
        if (!ignore_instruction_info) {
            switch (info->kind) {
                case ProgramIdSplAssociatedTokenAccount:
                case ProgramIdSplToken:
                case ProgramIdSystem:
                case ProgramIdStake:
                case ProgramIdVote:
                case ProgramIdComputeBudget:
                case ProgramIdUnknown:
                    PRINTF("Registered info %d to display in slot %d\n",
                           info->kind,
                           display_instruction_count);
                    display_instruction_info[display_instruction_count++] = info;
                    break;
                // Ignored instructions
                case ProgramIdSerumAssertOwner:
                case ProgramIdSplMemo:
                    break;
            }
        }
    }

    if (header->versioned) {
        size_t account_tables_length;
        BAIL_IF(parse_length(&parser, &account_tables_length));
        BAIL_IF(account_tables_length > 0);
    }

    // Ensure we've consumed the entire message body
    BAIL_IF(!parser_is_empty(&parser));

    // If we don't know about all the instructions, bail
    for (size_t i = 0; i < header->instructions_length; i++) {
        if (instruction_info[i].kind == ProgramIdUnknown) {
            PRINTF("Unknown program id for instruction n %d\n", i);
            return -1;
        }
    }

    if (generate_extension_warning) {
        PRINTF("generate_extension_warning\n");
        BAIL_IF(print_spl_token_extension_warning());
    }
    if (print_transaction(print_config, display_instruction_info, display_instruction_count) != 0) {
        PRINTF("print_transaction failed\n");
        return -1;
    }

    return 0;
}

int process_message_body(const uint8_t *message_body,
                         int message_body_length,
                         const PrintConfig *print_config) {
    const MessageHeader *header = &print_config->header;
    debug_print_header(header);
    BAIL_IF(header->instructions_length == 0);

    // Size the instruction buffers to the real count; bounded by the wire
    // transaction and the pool, no arbitrary cap.
    InstructionInfo *instruction_info = NULL;
    InstructionInfo **display_instruction_info = NULL;
    int status = -1;
    if (APP_MEM_CALLOC((void **) &instruction_info,
                       header->instructions_length * sizeof(*instruction_info)) &&
        APP_MEM_CALLOC((void **) &display_instruction_info,
                       header->instructions_length * sizeof(*display_instruction_info))) {
        status = process_message_body_inner(message_body,
                                            message_body_length,
                                            print_config,
                                            instruction_info,
                                            display_instruction_info);
    } else {
        PRINTF("process_message_body: instruction buffer allocation failed\n");
    }

    if (display_instruction_info != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &display_instruction_info);
    }
    if (instruction_info != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &instruction_info);
    }
    return status;
}

int process_message_body_with_descriptor(const uint8_t *message_body,
                                         int message_body_length,
                                         const PrintConfig *print_config) {
    const MessageHeader *header = &print_config->header;
    debug_print_header(header);
    BAIL_IF(header->instructions_length == 0);
    BAIL_IF(!instruction_descriptor_received());

    // We need to have recievied exactly 1 descriptor for each instruction
    size_t received_descriptors = get_descriptor_count();
    if (received_descriptors != header->instructions_length) {
        PRINTF("Error: received %u descriptors but message has %u instructions\n",
               (unsigned) received_descriptors,
               (unsigned) header->instructions_length);
        return -1;
    }

    // Iterate over all instructions of this message. ins_idx is size_t:
    // instructions_length is a size_t (compact-u16) and a uint8_t would wrap.
    Parser parser = {message_body, message_body_length};
    for (size_t ins_idx = 0; ins_idx < header->instructions_length; ins_idx++) {
        Instruction instruction;
        // Swap + descriptor path: ALT-loaded account indices are tolerated here, their integrity is
        // sealed by the swap tx_hash check. Concrete account inspection is gated by
        // get_account_from_ins() which returns -1 for an ALT index.
        if (parse_validate_and_debug_instruction_accounts(&parser, &instruction, header, true) !=
            0) {
            PRINTF("Error in parse_validate_and_debug_instruction_accounts for ins %d\n",
                   (int) ins_idx);
            return -1;
        }
        PRINTF("Checking instruction length %d data '%.*H'\n",
               instruction.data_length,
               instruction.data_length,
               instruction.data);

        if (validate_instruction_using_descriptor(header, &instruction) != 0) {
            PRINTF("Error in validate_instruction_using_descriptor for ins %d\n", (int) ins_idx);
            return -1;
        }
    }

    // Skip address table lookups for versioned messages
    if (header->versioned) {
        if (skip_address_table_lookups(&parser) != 0) {
            PRINTF("Error skip_address_table_lookups\n");
            return -1;
        }
    }

    // Ensure we've consumed the entire message body
    if (!parser_is_empty(&parser)) {
        PRINTF("Error !parser_is_empty\n");
        return -1;
    }

    return 0;
}
