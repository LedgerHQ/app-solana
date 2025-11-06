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

#define MAX_INSTRUCTIONS 6

static void debug_print_header(const MessageHeader *header) {
    PRINTF("instructions_length = %d\n", header->instructions_length);
    PRINTF("num_required_signatures = %d\n", header->pubkeys_header.num_required_signatures);
    PRINTF("num_readonly_signed_accounts = %d\n",
           header->pubkeys_header.num_readonly_signed_accounts);
    PRINTF("num_readonly_unsigned_accounts = %d\n",
           header->pubkeys_header.num_readonly_unsigned_accounts);
    PRINTF("pubkeys_length = %d\n", header->pubkeys_header.pubkeys_length);
    if (header->pubkeys != NULL) {
        for (uint8_t i = 0; i < header->pubkeys_header.pubkeys_length; ++i) {
            PRINTF("pubkeys[%d] = %.*H\n", i, PUBKEY_SIZE, header->pubkeys[i].data);
        }
    }
}

static int parse_validate_and_debug_instruction_accounts(Parser *parser,
                                                         Instruction *instruction,
                                                         const MessageHeader *header) {
    if (parse_instruction(parser, instruction) != 0) {
        PRINTF("Error in parse_instruction\n");
        return -1;
    }
    if (instruction_validate(instruction, header) != 0) {
        PRINTF("Error in instruction_validate\n");
        return -1;
    }
    for (uint8_t i = 0; i < instruction->accounts_length; ++i) {
        PRINTF("accounts[%d] = pubkeys[%d] = %.*H\n",
               i,
               instruction->accounts[i],
               PUBKEY_SIZE,
               header->pubkeys[instruction->accounts[i]].data);
    }
    return 0;
}

int process_message_body(const uint8_t *message_body,
                         int message_body_length,
                         const PrintConfig *print_config) {
    const MessageHeader *header = &print_config->header;
    debug_print_header(header);
    BAIL_IF(header->instructions_length == 0);
    BAIL_IF(header->instructions_length > MAX_INSTRUCTIONS);

    InstructionInfo instruction_info[MAX_INSTRUCTIONS];
    explicit_bzero(instruction_info, sizeof(InstructionInfo) * MAX_INSTRUCTIONS);

    // Track if given transaction contains token2022 extensions that are not fully supported
    // Needed to display user proper warning
    bool generate_extension_warning = false;

    size_t display_instruction_count = 0;
    InstructionInfo *display_instruction_info[MAX_INSTRUCTIONS];

    Parser parser = {message_body, message_body_length};
    for (uint8_t ins_idx = 0; ins_idx < header->instructions_length; ins_idx++) {
        Instruction instruction;
        if (parse_validate_and_debug_instruction_accounts(&parser, &instruction, header) != 0) {
            PRINTF("Error in parse_validate_and_debug_instruction_accounts for ins %d\n", ins_idx);
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
                    if (display_instruction_count >= MAX_INSTRUCTIONS) {
                        PRINTF("Error: too many instructions to display requested\n");
                        return -1;
                    } else {
                        PRINTF("Registered info %d to display in slot %d\n",
                               info->kind,
                               display_instruction_count);
                        display_instruction_info[display_instruction_count++] = info;
                    }
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

int process_message_body_with_descriptor(const uint8_t *message_body,
                                         int message_body_length,
                                         const PrintConfig *print_config) {
    const MessageHeader *header = &print_config->header;
    debug_print_header(header);
    BAIL_IF(header->instructions_length == 0);

    // We need to have recievied exactly 1 descriptor for each instruction
    uint8_t received_descriptors = get_descriptor_count();
    if (received_descriptors != header->instructions_length) {
        PRINTF("Error: received descriptors for %d instructions but received %d instructions\n",
               received_descriptors,
               header->instructions_length);
        return -1;
    }

    // Iterate over all instructions of this message
    Parser parser = {message_body, message_body_length};
    for (uint8_t ins_idx = 0; ins_idx < header->instructions_length; ins_idx++) {
        Instruction instruction;
        if (parse_validate_and_debug_instruction_accounts(&parser, &instruction, header) != 0) {
            PRINTF("Error in parse_validate_and_debug_instruction_accounts for ins %d\n", ins_idx);
            return -1;
        }
        PRINTF("Checking instruction length %d data '%.*H'\n",
               instruction.data_length,
               instruction.data_length,
               instruction.data);

        if (validate_instruction_using_descriptor(header, &instruction) != 0) {
            PRINTF("Error in validate_instruction_using_descriptor for ins %d\n", ins_idx);
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
