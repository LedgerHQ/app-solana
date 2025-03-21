#include "os.h"
#include "instruction.h"
#include "serum_assert_owner_instruction.h"
#include "spl_memo_instruction.h"
#include "spl_token_instruction.h"
#include "spl_token2022_instruction.h"
#include "compute_budget_instruction.h"
#include "stake_instruction.h"
#include "system_instruction.h"
#include "util.h"
#include <string.h>

enum ProgramId instruction_program_id(const Instruction *instruction, const MessageHeader *header) {
    const Pubkey *program_id = &header->pubkeys[instruction->program_id_index];
    if (memcmp(program_id, &system_program_id, PUBKEY_SIZE) == 0) {
        PRINTF("ProgramIdSystem\n");
        return ProgramIdSystem;
    } else if (memcmp(program_id, &stake_program_id, PUBKEY_SIZE) == 0) {
        PRINTF("ProgramIdStake\n");
        return ProgramIdStake;
    } else if (memcmp(program_id, &vote_program_id, PUBKEY_SIZE) == 0) {
        PRINTF("ProgramIdVote\n");
        return ProgramIdVote;
    } else if (memcmp(program_id, &spl_token_program_id, PUBKEY_SIZE) == 0) {
        PRINTF("ProgramIdSplToken\n");
        return ProgramIdSplToken;
    } else if (memcmp(program_id, &spl_token2022_program_id, PUBKEY_SIZE) == 0) {
        PRINTF("ProgramIdSplToken 2022\n");
        return ProgramIdSplToken;  // Treat the Token2022 exactly the same as the SplToken
    } else if (memcmp(program_id, &spl_associated_token_account_program_id, PUBKEY_SIZE) == 0) {
        PRINTF("ProgramIdSplAssociatedTokenAccount\n");
        return ProgramIdSplAssociatedTokenAccount;
    } else if (is_serum_assert_owner_program_id(program_id)) {
        PRINTF("ProgramIdSerumAssertOwner\n");
        return ProgramIdSerumAssertOwner;
    } else if (memcmp(program_id, &spl_memo_program_id, PUBKEY_SIZE) == 0) {
        PRINTF("ProgramIdSplMemo\n");
        return ProgramIdSplMemo;
    } else if (memcmp(program_id, &compute_budget_program_id, PUBKEY_SIZE) == 0) {
        PRINTF("ProgramIdComputeBudget\n");
        return ProgramIdComputeBudget;
    }

    return ProgramIdUnknown;
}

int instruction_validate(const Instruction *instruction, const MessageHeader *header) {
    BAIL_IF(instruction->program_id_index >= header->pubkeys_header.pubkeys_length);
    for (size_t i = 0; i < instruction->accounts_length; i++) {
        BAIL_IF(instruction->accounts[i] >= header->pubkeys_header.pubkeys_length);
    }
    return 0;
}

bool instruction_info_matches_brief(const InstructionInfo *info, const InstructionBrief *brief) {
    if (brief->program_id == info->kind) {
        switch (brief->program_id) {
            case ProgramIdSerumAssertOwner:
                return true;
            case ProgramIdSplAssociatedTokenAccount:
                return true;
            case ProgramIdSplMemo:
                return true;
            case ProgramIdComputeBudget:
                return (brief->compute_budget == info->compute_budget.kind);
            case ProgramIdSplToken:
                return (brief->spl_token == info->spl_token.kind);
            case ProgramIdStake:
                return (brief->stake == info->stake.kind);
            case ProgramIdSystem:
                return (brief->system == info->system.kind);
            case ProgramIdVote:
                return (brief->vote == info->vote.kind);
            case ProgramIdUnknown:
                break;
        }
    }
    return false;
}

bool instruction_infos_match_briefs(InstructionInfo *const *infos,
                                    const InstructionBrief *briefs,
                                    size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (!instruction_info_matches_brief(infos[i], &briefs[i])) {
            break;
        }
    }
    return (i == len);
}

void instruction_accounts_iterator_init(InstructionAccountsIterator *it,
                                        const MessageHeader *header,
                                        const Instruction *instruction) {
    it->message_header_pubkeys = header->pubkeys;
    it->instruction_accounts_length = instruction->accounts_length;
    it->instruction_accounts = instruction->accounts;
    it->current_instruction_account = 0;
}

int instruction_accounts_iterator_next(InstructionAccountsIterator *it,
                                       const Pubkey **next_account) {
    if (it->current_instruction_account < it->instruction_accounts_length) {
        size_t pubkeys_index = it->instruction_accounts[it->current_instruction_account++];
        if (next_account) {
            *next_account = &it->message_header_pubkeys[pubkeys_index];
        }
        return 0;
    }
    return 1;
}

size_t instruction_accounts_iterator_remaining(const InstructionAccountsIterator *it) {
    if (it->current_instruction_account < it->instruction_accounts_length) {
        return it->instruction_accounts_length - it->current_instruction_account;
    }
    return 0;
}
