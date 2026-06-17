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
    PRINTF("program_id = %.*H\n", PUBKEY_SIZE, program_id);
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

    PRINTF("ProgramIdUnknown\n");
    return ProgramIdUnknown;
}

int instruction_validate(const Instruction *instruction, const MessageHeader *header) {
    BAIL_IF(instruction->program_id_index >= header->pubkeys_header.pubkeys_length);
    for (size_t i = 0; i < instruction->accounts_length; i++) {
        BAIL_IF(instruction->accounts[i] >= header->pubkeys_header.pubkeys_length);
    }
    return 0;
}

int instruction_validate_allow_ALT(const Instruction *instruction, const MessageHeader *header) {
    // Swap + descriptor context only.
    // The program_id must always resolve in the statically listed keys: it is dereferenced to
    // match the descriptor's program_id, and a program loaded from an ALT could not be matched.
    BAIL_IF(instruction->program_id_index >= header->pubkeys_header.pubkeys_length);
    // Instruction account indices MAY reference accounts loaded from an Address Lookup Table
    // (index >= pubkeys_length). These are not present in the wire format and cannot be resolved
    // on the device. Their integrity is guaranteed by the swap tx_hash check (see ALT Option 2),
    // not by structural validation here. Any descriptor that needs to inspect a concrete account
    // is gated separately by get_account_from_ins(), which fails closed on ALT indices.
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

int instruction_accounts_iterator_get_current_account_index(InstructionAccountsIterator *it) {
    if (instruction_accounts_iterator_remaining(it) == 0) {
        return -1;
    }
    return it->instruction_accounts[it->current_instruction_account];
}

size_t instruction_accounts_iterator_remaining(const InstructionAccountsIterator *it) {
    if (it->current_instruction_account < it->instruction_accounts_length) {
        return it->instruction_accounts_length - it->current_instruction_account;
    }
    return 0;
}

// Instructions do not store the accounts they use, they only store the index of the accounts in
// the header account array. This function resolves the indirection
const uint8_t *get_account_from_ins(const Instruction *instruction,
                                    const MessageHeader *header,
                                    uint8_t account_index) {
    if (account_index >= instruction->accounts_length) {
        PRINTF("Error account_index %d while instruction accounts_length %d\n",
               account_index,
               instruction->accounts_length);
        return NULL;
    }
    // The resolved pubkey index must fall within the statically listed keys. An index pointing
    // into the Address Lookup Table range cannot be resolved on the device, so we fail closed:
    // a descriptor may only validate accounts the device can actually read.
    uint8_t pubkey_index = instruction->accounts[account_index];
    if (pubkey_index >= header->pubkeys_header.pubkeys_length) {
        PRINTF("Error account_index %d resolves to pubkey %d outside static keys (length %d)\n",
               account_index,
               pubkey_index,
               header->pubkeys_header.pubkeys_length);
        return NULL;
    }
    PRINTF("account_index %d = pubkey %d = %.*H\n",
           account_index,
           pubkey_index,
           PUBKEY_SIZE,
           header->pubkeys[pubkey_index].data);
    return header->pubkeys[pubkey_index].data;
}
