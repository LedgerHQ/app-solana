#pragma once

#include "sol/parser.h"
#include "spl_associated_token_account_instruction.h"
#include "spl_token_instruction.h"
#include "stake_instruction.h"
#include "system_instruction.h"
#include "vote_instruction.h"
#include "compute_budget_instruction.h"
#include <stdbool.h>

enum ProgramId {
    ProgramIdUnknown = 0,
    ProgramIdStake,
    ProgramIdSystem,
    ProgramIdVote,
    ProgramIdSplToken,
    ProgramIdSplAssociatedTokenAccount,
    ProgramIdSplMemo,
    ProgramIdSerumAssertOwner,
    ProgramIdComputeBudget
};

typedef struct InstructionInfo {
    enum ProgramId kind;
    union {
        SplAssociatedTokenAccountInfo spl_associated_token_account;
        SplTokenInfo spl_token;
        StakeInfo stake;
        SystemInfo system;
        VoteInfo vote;
        ComputeBudgetInfo compute_budget;
    };
} InstructionInfo;

enum ProgramId instruction_program_id(const Instruction* instruction, const MessageHeader* header);
int instruction_validate(const Instruction* instruction, const MessageHeader* header);

typedef struct InstructionBrief {
    enum ProgramId program_id;
    union {
        int none;
        SplTokenInstructionKind spl_token;
        enum SystemInstructionKind system;
        enum StakeInstructionKind stake;
        enum VoteInstructionKind vote;
        enum ComputeBudgetInstructionKind compute_budget;
    };
} InstructionBrief;

#define SPL_ASSOCIATED_TOKEN_ACCOUNT_IX_BRIEF \
    { ProgramIdSplAssociatedTokenAccount, .none = 0 }
#define SPL_TOKEN_IX_BRIEF(spl_token_ix) \
    { ProgramIdSplToken, .spl_token = (spl_token_ix) }
#define SYSTEM_IX_BRIEF(system_ix) \
    { ProgramIdSystem, .system = (system_ix) }
#define STAKE_IX_BRIEF(stake_ix) \
    { ProgramIdStake, .stake = (stake_ix) }
#define VOTE_IX_BRIEF(vote_ix) \
    { ProgramIdVote, .vote = (vote_ix) }

bool instruction_info_matches_brief(const InstructionInfo* info, const InstructionBrief* brief);
bool instruction_infos_match_briefs(InstructionInfo* const* infos,
                                    const InstructionBrief* briefs,
                                    size_t len);

typedef struct InstructionAccountsIterator {
    const Pubkey* message_header_pubkeys;
    uint8_t instruction_accounts_length;
    const uint8_t* instruction_accounts;
    size_t current_instruction_account;
} InstructionAccountsIterator;

void instruction_accounts_iterator_init(InstructionAccountsIterator* it,
                                        const MessageHeader* header,
                                        const Instruction* instruction);

int instruction_accounts_iterator_next(InstructionAccountsIterator* it,
                                       const Pubkey** next_account);

size_t instruction_accounts_iterator_remaining(const InstructionAccountsIterator* it);
