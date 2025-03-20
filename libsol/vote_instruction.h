#pragma once

#include "sol/parser.h"
#include "sol/print_config.h"

extern const Pubkey vote_program_id;

enum VoteInstructionKind {
    VoteInitialize,
    VoteAuthorize,
    VoteVote,
    VoteWithdraw,
    VoteUpdateValidatorId,
    VoteUpdateCommission,
    VoteSwitchVote,
    VoteAuthorizeChecked,
};

typedef struct VoteInitData {
    const Pubkey *validator_id;
    const Pubkey *vote_authority;
    const Pubkey *withdraw_authority;
    uint64_t commission;
} VoteInitData;

typedef struct VoteInitializeInfo {
    const Pubkey *account;
    VoteInitData vote_init;
} VoteInitializeInfo;

typedef struct VoteWithdrawInfo {
    const Pubkey *account;
    const Pubkey *authority;
    const Pubkey *to;
    uint64_t lamports;
} VoteWithdrawInfo;

enum VoteAuthorize {
    VoteAuthorizeVoter,
    VoteAuthorizeWithdrawer,
};

typedef struct VoteAuthorizeInfo {
    const Pubkey *account;
    const Pubkey *authority;
    const Pubkey *new_authority;
    enum VoteAuthorize authorize;
} VoteAuthorizeInfo;

typedef struct VoteUpdateValidatorIdInfo {
    const Pubkey *account;
    const Pubkey *authority;
    const Pubkey *new_validator_id;
} VoteUpdateValidatorIdInfo;

typedef struct VoteUpdateCommissionInfo {
    const Pubkey *account;
    const Pubkey *authority;
    uint8_t commission;
} VoteUpdateCommissionInfo;

typedef struct VoteInfo {
    enum VoteInstructionKind kind;
    union {
        VoteInitializeInfo initialize;
        VoteWithdrawInfo withdraw;
        VoteAuthorizeInfo authorize;
        VoteUpdateValidatorIdInfo update_validator_id;
        VoteUpdateCommissionInfo update_commission;
    };
} VoteInfo;

int parse_vote_instructions(const Instruction *instruction,
                            const MessageHeader *header,
                            VoteInfo *info);
int print_vote_info(const VoteInfo *info, const PrintConfig *print_config);
int print_vote_initialize_info(const char *primary_title,
                               const VoteInitializeInfo *info,
                               const PrintConfig *print_config);
