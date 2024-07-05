#pragma once

#include "sol/parser.h"
#include "sol/printer.h"

extern const Pubkey stake_program_id;

enum StakeInstructionKind {
    StakeInitialize,
    StakeAuthorize,
    StakeDelegate,
    StakeSplit,
    StakeWithdraw,
    StakeDeactivate,
    StakeSetLockup,
    StakeMerge,
    StakeAuthorizeWithSeed,
    StakeInitializeChecked,
    StakeAuthorizeChecked,
    StakeAuthorizeCheckedWithSeed,
    StakeSetLockupChecked,
};

typedef struct StakeDelegateInfo {
    const Pubkey* stake_pubkey;
    const Pubkey* vote_pubkey;
    const Pubkey* authorized_pubkey;
} StakeDelegateInfo;

// To support the `LockupArgs` type of the `SetLockup` instruction
// which looks like a `Lockup`, but all of the members are wrapped
// with `Option<>`s
typedef enum StakeLockupPresent {
    StakeLockupHasNone = 0,
    StakeLockupHasTimestamp = 1 << 0,
    StakeLockupHasEpoch = 1 << 1,
    StakeLockupHasCustodian = 1 << 2,
    StakeLockupHasAll = (StakeLockupHasTimestamp | StakeLockupHasEpoch | StakeLockupHasCustodian),
} StakeLockupPresent;

typedef struct StakeLockup {
    StakeLockupPresent present;
    int64_t unix_timestamp;
    uint64_t epoch;
    const Pubkey* custodian;
} StakeLockup;

typedef struct StakeInitializeInfo {
    const Pubkey* account;
    const Pubkey* stake_authority;
    const Pubkey* withdraw_authority;
    StakeLockup lockup;
} StakeInitializeInfo;

typedef struct StakeWithdrawInfo {
    const Pubkey* account;
    const Pubkey* authority;
    const Pubkey* to;
    uint64_t lamports;
} StakeWithdrawInfo;

enum StakeAuthorize {
    StakeAuthorizeStaker,
    StakeAuthorizeWithdrawer,
};

typedef struct StakeAuthorizeInfo {
    const Pubkey* account;
    const Pubkey* authority;
    const Pubkey* new_authority;
    const Pubkey* custodian;
    enum StakeAuthorize authorize;
} StakeAuthorizeInfo;

typedef struct StakeDeactivateInfo {
    const Pubkey* account;
    const Pubkey* authority;
} StakeDeactivateInfo;

typedef struct StakeSetLockupInfo {
    const Pubkey* account;
    const Pubkey* custodian;
    StakeLockup lockup;
} StakeSetLockupInfo;

typedef struct StakeSplitInfo {
    const Pubkey* account;
    const Pubkey* authority;
    const Pubkey* split_account;
    uint64_t lamports;
} StakeSplitInfo;

typedef struct StakeMergeInfo {
    const Pubkey* destination;
    const Pubkey* source;
    const Pubkey* authority;
} StakeMergeInfo;

typedef struct StakeInfo {
    enum StakeInstructionKind kind;
    union {
        StakeDelegateInfo delegate_stake;
        StakeInitializeInfo initialize;
        StakeWithdrawInfo withdraw;
        StakeAuthorizeInfo authorize;
        StakeDeactivateInfo deactivate;
        StakeSetLockupInfo set_lockup;
        StakeSplitInfo split;
        StakeMergeInfo merge;
    };
} StakeInfo;

int parse_stake_instructions(const Instruction* instruction,
                             const MessageHeader* header,
                             StakeInfo* info);
int print_stake_info(const StakeInfo* info, const PrintConfig* print_config);

int print_stake_initialize_info(const char* primary_title,
                                const StakeInitializeInfo* info,
                                const PrintConfig* print_config);
int print_stake_split_info(const StakeSplitInfo* info, const PrintConfig* print_config);

int print_stake_split_info1(const StakeSplitInfo* info, const PrintConfig* print_config);

int print_stake_split_info2(const StakeSplitInfo* info, const PrintConfig* print_config);

int print_delegate_stake_info(const char* primary_title,
                              const StakeDelegateInfo* info,
                              const PrintConfig* print_config);
