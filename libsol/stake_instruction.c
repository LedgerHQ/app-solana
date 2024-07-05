#include "common_byte_strings.h"
#include "instruction.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "stake_instruction.h"
#include "util.h"
#include <stdbool.h>
#include <string.h>

const Pubkey stake_program_id = {{PROGRAM_ID_STAKE}};

static int parse_stake_instruction_kind(Parser* parser, enum StakeInstructionKind* kind) {
    uint32_t maybe_kind;
    BAIL_IF(parse_u32(parser, &maybe_kind));
    switch (maybe_kind) {
        case StakeInitialize:
        case StakeAuthorize:
        case StakeDelegate:
        case StakeSplit:
        case StakeWithdraw:
        case StakeDeactivate:
        case StakeSetLockup:
        case StakeMerge:
        case StakeAuthorizeWithSeed:
        case StakeInitializeChecked:
        case StakeAuthorizeChecked:
        case StakeAuthorizeCheckedWithSeed:
        case StakeSetLockupChecked:
            *kind = (enum StakeInstructionKind) maybe_kind;
            return 0;
    }
    return 1;
}

static int parse_stake_authorize(Parser* parser, enum StakeAuthorize* authorize) {
    uint32_t maybe_authorize;
    BAIL_IF(parse_u32(parser, &maybe_authorize));
    switch (maybe_authorize) {
        case StakeAuthorizeStaker:
        case StakeAuthorizeWithdrawer:
            *authorize = (enum StakeAuthorize) maybe_authorize;
            return 0;
    }
    return 1;
}

// Returns 0 and populates StakeDelegateInfo if provided a MessageHeader
// and a delegate instruction, otherwise non-zero.
static int parse_delegate_stake_instruction(const Instruction* instruction,
                                            const MessageHeader* header,
                                            StakeDelegateInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->stake_pubkey));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->vote_pubkey));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip stake history sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip stake config account
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authorized_pubkey));

    return 0;
}

static int parse_stake_initialize_instruction(Parser* parser,
                                              const Instruction* instruction,
                                              const MessageHeader* header,
                                              StakeInitializeInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip rent sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));

    BAIL_IF(parse_pubkey(parser, &info->stake_authority));
    BAIL_IF(parse_pubkey(parser, &info->withdraw_authority));
    // Lockup
    BAIL_IF(parse_i64(parser, &info->lockup.unix_timestamp));
    BAIL_IF(parse_u64(parser, &info->lockup.epoch));
    BAIL_IF(parse_pubkey(parser, &info->lockup.custodian));
    info->lockup.present = StakeLockupHasAll;

    return 0;
}

static int parse_stake_initialize_checked_instruction(Parser* parser,
                                                      const Instruction* instruction,
                                                      const MessageHeader* header,
                                                      StakeInitializeInfo* info) {
    UNUSED(parser);

    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip rent sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->stake_authority));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->withdraw_authority));

    // No lockup on checked instructions
    info->lockup.present = StakeLockupHasNone;

    return 0;
}

static int parse_stake_withdraw_instruction(Parser* parser,
                                            const Instruction* instruction,
                                            const MessageHeader* header,
                                            StakeWithdrawInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->to));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip stake history sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    BAIL_IF(parse_u64(parser, &info->lamports));

    return 0;
}

static int parse_stake_authorize_instruction(Parser* parser,
                                             const Instruction* instruction,
                                             const MessageHeader* header,
                                             StakeAuthorizeInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));
    // Custodian is optional, don't BAIL_IF()
    instruction_accounts_iterator_next(&it, &info->custodian);

    BAIL_IF(parse_pubkey(parser, &info->new_authority));
    BAIL_IF(parse_stake_authorize(parser, &info->authorize));

    return 0;
}

static int parse_stake_authorize_checked_instruction(Parser* parser,
                                                     const Instruction* instruction,
                                                     const MessageHeader* header,
                                                     StakeAuthorizeInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->new_authority));
    // Custodian is optional, don't BAIL_IF()
    instruction_accounts_iterator_next(&it, &info->custodian);

    BAIL_IF(parse_stake_authorize(parser, &info->authorize));

    return 0;
}

static int parse_stake_deactivate_instruction(Parser* parser,
                                              const Instruction* instruction,
                                              const MessageHeader* header,
                                              StakeDeactivateInfo* info) {
    UNUSED(parser);

    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    return 0;
}

static int parse_stake_lockupargs(Parser* parser, StakeLockup* lockup, bool parse_custodian) {
    // LockupArgs
    enum StakeLockupPresent present = StakeLockupHasNone;
    enum Option option;
    BAIL_IF(parse_option(parser, &option));
    if (option == OptionSome) {
        BAIL_IF(parse_i64(parser, &lockup->unix_timestamp));
        present |= StakeLockupHasTimestamp;
    }
    BAIL_IF(parse_option(parser, &option));
    if (option == OptionSome) {
        BAIL_IF(parse_u64(parser, &lockup->epoch));
        present |= StakeLockupHasEpoch;
    }
    if (parse_custodian) {
        BAIL_IF(parse_option(parser, &option));
        if (option == OptionSome) {
            BAIL_IF(parse_pubkey(parser, &lockup->custodian));
            present |= StakeLockupHasCustodian;
        }
    }
    lockup->present = present;

    return 0;
}

static int parse_stake_set_lockup_instruction(Parser* parser,
                                              const Instruction* instruction,
                                              const MessageHeader* header,
                                              StakeSetLockupInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->custodian));

    BAIL_IF(parse_stake_lockupargs(parser, &info->lockup, true));

    return 0;
}

static int parse_stake_set_lockup_checked_instruction(Parser* parser,
                                                      const Instruction* instruction,
                                                      const MessageHeader* header,
                                                      StakeSetLockupInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->custodian));

    BAIL_IF(parse_stake_lockupargs(parser, &info->lockup, false));
    // Custodian is optional
    if (instruction_accounts_iterator_next(&it, &info->lockup.custodian) == 0) {
        info->lockup.present = info->lockup.present | StakeLockupHasCustodian;
    }

    return 0;
}

static int parse_stake_split_instruction(Parser* parser,
                                         const Instruction* instruction,
                                         const MessageHeader* header,
                                         StakeSplitInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->split_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    BAIL_IF(parse_u64(parser, &info->lamports));

    return 0;
}

static int parse_stake_merge_instruction(const Instruction* instruction,
                                         const MessageHeader* header,
                                         StakeMergeInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->destination));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->source));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip stake history sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    return 0;
}

int parse_stake_instructions(const Instruction* instruction,
                             const MessageHeader* header,
                             StakeInfo* info) {
    Parser parser = {instruction->data, instruction->data_length};

    BAIL_IF(parse_stake_instruction_kind(&parser, &info->kind));

    switch (info->kind) {
        case StakeDelegate:
            return parse_delegate_stake_instruction(instruction, header, &info->delegate_stake);
        case StakeInitialize:
            return parse_stake_initialize_instruction(&parser,
                                                      instruction,
                                                      header,
                                                      &info->initialize);
        case StakeInitializeChecked:
            return parse_stake_initialize_checked_instruction(&parser,
                                                              instruction,
                                                              header,
                                                              &info->initialize);
        case StakeWithdraw:
            return parse_stake_withdraw_instruction(&parser, instruction, header, &info->withdraw);
        case StakeAuthorize:
            return parse_stake_authorize_instruction(&parser,
                                                     instruction,
                                                     header,
                                                     &info->authorize);
        case StakeAuthorizeChecked:
            return parse_stake_authorize_checked_instruction(&parser,
                                                             instruction,
                                                             header,
                                                             &info->authorize);
        case StakeDeactivate:
            return parse_stake_deactivate_instruction(&parser,
                                                      instruction,
                                                      header,
                                                      &info->deactivate);
        case StakeSetLockup:
            return parse_stake_set_lockup_instruction(&parser,
                                                      instruction,
                                                      header,
                                                      &info->set_lockup);
        case StakeSetLockupChecked:
            return parse_stake_set_lockup_checked_instruction(&parser,
                                                              instruction,
                                                              header,
                                                              &info->set_lockup);
        case StakeSplit:
            return parse_stake_split_instruction(&parser, instruction, header, &info->split);
        case StakeMerge:
            return parse_stake_merge_instruction(instruction, header, &info->merge);
        // Unsupported instructions
        case StakeAuthorizeWithSeed:
        case StakeAuthorizeCheckedWithSeed:
            break;
    }

    return 1;
}

int print_delegate_stake_info(const char* primary_title,
                              const StakeDelegateInfo* info,
                              const PrintConfig* print_config) {
    SummaryItem* item;

    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->stake_pubkey);
    }

    if (print_config_show_authority(print_config, info->authorized_pubkey)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authorized_pubkey);
    }

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Vote account", info->vote_pubkey);

    return 0;
}

static int print_stake_withdraw_info(const StakeWithdrawInfo* info,
                                     const PrintConfig* print_config) {
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_amount(item, "Stake withdraw", info->lamports);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "From", info->account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "To", info->to);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}

static int print_stake_authorize_info(const StakeAuthorizeInfo* info,
                                      const PrintConfig* print_config) {
    const char* new_authority_title = NULL;
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Set stake auth", info->account);

    switch (info->authorize) {
        case StakeAuthorizeStaker:
            new_authority_title = "New stake auth";
            break;
        case StakeAuthorizeWithdrawer:
            new_authority_title = "New withdraw auth";
            break;
    }

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, new_authority_title, info->new_authority);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    if (info->custodian && print_config_show_authority(print_config, info->custodian)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Custodian", info->custodian);
    }

    return 0;
}

static int print_stake_deactivate_info(const StakeDeactivateInfo* info,
                                       const PrintConfig* print_config) {
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Deactivate stake", info->account);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}

static int print_stake_set_lockup_info(const StakeSetLockupInfo* info,
                                       const PrintConfig* print_config) {
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Set lockup", info->account);

    enum StakeLockupPresent present = info->lockup.present;
    if (present & StakeLockupHasTimestamp) {
        item = transaction_summary_general_item();
        summary_item_set_timestamp(item, "Time", info->lockup.unix_timestamp);
    }

    if (present & StakeLockupHasEpoch) {
        item = transaction_summary_general_item();
        summary_item_set_u64(item, "Epoch", info->lockup.epoch);
    }

    if (present & StakeLockupHasCustodian) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New authority", info->lockup.custodian);
    }

    if (print_config_show_authority(print_config, info->custodian)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->custodian);
    }

    return 0;
}

int print_stake_split_info(const StakeSplitInfo* info, const PrintConfig* print_config) {
    BAIL_IF(print_stake_split_info1(info, print_config));
    return print_stake_split_info2(info, print_config);
}

static int print_stake_merge_info(const StakeMergeInfo* info, const PrintConfig* print_config) {
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Merge", info->source);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Into", info->destination);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}

int print_stake_info(const StakeInfo* info, const PrintConfig* print_config) {
    switch (info->kind) {
        case StakeDelegate:
            return print_delegate_stake_info("Delegate from", &info->delegate_stake, print_config);
        case StakeInitialize:
        case StakeInitializeChecked:
            return print_stake_initialize_info("Init stake acct", &info->initialize, print_config);
        case StakeWithdraw:
            return print_stake_withdraw_info(&info->withdraw, print_config);
        case StakeAuthorize:
        case StakeAuthorizeChecked:
            return print_stake_authorize_info(&info->authorize, print_config);
        case StakeDeactivate:
            return print_stake_deactivate_info(&info->deactivate, print_config);
        case StakeSetLockup:
        case StakeSetLockupChecked:
            return print_stake_set_lockup_info(&info->set_lockup, print_config);
        case StakeSplit:
            return print_stake_split_info(&info->split, print_config);
        case StakeMerge:
            return print_stake_merge_info(&info->merge, print_config);
        // Unsupported instructions
        case StakeAuthorizeWithSeed:
        case StakeAuthorizeCheckedWithSeed:
            break;
    }

    return 1;
}

int print_stake_initialize_info(const char* primary_title,
                                const StakeInitializeInfo* info,
                                const PrintConfig* print_config) {
    SummaryItem* item;
    bool one_authority = pubkeys_equal(info->withdraw_authority, info->stake_authority);

    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->account);
    }

    if (one_authority) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New authority", info->stake_authority);
    } else {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New stake auth", info->stake_authority);

        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New withdraw auth", info->withdraw_authority);
    }

    int64_t lockup_time = info->lockup.unix_timestamp;
    uint64_t lockup_epoch = info->lockup.epoch;
    if (lockup_time > 0 || lockup_epoch > 0) {
        if (lockup_time > 0) {
            item = transaction_summary_general_item();
            summary_item_set_timestamp(item, "Lockup time", lockup_time);
        }

        if (lockup_epoch > 0) {
            item = transaction_summary_general_item();
            summary_item_set_u64(item, "Lockup epoch", lockup_epoch);
        }

        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Lockup authority", info->lockup.custodian);
    } else if (print_config->expert_mode) {
        item = transaction_summary_general_item();
        summary_item_set_string(item, "Lockup", "None");
    }

    return 0;
}

int print_stake_split_info1(const StakeSplitInfo* info, const PrintConfig* print_config) {
    UNUSED(print_config);

    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_amount(item, "Split stake", info->lamports);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "From", info->account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "To", info->split_account);

    return 0;
}

int print_stake_split_info2(const StakeSplitInfo* info, const PrintConfig* print_config) {
    if (print_config_show_authority(print_config, info->authority)) {
        SummaryItem* item;

        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}
