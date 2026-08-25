#include "os.h"
#include "instruction.h"
#include "sol/parser.h"
#include "sol/print_config.h"
#include "sol/transaction_summary.h"
#include "stake_instruction.h"
#include "spl_token2022_instruction.h"
#include "transaction_printers.h"
#include "vote_instruction.h"
#include "util.h"

const InstructionBrief nonce_brief[] = {
    SYSTEM_IX_BRIEF(SystemAdvanceNonceAccount),
};
#define is_advance_nonce_account(infos) instruction_info_matches_brief(infos, nonce_brief)

const InstructionBrief create_stake_account_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    STAKE_IX_BRIEF(StakeInitialize),
};
#define is_create_stake_account(infos, infos_length) \
    instruction_infos_match_briefs(infos, create_stake_account_brief, infos_length)

const InstructionBrief create_stake_account_checked_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    STAKE_IX_BRIEF(StakeInitializeChecked),
};
#define is_create_stake_account_checked(infos, infos_length) \
    instruction_infos_match_briefs(infos, create_stake_account_checked_brief, infos_length)

const InstructionBrief create_stake_account_with_seed_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccountWithSeed),
    STAKE_IX_BRIEF(StakeInitialize),
};
#define is_create_stake_account_with_seed(infos, infos_length) \
    instruction_infos_match_briefs(infos, create_stake_account_with_seed_brief, infos_length)

const InstructionBrief create_stake_account_with_seed_checked_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccountWithSeed),
    STAKE_IX_BRIEF(StakeInitializeChecked),
};
#define is_create_stake_account_with_seed_checked(infos, infos_length)           \
    instruction_infos_match_briefs(infos,                                        \
                                   create_stake_account_with_seed_checked_brief, \
                                   infos_length)

const InstructionBrief create_stake_account_and_delegate_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    STAKE_IX_BRIEF(StakeInitialize),
    STAKE_IX_BRIEF(StakeDelegate),
};
#define is_create_stake_account_and_delegate(infos, infos_length) \
    instruction_infos_match_briefs(infos, create_stake_account_and_delegate_brief, infos_length)

const InstructionBrief create_stake_account_with_seed_and_delegate_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccountWithSeed),
    STAKE_IX_BRIEF(StakeInitialize),
    STAKE_IX_BRIEF(StakeDelegate),
};
#define is_create_stake_account_with_seed_and_delegate(infos, infos_length)           \
    instruction_infos_match_briefs(infos,                                             \
                                   create_stake_account_with_seed_and_delegate_brief, \
                                   infos_length)

const InstructionBrief stake_split_brief_v1_1[] = {
    SYSTEM_IX_BRIEF(SystemAllocate),
    SYSTEM_IX_BRIEF(SystemAssign),
    STAKE_IX_BRIEF(StakeSplit),
};
#define is_stake_split_v1_1(infos, infos_length) \
    instruction_infos_match_briefs(infos, stake_split_brief_v1_1, infos_length)

const InstructionBrief stake_split_with_seed_brief_v1_1[] = {
    SYSTEM_IX_BRIEF(SystemAllocateWithSeed),
    STAKE_IX_BRIEF(StakeSplit),
};
#define is_stake_split_with_seed_v1_1(infos, infos_length) \
    instruction_infos_match_briefs(infos, stake_split_with_seed_brief_v1_1, infos_length)

const InstructionBrief stake_split_brief_v1_2[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    STAKE_IX_BRIEF(StakeSplit),
};
#define is_stake_split_v1_2(infos, infos_length) \
    instruction_infos_match_briefs(infos, stake_split_brief_v1_2, infos_length)

const InstructionBrief stake_split_with_seed_brief_v1_2[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccountWithSeed),
    STAKE_IX_BRIEF(StakeSplit),
};
#define is_stake_split_with_seed_v1_2(infos, infos_length) \
    instruction_infos_match_briefs(infos, stake_split_with_seed_brief_v1_2, infos_length)

const InstructionBrief stake_split_brief_v1_3[] = {
    SYSTEM_IX_BRIEF(SystemTransfer),
    SYSTEM_IX_BRIEF(SystemAllocate),
    SYSTEM_IX_BRIEF(SystemAssign),
    STAKE_IX_BRIEF(StakeSplit),
};
#define is_stake_split_v1_3(infos, infos_length) \
    instruction_infos_match_briefs(infos, stake_split_brief_v1_3, infos_length)

const InstructionBrief stake_split_with_seed_brief_v1_3[] = {
    SYSTEM_IX_BRIEF(SystemTransfer),
    SYSTEM_IX_BRIEF(SystemAllocateWithSeed),
    STAKE_IX_BRIEF(StakeSplit),
};
#define is_stake_split_with_seed_v1_3(infos, infos_length) \
    instruction_infos_match_briefs(infos, stake_split_with_seed_brief_v1_3, infos_length)

const InstructionBrief stake_authorize_both_brief[] = {
    STAKE_IX_BRIEF(StakeAuthorize),
    STAKE_IX_BRIEF(StakeAuthorize),
};
#define is_stake_authorize_both(infos, infos_length) \
    instruction_infos_match_briefs(infos, stake_authorize_both_brief, infos_length)

const InstructionBrief stake_authorize_checked_both_brief[] = {
    STAKE_IX_BRIEF(StakeAuthorizeChecked),
    STAKE_IX_BRIEF(StakeAuthorizeChecked),
};
#define is_stake_authorize_checked_both(infos, infos_length) \
    instruction_infos_match_briefs(infos, stake_authorize_checked_both_brief, infos_length)

const InstructionBrief create_nonce_account_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    SYSTEM_IX_BRIEF(SystemInitializeNonceAccount),
};
#define is_create_nonce_account(infos, infos_length) \
    instruction_infos_match_briefs(infos, create_nonce_account_brief, infos_length)

const InstructionBrief create_nonce_account_with_seed_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccountWithSeed),
    SYSTEM_IX_BRIEF(SystemInitializeNonceAccount),
};
#define is_create_nonce_account_with_seed(infos, infos_length) \
    instruction_infos_match_briefs(infos, create_nonce_account_with_seed_brief, infos_length)

const InstructionBrief create_vote_account_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    VOTE_IX_BRIEF(VoteInitialize),
};
#define is_create_vote_account(infos, infos_length) \
    instruction_infos_match_briefs(infos, create_vote_account_brief, infos_length)

const InstructionBrief create_vote_account_with_seed_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccountWithSeed),
    VOTE_IX_BRIEF(VoteInitialize),
};
#define is_create_vote_account_with_seed(infos, infos_length) \
    instruction_infos_match_briefs(infos, create_vote_account_with_seed_brief, infos_length)

const InstructionBrief vote_authorize_both_brief[] = {
    VOTE_IX_BRIEF(VoteAuthorize),
    VOTE_IX_BRIEF(VoteAuthorize),
};
#define is_vote_authorize_both(infos, infos_length) \
    instruction_infos_match_briefs(infos, vote_authorize_both_brief, infos_length)

const InstructionBrief vote_authorize_checked_both_brief[] = {
    VOTE_IX_BRIEF(VoteAuthorizeChecked),
    VOTE_IX_BRIEF(VoteAuthorizeChecked),
};
#define is_vote_authorize_checked_both(infos, infos_length) \
    instruction_infos_match_briefs(infos, vote_authorize_checked_both_brief, infos_length)

const InstructionBrief spl_token_create_mint_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    SPL_TOKEN_IX_BRIEF(SplTokenKind(InitializeMint)),
};
#define is_spl_token_create_mint(infos, infos_length) \
    instruction_infos_match_briefs(infos, spl_token_create_mint_brief, infos_length)

const InstructionBrief spl_token_create_account_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    SPL_TOKEN_IX_BRIEF(SplTokenKind(InitializeAccount)),
};
#define is_spl_token_create_account(infos, infos_length) \
    instruction_infos_match_briefs(infos, spl_token_create_account_brief, infos_length)

const InstructionBrief spl_token_create_account2_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    SPL_TOKEN_IX_BRIEF(SplTokenKind(InitializeAccount2)),
};
#define is_spl_token_create_account2(infos, infos_length) \
    instruction_infos_match_briefs(infos, spl_token_create_account2_brief, infos_length)

const InstructionBrief spl_token_create_multisig_brief[] = {
    SYSTEM_IX_BRIEF(SystemCreateAccount),
    SPL_TOKEN_IX_BRIEF(SplTokenKind(InitializeMultisig)),
};
#define is_spl_token_create_multisig(infos, infos_length) \
    instruction_infos_match_briefs(infos, spl_token_create_multisig_brief, infos_length)

const InstructionBrief spl_associated_token_account_create_with_transfer_brief[] = {
    SPL_ASSOCIATED_TOKEN_ACCOUNT_IX_BRIEF,
    SPL_TOKEN_IX_BRIEF(SplTokenKind(TransferChecked)),
};
#define is_spl_associated_token_account_create_with_transfer(infos, infos_length)           \
    instruction_infos_match_briefs(infos,                                                   \
                                   spl_associated_token_account_create_with_transfer_brief, \
                                   infos_length)

const InstructionBrief spl_associated_token_account_create_with_transfer_fee_brief[] = {
    SPL_ASSOCIATED_TOKEN_ACCOUNT_IX_BRIEF,
    SPL_TOKEN_IX_BRIEF(SplTokenExtensionKind(TransferFeeExtension)),
};
#define is_spl_associated_token_account_create_with_transfer_fee(infos, infos_length)           \
    instruction_infos_match_briefs(infos,                                                       \
                                   spl_associated_token_account_create_with_transfer_fee_brief, \
                                   infos_length)

static int print_create_stake_account(const PrintConfig *print_config,
                                      InstructionInfo *const *infos,
                                      size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountInfo *ca_info = &infos[0]->system.create_account;
    const StakeInitializeInfo *si_info = &infos[1]->stake.initialize;

    // Created and initialized account must be the same
    BAIL_IF(!pubkeys_equal(ca_info->to, si_info->account));

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create stake acct", ca_info->to);

    BAIL_IF(print_system_create_account_info(NULL, ca_info, print_config, false));
    BAIL_IF(print_stake_initialize_info(NULL, si_info, print_config));

    return 0;
}

static int print_create_stake_account_with_seed(const PrintConfig *print_config,
                                                InstructionInfo *const *infos,
                                                size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountWithSeedInfo *cws_info = &infos[0]->system.create_account_with_seed;
    const StakeInitializeInfo *si_info = &infos[1]->stake.initialize;

    // Created and initialized account must be the same
    BAIL_IF(!pubkeys_equal(cws_info->to, si_info->account));

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create stake acct", cws_info->to);

    BAIL_IF(print_system_create_account_with_seed_info(NULL, cws_info, print_config, false));
    BAIL_IF(print_stake_initialize_info(NULL, si_info, print_config));

    return 0;
}

static int print_create_stake_account_and_delegate(const PrintConfig *print_config,
                                                   InstructionInfo *const *infos,
                                                   size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountInfo *ca_info = &infos[0]->system.create_account;
    const StakeInitializeInfo *si_info = &infos[1]->stake.initialize;
    const StakeDelegateInfo *sd_info = &infos[2]->stake.delegate_stake;

    // Created, initialized and delegated account must be the same
    BAIL_IF(!pubkeys_equal(ca_info->to, si_info->account));
    BAIL_IF(!pubkeys_equal(ca_info->to, sd_info->stake_pubkey));

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Delegated from", ca_info->to);

    BAIL_IF(print_system_create_account_info(NULL, ca_info, print_config, false));
    BAIL_IF(print_stake_initialize_info(NULL, si_info, print_config));
    BAIL_IF(print_delegate_stake_info(NULL, sd_info, print_config));

    transaction_summary_set_transaction_type(TRANSACTION_TYPE_SOL_STAKING);
    return 0;
}

static int print_create_stake_account_with_seed_and_delegate(const PrintConfig *print_config,
                                                             InstructionInfo *const *infos,
                                                             size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountWithSeedInfo *cws_info = &infos[0]->system.create_account_with_seed;
    const StakeInitializeInfo *si_info = &infos[1]->stake.initialize;
    const StakeDelegateInfo *sd_info = &infos[2]->stake.delegate_stake;

    // Created, initialized and delegated account must be the same
    BAIL_IF(!pubkeys_equal(cws_info->to, si_info->account));
    BAIL_IF(!pubkeys_equal(cws_info->to, sd_info->stake_pubkey));

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Delegated from", cws_info->to);

    BAIL_IF(print_system_create_account_with_seed_info(NULL, cws_info, print_config, false));
    BAIL_IF(print_stake_initialize_info(NULL, si_info, print_config));
    BAIL_IF(print_delegate_stake_info(NULL, sd_info, print_config));

    transaction_summary_set_transaction_type(TRANSACTION_TYPE_SOL_STAKING);
    return 0;
}

static int bind_stake_split_v1_1(InstructionInfo *const *infos, const StakeSplitInfo **ss_out) {
    const SystemAllocateInfo *al_info = &infos[0]->system.allocate;
    const SystemAssignInfo *as_info = &infos[1]->system.assign;
    const StakeSplitInfo *ss_info = &infos[2]->stake.split;

    // The allocated and assigned account is the account the split funds land in
    BAIL_IF(!pubkeys_equal(al_info->account, ss_info->split_account));
    BAIL_IF(!pubkeys_equal(as_info->account, ss_info->split_account));
    BAIL_IF(!pubkeys_equal(as_info->program_id, &stake_program_id));

    *ss_out = ss_info;
    return 0;
}

static int bind_stake_split_v1_2(InstructionInfo *const *infos, const StakeSplitInfo **ss_out) {
    const SystemCreateAccountInfo *ca_info = &infos[0]->system.create_account;
    const StakeSplitInfo *ss_info = &infos[1]->stake.split;

    // The created account is the account the split funds land in
    BAIL_IF(!pubkeys_equal(ca_info->to, ss_info->split_account));
    BAIL_IF(!pubkeys_equal(ca_info->owner, &stake_program_id));

    *ss_out = ss_info;
    return 0;
}

static int bind_stake_split_with_seed(InstructionInfo *const *infos,
                                      bool legacy,
                                      const StakeSplitInfo **ss_out) {
    const StakeSplitInfo *ss_info = &infos[1]->stake.split;
    const Pubkey *account = NULL;
    const Pubkey *owner = NULL;

    if (legacy) {
        const SystemAllocateWithSeedInfo *aws_info = &infos[0]->system.allocate_with_seed;
        account = aws_info->account;
        owner = aws_info->program_id;
    } else {
        const SystemCreateAccountWithSeedInfo *cws_info = &infos[0]
                                                               ->system.create_account_with_seed;
        account = cws_info->to;
        owner = cws_info->owner;
    }

    // The account the displayed base and seed derive is the account the split funds land in
    BAIL_IF(!pubkeys_equal(account, ss_info->split_account));
    BAIL_IF(!pubkeys_equal(owner, &stake_program_id));

    *ss_out = ss_info;
    return 0;
}

// Heuristic, dated premise: no known producer uses a pre-existing account as a split
// destination. It stays runtime-legal though, Allocate accepts a funded, data-empty,
// System-owned signer. Re-check when SIMD-0312 (CreateAccountAllowPrefund) activates, it
// removes the funded-`to` guard this relies on for the v1.2 shapes.
static int bind_split_destination_is_new(const StakeSplitInfo *ss_info,
                                         const PrintConfig *print_config) {
    BAIL_IF(pubkeys_equal(ss_info->split_account, &print_config->header.pubkeys[0]));
    BAIL_IF(pubkeys_equal(ss_info->split_account, print_config->signer_pubkey));

    return 0;
}

// The lamports a split composite moves on top of the split itself. Shown unconditionally,
// the funder only when it is not the signing key.
static int print_split_funding(const char *amount_title,
                               const char *funder_title,
                               uint64_t lamports,
                               const Pubkey *funder,
                               const PrintConfig *print_config) {
    SummaryItem *item = transaction_summary_general_item();
    summary_item_set_amount(item, amount_title, lamports);

    if (print_config_show_authority(print_config, funder)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, funder_title, funder);
    }

    return 0;
}

static int print_stake_split_no_seed(const PrintConfig *print_config,
                                     const StakeSplitInfo *ss_info,
                                     const SystemCreateAccountInfo *ca_info,
                                     const SystemInfo *prefund) {
    BAIL_IF(print_stake_split_info1(ss_info, print_config));

    if (ca_info != NULL) {
        BAIL_IF(print_split_funding("Deposit",
                                    "Funded by",
                                    ca_info->lamports,
                                    ca_info->from,
                                    print_config));
    }

    if (prefund != NULL) {
        BAIL_IF(print_split_funding("Prefund",
                                    "Prefunder",
                                    prefund->transfer.lamports,
                                    prefund->transfer.from,
                                    print_config));
    }

    BAIL_IF(print_stake_split_info2(ss_info, print_config));

    return 0;
}

static int print_stake_split_with_seed(const PrintConfig *print_config,
                                       InstructionInfo *const *infos,
                                       const StakeSplitInfo *ss_info,
                                       bool legacy,
                                       const SystemInfo *prefund) {
    const SystemCreateAccountWithSeedInfo *cws_info = NULL;
    const Pubkey *base = NULL;
    const SizedString *seed = NULL;

    if (legacy) {
        const SystemAllocateWithSeedInfo *aws_info = &infos[0]->system.allocate_with_seed;
        base = aws_info->base;
        seed = &aws_info->seed;
    } else {
        cws_info = &infos[0]->system.create_account_with_seed;
        base = cws_info->base;
        seed = &cws_info->seed;
    }

    BAIL_IF(print_stake_split_info1(ss_info, print_config));

    if (print_config->expert_mode) {
        SummaryItem *item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Base", base);
        item = transaction_summary_general_item();
        summary_item_set_sized_string(item, "Seed", seed);
    }

    if (cws_info != NULL) {
        BAIL_IF(print_split_funding("Deposit",
                                    "Funded by",
                                    cws_info->lamports,
                                    cws_info->from,
                                    print_config));
    }

    if (prefund != NULL) {
        BAIL_IF(print_split_funding("Prefund",
                                    "Prefunder",
                                    prefund->transfer.lamports,
                                    prefund->transfer.from,
                                    print_config));
    }

    BAIL_IF(print_stake_split_info2(ss_info, print_config));

    return 0;
}

static int print_stake_split_v1_1(const PrintConfig *print_config, InstructionInfo *const *infos) {
    const StakeSplitInfo *ss_info = NULL;

    BAIL_IF(bind_stake_split_v1_1(infos, &ss_info));
    BAIL_IF(bind_split_destination_is_new(ss_info, print_config));

    return print_stake_split_no_seed(print_config, ss_info, NULL, NULL);
}

static int print_stake_split_v1_2(const PrintConfig *print_config, InstructionInfo *const *infos) {
    const StakeSplitInfo *ss_info = NULL;

    BAIL_IF(bind_stake_split_v1_2(infos, &ss_info));
    BAIL_IF(bind_split_destination_is_new(ss_info, print_config));

    return print_stake_split_no_seed(print_config,
                                     ss_info,
                                     &infos[0]->system.create_account,
                                     NULL);
}

static int print_seeded_split(const PrintConfig *print_config,
                              InstructionInfo *const *infos,
                              bool legacy) {
    const StakeSplitInfo *ss_info = NULL;

    BAIL_IF(bind_stake_split_with_seed(infos, legacy, &ss_info));

    return print_stake_split_with_seed(print_config, infos, ss_info, legacy, NULL);
}

static int print_prefunded_split(const PrintConfig *print_config, InstructionInfo *const *infos) {
    const SystemTransferInfo *t_info = &infos[0]->system.transfer;
    const StakeSplitInfo *ss_info = NULL;

    BAIL_IF(bind_stake_split_v1_1(&infos[1], &ss_info));
    // The prefunded account is the account the split funds land in
    BAIL_IF(!pubkeys_equal(t_info->to, ss_info->split_account));
    BAIL_IF(bind_split_destination_is_new(ss_info, print_config));

    return print_stake_split_no_seed(print_config, ss_info, NULL, &infos[0]->system);
}

static int print_prefunded_split_with_seed(const PrintConfig *print_config,
                                           InstructionInfo *const *infos) {
    const SystemTransferInfo *t_info = &infos[0]->system.transfer;
    const StakeSplitInfo *ss_info = NULL;

    BAIL_IF(bind_stake_split_with_seed(&infos[1], true, &ss_info));
    // The prefunded account is the account the split funds land in
    BAIL_IF(!pubkeys_equal(t_info->to, ss_info->split_account));

    return print_stake_split_with_seed(print_config, &infos[1], ss_info, true, &infos[0]->system);
}

static int print_stake_authorize_both(const PrintConfig *print_config,
                                      InstructionInfo *const *infos,
                                      size_t infos_length) {
    UNUSED(infos_length);

    const StakeAuthorizeInfo *staker_info = &infos[0]->stake.authorize;
    const StakeAuthorizeInfo *withdrawer_info = &infos[1]->stake.authorize;
    SummaryItem *item;

    // Sanity check
    BAIL_IF(staker_info->authorize != StakeAuthorizeStaker);
    BAIL_IF(withdrawer_info->authorize != StakeAuthorizeWithdrawer);
    BAIL_IF(!pubkeys_equal(staker_info->account, withdrawer_info->account));

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Set stake auth", staker_info->account);

    if (pubkeys_equal(staker_info->new_authority, withdrawer_info->new_authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New authorities", staker_info->new_authority);
    } else {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New stake auth", staker_info->new_authority);

        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New withdraw auth", withdrawer_info->new_authority);
    }

    if (withdrawer_info->custodian) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Custodian", withdrawer_info->custodian);
    }

    if (print_config_show_authority(print_config, withdrawer_info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", withdrawer_info->authority);
    }

    return 0;
}

static int print_create_nonce_account(const PrintConfig *print_config,
                                      InstructionInfo *const *infos,
                                      size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountInfo *ca_info = &infos[0]->system.create_account;
    const SystemInitializeNonceInfo *ni_info = &infos[1]->system.initialize_nonce;

    // Created and initialized account must be the same
    BAIL_IF(!pubkeys_equal(ca_info->to, ni_info->account));

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create nonce acct", ca_info->to);

    BAIL_IF(print_system_create_account_info(NULL, ca_info, print_config, false));
    BAIL_IF(print_system_initialize_nonce_info(NULL, ni_info, print_config));

    return 0;
}

static int print_create_nonce_account_with_seed(const PrintConfig *print_config,
                                                InstructionInfo *const *infos,
                                                size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountWithSeedInfo *ca_info = &infos[0]->system.create_account_with_seed;
    const SystemInitializeNonceInfo *ni_info = &infos[1]->system.initialize_nonce;

    // Created and initialized account must be the same
    BAIL_IF(!pubkeys_equal(ca_info->to, ni_info->account));

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create nonce acct", ca_info->to);

    BAIL_IF(print_system_create_account_with_seed_info(NULL, ca_info, print_config, false));
    BAIL_IF(print_system_initialize_nonce_info(NULL, ni_info, print_config));

    return 0;
}

static int print_create_vote_account(const PrintConfig *print_config,
                                     InstructionInfo *const *infos,
                                     size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountInfo *ca_info = &infos[0]->system.create_account;
    const VoteInitializeInfo *vi_info = &infos[1]->vote.initialize;

    // Created and initialized account must be the same
    BAIL_IF(!pubkeys_equal(ca_info->to, vi_info->account));

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create vote acct", ca_info->to);

    BAIL_IF(print_system_create_account_info(NULL, ca_info, print_config, false));
    BAIL_IF(print_vote_initialize_info(NULL, vi_info, print_config));

    return 0;
}

static int print_create_vote_account_with_seed(const PrintConfig *print_config,
                                               InstructionInfo *const *infos,
                                               size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountWithSeedInfo *ca_info = &infos[0]->system.create_account_with_seed;
    const VoteInitializeInfo *vi_info = &infos[1]->vote.initialize;

    // Created and initialized account must be the same
    BAIL_IF(!pubkeys_equal(ca_info->to, vi_info->account));

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create vote acct", ca_info->to);

    BAIL_IF(print_system_create_account_with_seed_info(NULL, ca_info, print_config, false));
    BAIL_IF(print_vote_initialize_info(NULL, vi_info, print_config));

    return 0;
}

static int print_vote_authorize_both(const PrintConfig *print_config,
                                     InstructionInfo *const *infos,
                                     size_t infos_length) {
    UNUSED(infos_length);

    const VoteAuthorizeInfo *voter_info = &infos[0]->vote.authorize;
    const VoteAuthorizeInfo *withdrawer_info = &infos[1]->vote.authorize;
    SummaryItem *item;

    // Sanity check
    BAIL_IF(voter_info->authorize != VoteAuthorizeVoter);
    BAIL_IF(withdrawer_info->authorize != VoteAuthorizeWithdrawer);
    BAIL_IF(!pubkeys_equal(voter_info->account, withdrawer_info->account));

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Set vote auth", voter_info->account);

    if (pubkeys_equal(voter_info->new_authority, withdrawer_info->new_authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New authorities", voter_info->new_authority);
    } else {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New vote auth", voter_info->new_authority);

        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "New withdraw auth", withdrawer_info->new_authority);
    }

    if (print_config_show_authority(print_config, withdrawer_info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", withdrawer_info->authority);
    }

    return 0;
}

static int print_spl_token_create_mint(const PrintConfig *print_config,
                                       InstructionInfo *const *infos,
                                       size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountInfo *ca_info = &infos[0]->system.create_account;
    const SplTokenInitializeMintInfo *im_info = &infos[1]->spl_token.initialize_mint;

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create token mint", im_info->mint_account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Mint authority", im_info->mint_authority);

    item = transaction_summary_general_item();
    summary_item_set_u64(item, "Mint decimals", im_info->decimals);

    if (im_info->freeze_authority != NULL) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Freeze authority", im_info->freeze_authority);
    }

    if (print_config_show_authority(print_config, ca_info->from)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Funded by", ca_info->from);
    }

    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Funded with", ca_info->lamports);

    return 0;
}

static int print_spl_token_create_account(const PrintConfig *print_config,
                                          InstructionInfo *const *infos,
                                          size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountInfo *ca_info = &infos[0]->system.create_account;
    const SplTokenInitializeAccountInfo *ia_info = &infos[1]->spl_token.initialize_account;

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create token account", ia_info->token_account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "For", ia_info->owner);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Token address", ia_info->mint_account);

    if (print_config_show_authority(print_config, ca_info->from)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Funded by", ca_info->from);
    }

    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Funded with", ca_info->lamports);

    return 0;
}

static int print_spl_token_create_multisig(const PrintConfig *print_config,
                                           InstructionInfo *const *infos,
                                           size_t infos_length) {
    UNUSED(infos_length);

    const SystemCreateAccountInfo *ca_info = &infos[0]->system.create_account;
    const SplTokenInitializeMultisigInfo *im_info = &infos[1]->spl_token.initialize_multisig;

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create multisig", im_info->multisig_account);

    item = transaction_summary_general_item();
    summary_item_set_multisig_m_of_n(item, im_info->body.m, im_info->signers.count);

    if (print_config_show_authority(print_config, ca_info->from)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Funded by", ca_info->from);
    }

    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Funded with", ca_info->lamports);

    return 0;
}

static int print_spl_associated_token_account_create_with_transfer(const PrintConfig *print_config,
                                                                   InstructionInfo *const *infos,
                                                                   size_t infos_length) {
    UNUSED(infos_length);

    // Unused currently as the additional fees are bundled with the computed fees
    const SplAssociatedTokenAccountCreateInfo *c_info = &infos[0]
                                                             ->spl_associated_token_account.create;
    UNUSED(c_info);

    SplTokenInfo spl_token = infos[1]->spl_token;
    const SplTokenTransferInfo *t_info = &spl_token.transfer;

    print_spl_token_transfer_info(t_info, print_config, spl_token.is_token2022_kind, true);

    return 0;
}

int print_spl_token_extension_warning() {
    SummaryItem *item = transaction_summary_general_item();
    summary_item_set_string(item, "Extension Warning", "Unsupported extensions found");
    item = transaction_summary_general_item();
    summary_item_set_string(item, "", "Verify transaction before signing");

    return 0;
}

InstructionInfo *const *preprocess_compute_budget_instructions(
    InstructionInfo *const *infos,
    size_t *infos_length,
    ComputeBudgetFeeInfo *compute_budget_fee_info) {
    size_t infos_length_initial = *infos_length;
    explicit_bzero(compute_budget_fee_info, sizeof(*compute_budget_fee_info));
    if (infos_length_initial > 1) {
        // Iterate over infos and print compute budget instructions and offset pointers
        // Handle ComputeBudget instructions first due to tech limitations of the
        // print_transaction_nonce_processed. We can get one or 4 ComputeBudget instructions in a
        // single transaction, so we are not able to handle it in a static switch case.
        compute_budget_fee_info->change_unit_limit = NULL;
        compute_budget_fee_info->change_unit_price = NULL;
        compute_budget_fee_info->instructions_count = infos_length_initial;
        compute_budget_fee_info->signatures_count = 0;
        for (size_t info_idx = 0; info_idx < infos_length_initial; ++info_idx) {
            InstructionInfo *instruction_info = infos[0];
            if (instruction_info->kind == ProgramIdComputeBudget) {
                compute_budget_fee_info->signatures_count = instruction_info->compute_budget
                                                                .signatures_count;
                // Unit limit and unit price needs to be aggregated
                // before displaying as this is needed for calculating max fee properly
                if (instruction_info->compute_budget.kind == ComputeBudgetChangeUnitLimit) {
                    compute_budget_fee_info->change_unit_limit = &instruction_info->compute_budget
                                                                      .change_unit_limit;
                }
                if (instruction_info->compute_budget.kind == ComputeBudgetChangeUnitPrice) {
                    compute_budget_fee_info->change_unit_price = &instruction_info->compute_budget
                                                                      .change_unit_price;
                }
                infos++;
                (*infos_length)--;
            }
        }
    }
    return infos;
}

static int print_transaction_nonce_processed(const PrintConfig *print_config,
                                             InstructionInfo *const *infos,
                                             size_t infos_length) {
    int print_ret = -1;
    uint64_t transaction_max_fee = 0;

    // Extract compute budget from infos but don't print yet
    ComputeBudgetFeeInfo compute_budget_fee_info;
    infos = preprocess_compute_budget_instructions(infos, &infos_length, &compute_budget_fee_info);
    if (compute_budget_fee_info.change_unit_limit || compute_budget_fee_info.change_unit_price) {
        PRINTF("Compute budget set, calculating max fees\n");
        if (calculate_max_fee(&compute_budget_fee_info, &transaction_max_fee) != 0) {
            PRINTF("Fee calculation overflow, rejecting transaction\n");
            return -1;
        }
    }

    PRINTF("infos_length = %d\n", infos_length);
    for (uint8_t i = 0; i < infos_length; ++i) {
        PRINTF("infos[%d]->kind = %d\n", i, infos[i]->kind);
    }
    switch (infos_length) {
        case 1:
            switch (infos[0]->kind) {
                case ProgramIdSystem:
                    PRINTF("Handle with print_system_info\n");
                    print_ret = print_system_info(&(infos[0]->system), print_config);
                    break;
                case ProgramIdStake:
                    PRINTF("Handle with print_stake_info\n");
                    print_ret = print_stake_info(&(infos[0]->stake), print_config);
                    break;
                case ProgramIdVote:
                    PRINTF("Handle with print_vote_info\n");
                    print_ret = print_vote_info(&(infos[0]->vote), print_config);
                    break;
                case ProgramIdSplToken:
                    PRINTF("Handle with print_spl_token_info\n");
                    print_ret = print_spl_token_info(&(infos[0]->spl_token), print_config);
                    break;
                case ProgramIdSplAssociatedTokenAccount:
                    PRINTF("Handle with print_spl_associated_token_account_info\n");
                    print_ret = print_spl_associated_token_account_info(
                        &(infos[0]->spl_associated_token_account),
                        print_config);
                    break;
                case ProgramIdSerumAssertOwner:
                case ProgramIdSplMemo:
                case ProgramIdComputeBudget:
                case ProgramIdUnknown:
                    PRINTF("Unhandled info kind %d\n", infos[0]->kind);
                    return -1;
                default:
                    PRINTF("Unrecognized info kind %d\n", infos[0]->kind);
                    return -1;
            }
            break;

        case 2:
            if (is_create_stake_account(infos, infos_length) ||
                is_create_stake_account_checked(infos, infos_length)) {
                PRINTF("Handle with print_create_stake_account\n");
                print_ret = print_create_stake_account(print_config, infos, infos_length);
            } else if (is_create_stake_account_with_seed(infos, infos_length) ||
                       is_create_stake_account_with_seed_checked(infos, infos_length)) {
                PRINTF("Handle with print_create_stake_account_with_seed\n");
                print_ret = print_create_stake_account_with_seed(print_config, infos, infos_length);
            } else if (is_create_nonce_account(infos, infos_length)) {
                PRINTF("Handle with print_create_nonce_account\n");
                print_ret = print_create_nonce_account(print_config, infos, infos_length);
            } else if (is_create_nonce_account_with_seed(infos, infos_length)) {
                PRINTF("Handle with print_create_nonce_account_with_seed\n");
                print_ret = print_create_nonce_account_with_seed(print_config, infos, infos_length);
            } else if (is_create_vote_account(infos, infos_length)) {
                PRINTF("Handle with print_create_vote_account\n");
                print_ret = print_create_vote_account(print_config, infos, infos_length);
            } else if (is_create_vote_account_with_seed(infos, infos_length)) {
                PRINTF("Handle with print_create_vote_account_with_seed\n");
                print_ret = print_create_vote_account_with_seed(print_config, infos, infos_length);
            } else if (is_stake_authorize_both(infos, infos_length) ||
                       is_stake_authorize_checked_both(infos, infos_length)) {
                PRINTF("Handle with print_stake_authorize_both\n");
                print_ret = print_stake_authorize_both(print_config, infos, infos_length);
            } else if (is_vote_authorize_both(infos, infos_length) ||
                       is_vote_authorize_checked_both(infos, infos_length)) {
                PRINTF("Handle with print_vote_authorize_both\n");
                print_ret = print_vote_authorize_both(print_config, infos, infos_length);
            } else if (is_stake_split_with_seed_v1_1(infos, infos_length)) {
                PRINTF("Handle with print_seeded_split\n");
                print_ret = print_seeded_split(print_config, infos, true);
            } else if (is_stake_split_v1_2(infos, infos_length)) {
                PRINTF("Handle with print_stake_split_v1_2\n");
                print_ret = print_stake_split_v1_2(print_config, infos);
            } else if (is_stake_split_with_seed_v1_2(infos, infos_length)) {
                PRINTF("Handle with print_seeded_split\n");
                print_ret = print_seeded_split(print_config, infos, false);
            } else if (is_spl_token_create_mint(infos, infos_length)) {
                PRINTF("Handle with print_spl_token_create_mint\n");
                print_ret = print_spl_token_create_mint(print_config, infos, infos_length);
            } else if (is_spl_token_create_account(infos, infos_length) ||
                       is_spl_token_create_account2(infos, infos_length)) {
                PRINTF("Handle with print_spl_token_create_account\n");
                print_ret = print_spl_token_create_account(print_config, infos, infos_length);
            } else if (is_spl_token_create_multisig(infos, infos_length)) {
                PRINTF("Handle with print_spl_token_create_multisig\n");
                print_ret = print_spl_token_create_multisig(print_config, infos, infos_length);
            } else if (is_spl_associated_token_account_create_with_transfer(infos, infos_length) ||
                       is_spl_associated_token_account_create_with_transfer_fee(infos,
                                                                                infos_length)) {
                PRINTF("Handle with print_spl_associated_token_account_create_with_transfer\n");
                PRINTF("Adding hard coded rent-exempt balance to max fees\n");
                transaction_max_fee += 2039280;
                print_ret = print_spl_associated_token_account_create_with_transfer(print_config,
                                                                                    infos,
                                                                                    infos_length);
            } else {
                PRINTF("Unrecognized info pattern\n");
                return -1;
            }
            break;

        case 3:
            if (is_create_stake_account_and_delegate(infos, infos_length)) {
                PRINTF("Handle with print_create_stake_account_and_delegate\n");
                print_ret = print_create_stake_account_and_delegate(print_config,
                                                                    infos,
                                                                    infos_length);
            } else if (is_create_stake_account_with_seed_and_delegate(infos, infos_length)) {
                PRINTF("Handle with print_create_stake_account_with_seed_and_delegate\n");
                print_ret = print_create_stake_account_with_seed_and_delegate(print_config,
                                                                              infos,
                                                                              infos_length);
            } else if (is_stake_split_v1_1(infos, infos_length)) {
                PRINTF("Handle with print_stake_split_v1_1\n");
                print_ret = print_stake_split_v1_1(print_config, infos);
            } else if (is_stake_split_with_seed_v1_3(infos, infos_length)) {
                PRINTF("Handle with print_prefunded_split_with_seed\n");
                print_ret = print_prefunded_split_with_seed(print_config, infos);
            } else {
                PRINTF("Unrecognized info pattern\n");
                return -1;
            }
            break;

        case 4:
            if (is_stake_split_v1_3(infos, infos_length)) {
                PRINTF("Handle with print_prefunded_split\n");
                print_ret = print_prefunded_split(print_config, infos);
            } else {
                PRINTF("Unrecognized info pattern\n");
                return -1;
            }
            break;

        default:
            PRINTF("Unsupported infos_length %d\n", infos_length);
            return -1;
    }

    if (print_ret != 0) {
        PRINTF("Handler print failed\n");
        return print_ret;
    }

    if (transaction_max_fee != 0) {
        PRINTF("Printing max fees\n");
        print_compute_budget_max_fee(transaction_max_fee, print_config);
    }

    return 0;
}

int print_transaction(const PrintConfig *print_config,
                      InstructionInfo *const *infos,
                      size_t infos_length) {
    // Additional nonce info might be present at first position of in info list
    if ((infos_length > 1) && is_advance_nonce_account(infos[0])) {
        PRINTF("Skip nonce\n");
        const InstructionInfo *nonce_info = infos[0];
        print_system_nonced_transaction_sentinel(&(nonce_info->system), print_config);
        // offset parameters given to print_transaction_nonce_processed()
        infos++;
        infos_length--;
    }

    if (print_transaction_nonce_processed(print_config, infos, infos_length) != 0) {
        PRINTF("Error !print_transaction_nonce_processed\n");
        return -1;
    }

    return 0;
}
