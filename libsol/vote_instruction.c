#include "common_byte_strings.h"
#include "instruction.h"
#include "sol/print_config.h"
#include "sol/transaction_summary.h"
#include "util.h"
#include "vote_instruction.h"

const Pubkey vote_program_id = {{PROGRAM_ID_VOTE}};

static int parse_vote_instruction_kind(Parser *parser, enum VoteInstructionKind *kind) {
    uint32_t maybe_kind;
    BAIL_IF(parse_u32(parser, &maybe_kind));
    switch (maybe_kind) {
        case VoteInitialize:
        case VoteAuthorize:
        case VoteVote:
        case VoteWithdraw:
        case VoteUpdateValidatorId:
        case VoteUpdateCommission:
        case VoteSwitchVote:
        case VoteAuthorizeChecked:
            *kind = (enum VoteInstructionKind) maybe_kind;
            return 0;
    }
    return 1;
}

static int parse_vote_authorize(Parser *parser, enum VoteAuthorize *authorize) {
    uint32_t maybe_authorize;
    BAIL_IF(parse_u32(parser, &maybe_authorize));
    switch (maybe_authorize) {
        case VoteAuthorizeVoter:
        case VoteAuthorizeWithdrawer:
            *authorize = (enum VoteAuthorize) maybe_authorize;
            return 0;
    }
    return 1;
}

static int parse_vote_initialize_instruction(Parser *parser,
                                             const Instruction *instruction,
                                             const MessageHeader *header,
                                             VoteInitializeInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip rent sysvat
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));

    BAIL_IF(parse_pubkey(parser, &info->vote_init.validator_id));
    BAIL_IF(parse_pubkey(parser, &info->vote_init.vote_authority));
    BAIL_IF(parse_pubkey(parser, &info->vote_init.withdraw_authority));
    uint8_t commission;
    BAIL_IF(parse_u8(parser, &commission));
    info->vote_init.commission = commission;

    return 0;
}

static int parse_vote_withdraw_instruction(Parser *parser,
                                           const Instruction *instruction,
                                           const MessageHeader *header,
                                           VoteWithdrawInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->to));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    BAIL_IF(parse_u64(parser, &info->lamports));

    return 0;
}

static int parse_vote_authorize_instruction(Parser *parser,
                                            const Instruction *instruction,
                                            const MessageHeader *header,
                                            VoteAuthorizeInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    BAIL_IF(parse_pubkey(parser, &info->new_authority));
    BAIL_IF(parse_vote_authorize(parser, &info->authorize));

    return 0;
}

static int parse_vote_authorize_checked_instruction(Parser *parser,
                                                    const Instruction *instruction,
                                                    const MessageHeader *header,
                                                    VoteAuthorizeInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip clock sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->new_authority));

    BAIL_IF(parse_vote_authorize(parser, &info->authorize));

    return 0;
}

static int parse_vote_update_validator_id_instruction(Parser *parser,
                                                      const Instruction *instruction,
                                                      const MessageHeader *header,
                                                      VoteUpdateValidatorIdInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    if (instruction->data_length == sizeof(uint32_t)) {
        // 1.0.8+, 1.1.3+ format
        // https://github.com/solana-labs/solana/pull/8947
        BAIL_IF(instruction_accounts_iterator_next(&it, &info->new_validator_id));
    } else if (instruction->data_length == (sizeof(uint32_t) + sizeof(Pubkey))) {
        // Before 1.0.8 and 1.1.3, the validaotr identity was passed
        // as an instruction arg
        BAIL_IF(parse_pubkey(parser, &info->new_validator_id));
        // Skip clock sysvar
        BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    } else {
        return 1;
    }

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    return 0;
}

static int parse_vote_update_commission_instruction(Parser *parser,
                                                    const Instruction *instruction,
                                                    const MessageHeader *header,
                                                    VoteUpdateCommissionInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    BAIL_IF(parse_u8(parser, &info->commission));

    return 0;
}

int parse_vote_instructions(const Instruction *instruction,
                            const MessageHeader *header,
                            VoteInfo *info) {
    Parser parser = {instruction->data, instruction->data_length};

    BAIL_IF(parse_vote_instruction_kind(&parser, &info->kind));

    switch (info->kind) {
        case VoteInitialize:
            return parse_vote_initialize_instruction(&parser,
                                                     instruction,
                                                     header,
                                                     &info->initialize);
        case VoteWithdraw:
            return parse_vote_withdraw_instruction(&parser, instruction, header, &info->withdraw);
        case VoteAuthorize:
            return parse_vote_authorize_instruction(&parser, instruction, header, &info->authorize);
        case VoteAuthorizeChecked:
            return parse_vote_authorize_checked_instruction(&parser,
                                                            instruction,
                                                            header,
                                                            &info->authorize);
        case VoteUpdateValidatorId:
            return parse_vote_update_validator_id_instruction(&parser,
                                                              instruction,
                                                              header,
                                                              &info->update_validator_id);
        case VoteUpdateCommission:
            return parse_vote_update_commission_instruction(&parser,
                                                            instruction,
                                                            header,
                                                            &info->update_commission);
        case VoteVote:
        case VoteSwitchVote:
            break;
    }

    return 1;
}

static int print_vote_withdraw_info(const VoteWithdrawInfo *info, const PrintConfig *print_config) {
    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_amount(item, "Vote withdraw", info->lamports);

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

static int print_vote_authorize_info(const VoteAuthorizeInfo *info,
                                     const PrintConfig *print_config) {
    const char *new_authority_title = NULL;
    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Set vote auth", info->account);

    switch (info->authorize) {
        case VoteAuthorizeVoter:
            new_authority_title = "New vote auth";
            break;
        case VoteAuthorizeWithdrawer:
            new_authority_title = "New withdraw auth";
            break;
    }

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, new_authority_title, info->new_authority);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}

static int print_vote_update_validator_id_info(const VoteUpdateValidatorIdInfo *info,
                                               const PrintConfig *print_config) {
    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Update validator", info->account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "New validator ID", info->new_validator_id);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}

static int print_vote_update_commission_info(const VoteUpdateCommissionInfo *info,
                                             const PrintConfig *print_config) {
    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Update commission", info->account);

    item = transaction_summary_general_item();
    summary_item_set_u64(item, "Commission", info->commission);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}

int print_vote_info(const VoteInfo *info, const PrintConfig *print_config) {
    switch (info->kind) {
        case VoteInitialize:
            return print_vote_initialize_info("Init vote acct", &info->initialize, print_config);
        case VoteWithdraw:
            return print_vote_withdraw_info(&info->withdraw, print_config);
        case VoteAuthorize:
        case VoteAuthorizeChecked:
            return print_vote_authorize_info(&info->authorize, print_config);
        case VoteUpdateValidatorId:
            return print_vote_update_validator_id_info(&info->update_validator_id, print_config);
        case VoteUpdateCommission:
            return print_vote_update_commission_info(&info->update_commission, print_config);
        case VoteVote:
        case VoteSwitchVote:
            break;
    }

    return 1;
}

int print_vote_initialize_info(const char *primary_title,
                               const VoteInitializeInfo *info,
                               const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;
    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->account);
    }

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Validator ID", info->vote_init.validator_id);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "New vote auth", info->vote_init.vote_authority);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "New withdraw auth", info->vote_init.withdraw_authority);

    item = transaction_summary_general_item();
    summary_item_set_u64(item, "Commission", info->vote_init.commission);

    return 0;
}
