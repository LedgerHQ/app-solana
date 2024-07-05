#include "common_byte_strings.h"
#include "instruction.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "system_instruction.h"
#include "util.h"
#include <string.h>

#define CREATE_ACCOUNT_TITLE "Create account"

const Pubkey system_program_id = {{PROGRAM_ID_SYSTEM}};

static int parse_system_instruction_kind(Parser* parser, enum SystemInstructionKind* kind) {
    uint32_t maybe_kind;
    BAIL_IF(parse_u32(parser, &maybe_kind));
    switch (maybe_kind) {
        case SystemCreateAccount:
        case SystemAssign:
        case SystemTransfer:
        case SystemCreateAccountWithSeed:
        case SystemAdvanceNonceAccount:
        case SystemWithdrawNonceAccount:
        case SystemInitializeNonceAccount:
        case SystemAuthorizeNonceAccount:
        case SystemAllocate:
        case SystemAllocateWithSeed:
        case SystemAssignWithSeed:
            *kind = (enum SystemInstructionKind) maybe_kind;
            return 0;
    }
    return 1;
}

// Returns 0 and populates SystemTransferInfo if provided a MessageHeader
// and a transfer instruction, otherwise non-zero.
static int parse_system_transfer_instruction(Parser* parser,
                                             const Instruction* instruction,
                                             const MessageHeader* header,
                                             SystemTransferInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->from));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->to));

    BAIL_IF(parse_u64(parser, &info->lamports));

    return 0;
}

static int parse_system_create_account_instruction(Parser* parser,
                                                   const Instruction* instruction,
                                                   const MessageHeader* header,
                                                   SystemCreateAccountInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->from));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->to));

    BAIL_IF(parse_u64(parser, &info->lamports));

    return 0;
}

static int parse_system_create_account_with_seed_instruction(
    Parser* parser,
    const Instruction* instruction,
    const MessageHeader* header,
    SystemCreateAccountWithSeedInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->from));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->to));

    BAIL_IF(parse_pubkey(parser, &info->base));
    BAIL_IF(parse_sized_string(parser, &info->seed));
    BAIL_IF(parse_u64(parser, &info->lamports));

    return 0;
}

static int parse_system_advance_nonce_account_instruction(Parser* parser,
                                                          const Instruction* instruction,
                                                          const MessageHeader* header,
                                                          SystemAdvanceNonceInfo* info) {
    UNUSED(parser);

    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip recent blockhashes sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    return 0;
}

static int parse_system_initialize_nonce_account_instruction(Parser* parser,
                                                             const Instruction* instruction,
                                                             const MessageHeader* header,
                                                             SystemInitializeNonceInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip recent blockhashes sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip rent blockhashes sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));

    BAIL_IF(parse_pubkey(parser, &info->authority));

    return 0;
}

static int parse_system_withdraw_nonce_account_instruction(Parser* parser,
                                                           const Instruction* instruction,
                                                           const MessageHeader* header,
                                                           SystemWithdrawNonceInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->to));
    // Skip recent blockhashes sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip rent sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    BAIL_IF(parse_u64(parser, &info->lamports));

    return 0;
}

static int parse_system_authorize_nonce_account_instruction(Parser* parser,
                                                            const Instruction* instruction,
                                                            const MessageHeader* header,
                                                            SystemAuthorizeNonceInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->authority));

    BAIL_IF(parse_pubkey(parser, &info->new_authority));

    return 0;
}

static int parse_system_allocate_instruction(Parser* parser,
                                             const Instruction* instruction,
                                             const MessageHeader* header,
                                             SystemAllocateInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));

    BAIL_IF(parse_u64(parser, &info->space));

    return 0;
}

static int parse_system_assign_instruction(Parser* parser,
                                           const Instruction* instruction,
                                           const MessageHeader* header,
                                           SystemAssignInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));

    BAIL_IF(parse_pubkey(parser, &info->program_id));

    return 0;
}

static int parse_system_allocate_with_seed_instruction(Parser* parser,
                                                       const Instruction* instruction,
                                                       const MessageHeader* header,
                                                       SystemAllocateWithSeedInfo* info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));
    // Skip base, we have to parse it out of the ix anyway
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));

    BAIL_IF(parse_pubkey(parser, &info->base));
    BAIL_IF(parse_sized_string(parser, &info->seed));
    BAIL_IF(parse_u64(parser, &info->space));
    BAIL_IF(parse_pubkey(parser, &info->program_id));

    return 0;
}

int parse_system_instructions(const Instruction* instruction,
                              const MessageHeader* header,
                              SystemInfo* info) {
    Parser parser = {instruction->data, instruction->data_length};

    BAIL_IF(parse_system_instruction_kind(&parser, &info->kind));

    switch (info->kind) {
        case SystemTransfer:
            return parse_system_transfer_instruction(&parser, instruction, header, &info->transfer);
        case SystemAdvanceNonceAccount:
            return parse_system_advance_nonce_account_instruction(&parser,
                                                                  instruction,
                                                                  header,
                                                                  &info->advance_nonce);
        case SystemCreateAccount:
            return parse_system_create_account_instruction(&parser,
                                                           instruction,
                                                           header,
                                                           &info->create_account);
        case SystemCreateAccountWithSeed:
            return parse_system_create_account_with_seed_instruction(
                &parser,
                instruction,
                header,
                &info->create_account_with_seed);
        case SystemInitializeNonceAccount:
            return parse_system_initialize_nonce_account_instruction(&parser,
                                                                     instruction,
                                                                     header,
                                                                     &info->initialize_nonce);
        case SystemWithdrawNonceAccount:
            return parse_system_withdraw_nonce_account_instruction(&parser,
                                                                   instruction,
                                                                   header,
                                                                   &info->withdraw_nonce);
        case SystemAuthorizeNonceAccount:
            return parse_system_authorize_nonce_account_instruction(&parser,
                                                                    instruction,
                                                                    header,
                                                                    &info->authorize_nonce);
        case SystemAssign:
            return parse_system_assign_instruction(&parser, instruction, header, &info->assign);
        case SystemAllocate:
            return parse_system_allocate_instruction(&parser, instruction, header, &info->allocate);
        case SystemAllocateWithSeed:
            return parse_system_allocate_with_seed_instruction(&parser,
                                                               instruction,
                                                               header,
                                                               &info->allocate_with_seed);
        case SystemAssignWithSeed:
            break;
    }

    return 1;
}

static int print_system_transfer_info(const SystemTransferInfo* info,
                                      const PrintConfig* print_config) {
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_amount(item, "Transfer", info->lamports);

    if (print_config_show_authority(print_config, info->from)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Sender", info->from);
    }

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Recipient", info->to);

    return 0;
}

int print_system_prefund_for_split(const SystemInfo* info, const PrintConfig* print_config) {
    if (print_config->expert_mode) {
        const SystemTransferInfo* transfer_info = &info->transfer;
        SummaryItem* item;

        item = transaction_summary_general_item();
        summary_item_set_amount(item, "Prefund", transfer_info->lamports);

        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Prefunder", transfer_info->from);
    }

    return 0;
}

static int print_system_advance_nonce_account(const SystemAdvanceNonceInfo* info,
                                              const PrintConfig* print_config) {
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Advance nonce", info->account);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}

static int print_system_withdraw_nonce_info(const SystemWithdrawNonceInfo* info,
                                            const PrintConfig* print_config) {
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_amount(item, "Nonce withdraw", info->lamports);

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

static int print_system_authorize_nonce_info(const SystemAuthorizeNonceInfo* info,
                                             const PrintConfig* print_config) {
    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Set nonce auth", info->account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "New authority", info->new_authority);

    if (print_config_show_authority(print_config, info->authority)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authorized by", info->authority);
    }

    return 0;
}

static int print_system_allocate_info(const SystemAllocateInfo* info,
                                      const PrintConfig* print_config) {
    UNUSED(print_config);

    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Allocate acct", info->account);

    item = transaction_summary_general_item();
    summary_item_set_u64(item, "Data size", info->space);

    return 0;
}

static int print_system_assign_info(const SystemAssignInfo* info, const PrintConfig* print_config) {
    UNUSED(print_config);

    SummaryItem* item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Assign acct", info->account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "To program", info->program_id);

    return 0;
}

int print_system_info(const SystemInfo* info, const PrintConfig* print_config) {
    switch (info->kind) {
        case SystemTransfer:
            return print_system_transfer_info(&info->transfer, print_config);
        case SystemAdvanceNonceAccount:
            return print_system_advance_nonce_account(&info->advance_nonce, print_config);
        case SystemCreateAccount:
            return print_system_create_account_info(CREATE_ACCOUNT_TITLE,
                                                    &info->create_account,
                                                    print_config);
        case SystemCreateAccountWithSeed:
            return print_system_create_account_with_seed_info(CREATE_ACCOUNT_TITLE,
                                                              &info->create_account_with_seed,
                                                              print_config);
        case SystemInitializeNonceAccount:
            return print_system_initialize_nonce_info("Init nonce acct",
                                                      &info->initialize_nonce,
                                                      print_config);
        case SystemWithdrawNonceAccount:
            return print_system_withdraw_nonce_info(&info->withdraw_nonce, print_config);
        case SystemAuthorizeNonceAccount:
            return print_system_authorize_nonce_info(&info->authorize_nonce, print_config);
        case SystemAssign:
            return print_system_assign_info(&info->assign, print_config);
        case SystemAllocate:
            return print_system_allocate_info(&info->allocate, print_config);
        case SystemAllocateWithSeed:
            return print_system_allocate_with_seed_info("Allocate acct",
                                                        &info->allocate_with_seed,
                                                        print_config);
        case SystemAssignWithSeed:
            break;
    }

    return 1;
}

int print_system_nonced_transaction_sentinel(const SystemInfo* info,
                                             const PrintConfig* print_config) {
    if (print_config->expert_mode) {
        const SystemAdvanceNonceInfo* nonce_info = &info->advance_nonce;
        SummaryItem* item;

        item = transaction_summary_nonce_account_item();
        summary_item_set_pubkey(item, "Nonce account", nonce_info->account);

        item = transaction_summary_nonce_authority_item();
        summary_item_set_pubkey(item, "Nonce authority", nonce_info->authority);
    }

    return 0;
}

int print_system_create_account_info(const char* primary_title,
                                     const SystemCreateAccountInfo* info,
                                     const PrintConfig* print_config) {
    SummaryItem* item;
    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->to);
    }

    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Deposit", info->lamports);

    if (print_config_show_authority(print_config, info->from)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "From", info->from);
    }

    return 0;
}

int print_system_create_account_with_seed_info(const char* primary_title,
                                               const SystemCreateAccountWithSeedInfo* info,
                                               const PrintConfig* print_config) {
    SummaryItem* item;
    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->to);
    }

    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Deposit", info->lamports);

    if (print_config_show_authority(print_config, info->from)) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "From", info->from);
    }

    if (print_config->expert_mode) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Base", info->base);

        item = transaction_summary_general_item();
        summary_item_set_sized_string(item, "Seed", &info->seed);
    }

    return 0;
}

int print_system_initialize_nonce_info(const char* primary_title,
                                       const SystemInitializeNonceInfo* info,
                                       const PrintConfig* print_config) {
    UNUSED(print_config);

    SummaryItem* item;
    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->account);
    }

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "New authority", info->authority);

    return 0;
}

int print_system_allocate_with_seed_info(const char* primary_title,
                                         const SystemAllocateWithSeedInfo* info,
                                         const PrintConfig* print_config) {
    SummaryItem* item;

    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, "Allocate acct", info->account);
    }

    item = transaction_summary_general_item();
    summary_item_set_u64(item, "Data size", info->space);

    if (print_config->expert_mode) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Base", info->base);

        item = transaction_summary_general_item();
        summary_item_set_sized_string(item, "Seed", &info->seed);
    }

    return 0;
}
