#include "common_byte_strings.h"
#include "instruction.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "spl_associated_token_account_instruction.h"
#include "util.h"

const Pubkey spl_associated_token_account_program_id = {{PROGRAM_ID_SPL_ASSOCIATED_TOKEN_ACCOUNT}};

static int parse_create_spl_associated_token_account_instruction(
    const Instruction *instruction,
    const MessageHeader *header,
    SplAssociatedTokenAccountCreateInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->funder));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->address));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->owner));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint));
    // Skip system program_id
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip spl token program_id
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    // Skip (optional) rent sysvar
    instruction_accounts_iterator_next(&it, NULL);

    return 0;
}

int parse_spl_associated_token_account_instructions(const Instruction *instruction,
                                                    const MessageHeader *header,
                                                    SplAssociatedTokenAccountInfo *info) {
    return parse_create_spl_associated_token_account_instruction(instruction,
                                                                 header,
                                                                 &info->create);
}

int print_spl_associated_token_account_create_info(const SplAssociatedTokenAccountCreateInfo *info,
                                                   const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Create token account", info->address);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "For", info->owner);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Token address", info->mint);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Funded by", info->funder);

    /* hard-code current token account rent-exempt balance?
    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Funded with", 2039280);
    */

    return 0;
}

int print_spl_associated_token_account_info(const SplAssociatedTokenAccountInfo *info,
                                            const PrintConfig *print_config) {
    return print_spl_associated_token_account_create_info(&info->create, print_config);
}
