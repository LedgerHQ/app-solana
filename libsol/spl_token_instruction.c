#include "common_byte_strings.h"
#include "instruction.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "spl_token_instruction.h"
#include "spl_token2022_instruction.h"
#include "token_info.h"
#include "util.h"
#include "sol/parser.h"
#include "ed25519_helpers.h"
#include "trusted_info.h"

#include "spl_token_instruction.h"

const Pubkey spl_token_program_id = {{PROGRAM_ID_SPL_TOKEN}};

static int parse_spl_token_instruction_kind(Parser *parser, SplTokenInstructionKind *kind) {
    uint8_t maybe_kind;
    BAIL_IF(parse_u8(parser, &maybe_kind));
    switch (maybe_kind) {
        case SplTokenKind(InitializeMint):
        case SplTokenKind(InitializeAccount):
        case SplTokenKind(InitializeAccount2):
        case SplTokenKind(InitializeMultisig):
        case SplTokenKind(TransferChecked):
        case SplTokenKind(ApproveChecked):
        case SplTokenKind(Revoke):
        case SplTokenKind(SetAuthority):
        case SplTokenKind(MintToChecked):
        case SplTokenKind(BurnChecked):
        case SplTokenKind(CloseAccount):
        case SplTokenKind(FreezeAccount):
        case SplTokenKind(ThawAccount):
        case SplTokenKind(SyncNative):

            // Token2022 extensions
        case SplTokenExtensionKind(TransferFeeExtension):
        case SplTokenExtensionKind(ConfidentialTransferExtension):
        case SplTokenExtensionKind(DefaultAccountStateExtension):
        case SplTokenExtensionKind(MemoTransferExtension):
        case SplTokenExtensionKind(InterestBearingMintExtension):
        case SplTokenExtensionKind(CpiGuardExtension):
        case SplTokenExtensionKind(TransferHookExtension):
        case SplTokenExtensionKind(ConfidentialTransferFeeExtension):
        case SplTokenExtensionKind(MetadataPointerExtension):
        case SplTokenExtensionKind(GroupPointerExtension):
        case SplTokenExtensionKind(GroupMemberPointerExtension):
            *kind = (SplTokenInstructionKind) maybe_kind;
            return 0;

        // Deprecated instructions
        case SplTokenKind(Transfer):
        case SplTokenKind(Approve):
        case SplTokenKind(MintTo):
        case SplTokenKind(Burn):
            PRINTF("Deprecated instruction %d\n", maybe_kind);
            return 1;
        default:
            PRINTF("Unknown instruction %d\n", maybe_kind);
            return 1;
    }
}

static int parse_initialize_mint_spl_token_instruction(Parser *parser,
                                                       const Instruction *instruction,
                                                       const MessageHeader *header,
                                                       SplTokenInitializeMintInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(parse_u8(parser, &info->decimals));
    BAIL_IF(parse_pubkey(parser, &info->mint_authority));
    enum Option freeze_authority;
    BAIL_IF(parse_option(parser, &freeze_authority));
    if (freeze_authority == OptionSome) {
        BAIL_IF(parse_pubkey(parser, &info->freeze_authority));
    } else {
        info->freeze_authority = NULL;
    }

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint_account));
    // Skip rent sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));

    return 0;
}

static int parse_initialize_account_spl_token_instruction(Parser *parser,
                                                          const Instruction *instruction,
                                                          const MessageHeader *header,
                                                          SplTokenInitializeAccountInfo *info,
                                                          bool expect_owner_in_accounts) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    if (expect_owner_in_accounts) {
        BAIL_IF(instruction->accounts_length != 4);
    }

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint_account));
    if (expect_owner_in_accounts) {
        BAIL_IF(instruction_accounts_iterator_next(&it, &info->owner));
    }
    // Skip rent sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));

    if (!expect_owner_in_accounts) {
        BAIL_IF(parse_pubkey(parser, &info->owner));
    }

    return 0;
}

static int parse_spl_token_multisigners(InstructionAccountsIterator *it,
                                        SplTokenMultisigners *signers) {
    size_t n = instruction_accounts_iterator_remaining(it);
    BAIL_IF(n > Token_MAX_SIGNERS);
    BAIL_IF(instruction_accounts_iterator_next(it, &signers->first));
    signers->count = n;
    return 0;
}

static int parse_initialize_multisig_spl_token_instruction(Parser *parser,
                                                           const Instruction *instruction,
                                                           const MessageHeader *header,
                                                           SplTokenInitializeMultisigInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(parse_u8(parser, &info->body.m));
    BAIL_IF(info->body.m > Token_MAX_SIGNERS);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->multisig_account));
    // Skip rent sysvar
    BAIL_IF(instruction_accounts_iterator_next(&it, NULL));
    BAIL_IF(parse_spl_token_multisigners(&it, &info->signers));

    return 0;
}

static int parse_spl_token_sign(InstructionAccountsIterator *it, SplTokenSign *sign) {
    size_t n = instruction_accounts_iterator_remaining(it);
    BAIL_IF(n == 0);
    if (n == 1) {
        sign->kind = SplTokenSignKindSingle;
        PRINTF("Single signer transaction\n");
        BAIL_IF(instruction_accounts_iterator_next(it, &sign->single.signer));
    } else {
        sign->kind = SplTokenSignKindMulti;
        PRINTF("Multi signer transaction\n");
        // We don't bother with trailing account refined detection, all are treated as signers
        // Maybe this should be re-evaluated even for legacy tokens?
        BAIL_IF(instruction_accounts_iterator_next(it, &sign->multi.account));
        BAIL_IF(parse_spl_token_multisigners(it, &sign->multi.signers));
    }
    return 0;
}

// Please see comments on TransferChecked in token.h to understand better account ordering
static int parse_spl_token2022_sign(const MessageHeader *header,
                                    InstructionAccountsIterator *it,
                                    SplTokenSign *sign) {
    int current_account_index = instruction_accounts_iterator_get_current_account_index(it);
    // We need at least the standard signer
    BAIL_IF(current_account_index < 0);
    // Check if the first additional account is a signed one.
    if (current_account_index < header->pubkeys_header.num_required_signatures) {
        sign->kind = SplTokenSignKindSingle;
        PRINTF("Single signer transaction\n");
        BAIL_IF(instruction_accounts_iterator_next(it, &sign->single.signer));
    } else {
        // Multi signature detected
        sign->kind = SplTokenSignKindMulti;
        PRINTF("Multi signers transaction\n");
        BAIL_IF(instruction_accounts_iterator_next(it, &sign->multi.account));
        BAIL_IF(instruction_accounts_iterator_next(it, &sign->multi.signers.first));
        uint8_t signers_count = 1;
        // Count and skip all next signers
        while (instruction_accounts_iterator_remaining(it) > 0) {
            current_account_index = instruction_accounts_iterator_get_current_account_index(it);
            PRINTF("Checking account[%d] = %d: ",
                   it->current_instruction_account,
                   current_account_index);
            if (current_account_index < header->pubkeys_header.num_required_signatures) {
                PRINTF("Signer\n");
                ++signers_count;
                BAIL_IF(instruction_accounts_iterator_next(it, NULL));
            } else {
                // Not signers anymore
                PRINTF("NOT a signer\n");
                break;
            }
        }
        // Register signers count
        BAIL_IF(signers_count > Token_MAX_SIGNERS);
        sign->multi.signers.count = signers_count;
        PRINTF("Multi signers count = %d\n", sign->multi.signers.count);
    }
    return 0;
}

static int parse_spl_token_hook(InstructionAccountsIterator *it,
                                bool *is_transfer_checked_with_hook) {
    // We skipped the whole single / multi signers accounts. If we have remaining accounts it means
    // we are signing a TX that will trigger a transfer hook.
    size_t n = instruction_accounts_iterator_remaining(it);
    *is_transfer_checked_with_hook = (n != 0);
    return 0;
}

static int parse_transfer_spl_token_instruction(Parser *parser,
                                                const Instruction *instruction,
                                                const MessageHeader *header,
                                                SplTokenTransferInfo *info,
                                                bool is_transfer_checked_with_fee,
                                                bool is_token2022_kind) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(parse_u64(parser, &info->body.amount));
    BAIL_IF(parse_u8(parser, &info->body.decimals));
    info->is_transfer_checked_with_fee = is_transfer_checked_with_fee;
    if (is_transfer_checked_with_fee) {
        BAIL_IF(parse_u64(parser, &info->transfer_checked_with_fee_amount));
    }

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->src_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->dest_account));

    if (is_token2022_kind) {
        BAIL_IF(parse_spl_token2022_sign(header, &it, &info->sign));
        BAIL_IF(parse_spl_token_hook(&it, &info->is_transfer_checked_with_hook));
        if (info->is_transfer_checked_with_hook) {
            PRINTF("Transfer hook detected\n");
        }
    } else {
        BAIL_IF(parse_spl_token_sign(&it, &info->sign));
    }

    if (!check_ata_agaisnt_trusted_info(info->src_account->data,
                                        info->mint_account->data,
                                        info->dest_account->data,
                                        is_token2022_kind)) {
        PRINTF("check_ata_agaisnt_trusted_info failed\n");
        return -1;
    }

    return 0;
}

static int parse_approve_spl_token_instruction(Parser *parser,
                                               const Instruction *instruction,
                                               const MessageHeader *header,
                                               SplTokenApproveInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(parse_u64(parser, &info->body.amount));
    BAIL_IF(parse_u8(parser, &info->body.decimals));

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->delegate));

    BAIL_IF(parse_spl_token_sign(&it, &info->sign));

    return 0;
}

static int parse_revoke_spl_token_instruction(const Instruction *instruction,
                                              const MessageHeader *header,
                                              SplTokenRevokeInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));

    BAIL_IF(parse_spl_token_sign(&it, &info->sign));

    return 0;
}

static int parse_token_authority_type(Parser *parser, Token_AuthorityType *auth_type) {
    uint8_t maybe_type;
    BAIL_IF(parse_u8(parser, &maybe_type));
    switch (maybe_type) {
        case Token_AuthorityType_MintTokens:
        case Token_AuthorityType_FreezeAccount:
        case Token_AuthorityType_AccountOwner:
        case Token_AuthorityType_CloseAccount:
            *auth_type = (Token_AuthorityType) maybe_type;
            return 0;
    }
    return 1;
}

static const char *stringify_token_authority_type(Token_AuthorityType auth_type) {
    switch (auth_type) {
        case Token_AuthorityType_MintTokens:
            return "Mint tokens";
        case Token_AuthorityType_FreezeAccount:
            return "Freeze account";
        case Token_AuthorityType_AccountOwner:
            return "Owner";
        case Token_AuthorityType_CloseAccount:
            return "Close acct";
    }
    return NULL;
}

static int parse_set_authority_spl_token_instruction(Parser *parser,
                                                     const Instruction *instruction,
                                                     const MessageHeader *header,
                                                     SplTokenSetAuthorityInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->account));

    BAIL_IF(parse_token_authority_type(parser, &info->authority_type));

    enum Option new_authority;
    BAIL_IF(parse_option(parser, &new_authority));
    if (new_authority == OptionSome) {
        BAIL_IF(parse_pubkey(parser, &info->new_authority));
    } else {
        info->new_authority = NULL;
    }

    BAIL_IF(parse_spl_token_sign(&it, &info->sign));

    return 0;
}

static int parse_mint_to_spl_token_instruction(Parser *parser,
                                               const Instruction *instruction,
                                               const MessageHeader *header,
                                               SplTokenMintToInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(parse_u64(parser, &info->body.amount));
    BAIL_IF(parse_u8(parser, &info->body.decimals));

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));

    BAIL_IF(parse_spl_token_sign(&it, &info->sign));

    return 0;
}

static int parse_burn_spl_token_instruction(Parser *parser,
                                            const Instruction *instruction,
                                            const MessageHeader *header,
                                            SplTokenBurnInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(parse_u64(parser, &info->body.amount));
    BAIL_IF(parse_u8(parser, &info->body.decimals));

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint_account));

    BAIL_IF(parse_spl_token_sign(&it, &info->sign));

    return 0;
}

static int parse_close_account_spl_token_instruction(const Instruction *instruction,
                                                     const MessageHeader *header,
                                                     SplTokenCloseAccountInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->dest_account));

    BAIL_IF(parse_spl_token_sign(&it, &info->sign));

    return 0;
}

static int parse_freeze_account_spl_token_instruction(const Instruction *instruction,
                                                      const MessageHeader *header,
                                                      SplTokenFreezeAccountInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint_account));

    BAIL_IF(parse_spl_token_sign(&it, &info->sign));

    return 0;
}

static int parse_thaw_account_spl_token_instruction(const Instruction *instruction,
                                                    const MessageHeader *header,
                                                    SplTokenThawAccountInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));
    BAIL_IF(instruction_accounts_iterator_next(&it, &info->mint_account));

    BAIL_IF(parse_spl_token_sign(&it, &info->sign));

    return 0;
}

static int parse_sync_native_spl_token_instruction(const Instruction *instruction,
                                                   const MessageHeader *header,
                                                   SplTokenSyncNativeInfo *info) {
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, header, instruction);

    BAIL_IF(instruction_accounts_iterator_next(&it, &info->token_account));

    return 0;
}

typedef enum transfer_fee_instruction_tag_e {
    InitializeTransferFeeConfig = 0,
    TransferCheckedWithFee = 1,
    WithdrawWithheldTokensFromMint = 2,
    WithdrawWithheldTokensFromAccounts = 3,
    HarvestWithheldTokensToMint = 4,
    SetTransferFee = 5,
} transfer_fee_instruction_tag_t;

static int parse_transfer_fee_instruction(Parser *parser, transfer_fee_instruction_tag_t *tag) {
    uint8_t maybe_tag;
    BAIL_IF(parse_u8(parser, &maybe_tag));
    switch (maybe_tag) {
        case InitializeTransferFeeConfig:
        case TransferCheckedWithFee:
        case WithdrawWithheldTokensFromMint:
        case WithdrawWithheldTokensFromAccounts:
        case HarvestWithheldTokensToMint:
        case SetTransferFee:
            *tag = (transfer_fee_instruction_tag_t) maybe_tag;
            return 0;
        default:
            PRINTF("Unknown transfer_fee_instruction tag %d\n", maybe_tag);
            return 1;
    }
}

int parse_spl_token_instructions(const Instruction *instruction,
                                 const MessageHeader *header,
                                 SplTokenInfo *info,
                                 bool *ignore_instruction_info) {
    Parser parser = {instruction->data, instruction->data_length};

    if (parse_spl_token_instruction_kind(&parser, &info->kind) != 0) {
        PRINTF("parse_spl_token_instruction_kind failed\n");
        return -1;
    }

    info->is_token2022_kind = is_token2022_instruction(instruction, header);

    switch (info->kind) {
        case SplTokenKind(InitializeMint):
            return parse_initialize_mint_spl_token_instruction(&parser,
                                                               instruction,
                                                               header,
                                                               &info->initialize_mint);
        case SplTokenKind(InitializeAccount):
            return parse_initialize_account_spl_token_instruction(&parser,
                                                                  instruction,
                                                                  header,
                                                                  &info->initialize_account,
                                                                  true);
        case SplTokenKind(InitializeAccount2):
            return parse_initialize_account_spl_token_instruction(&parser,
                                                                  instruction,
                                                                  header,
                                                                  &info->initialize_account,
                                                                  false);
        case SplTokenKind(InitializeMultisig):
            return parse_initialize_multisig_spl_token_instruction(&parser,
                                                                   instruction,
                                                                   header,
                                                                   &info->initialize_multisig);
        case SplTokenKind(Revoke):
            return parse_revoke_spl_token_instruction(instruction, header, &info->revoke);
        case SplTokenKind(SetAuthority):
            return parse_set_authority_spl_token_instruction(&parser,
                                                             instruction,
                                                             header,
                                                             &info->set_owner);
        case SplTokenKind(CloseAccount):
            return parse_close_account_spl_token_instruction(instruction,
                                                             header,
                                                             &info->close_account);
        case SplTokenKind(FreezeAccount):
            return parse_freeze_account_spl_token_instruction(instruction,
                                                              header,
                                                              &info->freeze_account);
        case SplTokenKind(ThawAccount):
            return parse_thaw_account_spl_token_instruction(instruction,
                                                            header,
                                                            &info->thaw_account);
        case SplTokenKind(TransferChecked):
            return parse_transfer_spl_token_instruction(&parser,
                                                        instruction,
                                                        header,
                                                        &info->transfer,
                                                        false,
                                                        info->is_token2022_kind);
        case SplTokenKind(ApproveChecked):
            return parse_approve_spl_token_instruction(&parser,
                                                       instruction,
                                                       header,
                                                       &info->approve);
        case SplTokenKind(MintToChecked):
            return parse_mint_to_spl_token_instruction(&parser,
                                                       instruction,
                                                       header,
                                                       &info->mint_to);
        case SplTokenKind(BurnChecked):
            return parse_burn_spl_token_instruction(&parser, instruction, header, &info->burn);
        case SplTokenKind(SyncNative):
            return parse_sync_native_spl_token_instruction(instruction, header, &info->sync_native);

        // Handle only TransferCheckedWithFee of the TransferFeeExtension
        case SplTokenExtensionKind(TransferFeeExtension):
            if (!info->is_token2022_kind) {
                PRINTF("Can't use extension with standard token\n");
                return 1;
            }
            transfer_fee_instruction_tag_t tag;
            if (parse_transfer_fee_instruction(&parser, &tag) != 0) {
                PRINTF("Failed parse_transfer_fee_instruction\n");
                return 1;
            }
            if (tag == TransferCheckedWithFee) {
                return parse_transfer_spl_token_instruction(&parser,
                                                            instruction,
                                                            header,
                                                            &info->transfer,
                                                            true,
                                                            info->is_token2022_kind);
            }
            __attribute__((fallthrough));

        // Currently we do not need to parse these extensions in any way
        case SplTokenExtensionKind(ConfidentialTransferExtension):
        case SplTokenExtensionKind(MemoTransferExtension):
        case SplTokenExtensionKind(TransferHookExtension):
        case SplTokenExtensionKind(ConfidentialTransferFeeExtension):
            // Mark that we have encountered not fully supported extension
            info->generate_extension_warning = true;
            __attribute__((fallthrough));
        case SplTokenExtensionKind(DefaultAccountStateExtension):
        case SplTokenExtensionKind(InterestBearingMintExtension):
        case SplTokenExtensionKind(CpiGuardExtension):
        case SplTokenExtensionKind(MetadataPointerExtension):
        case SplTokenExtensionKind(GroupPointerExtension):
        case SplTokenExtensionKind(GroupMemberPointerExtension):
            // Don't generate any screens for the user for any extension
            *ignore_instruction_info = true;
            return 0;

        // Deprecated instructions
        case SplTokenKind(Transfer):
        case SplTokenKind(Approve):
        case SplTokenKind(MintTo):
        case SplTokenKind(Burn):
            break;
    }
    return 1;
}

static int print_spl_token_sign(const SplTokenSign *sign, const PrintConfig *print_config) {
    SummaryItem *item;

    item = transaction_summary_general_item();
    if (sign->kind == SplTokenSignKindSingle) {
        if (print_config_show_authority(print_config, sign->single.signer)) {
            summary_item_set_pubkey(item, "Owner", sign->single.signer);
        }
    } else {
        summary_item_set_pubkey(item, "Owner", sign->multi.account);
        item = transaction_summary_general_item();
        summary_item_set_u64(item, "Signers", sign->multi.signers.count);
    }

    return 0;
}

static int print_spl_token_initialize_mint_info(const char *primary_title,
                                                const SplTokenInitializeMintInfo *info,
                                                const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;

    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->mint_account);
    }

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Mint authority", info->mint_authority);

    item = transaction_summary_general_item();
    summary_item_set_u64(item, "Decimals", info->decimals);

    if (info->freeze_authority != NULL) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Freeze authority", info->freeze_authority);
    }

    return 0;
}

static int print_spl_token_initialize_account_info(const char *primary_title,
                                                   const SplTokenInitializeAccountInfo *info,
                                                   const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;

    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->token_account);
    }

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Owner", info->owner);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Token address", info->mint_account);

    return 0;
}

static int print_spl_token_initialize_multisig_info(const char *primary_title,
                                                    const SplTokenInitializeMultisigInfo *info,
                                                    const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;

    if (primary_title != NULL) {
        item = transaction_summary_primary_item();
        summary_item_set_pubkey(item, primary_title, info->multisig_account);
    }

    item = transaction_summary_general_item();
    summary_item_set_multisig_m_of_n(item, info->body.m, info->signers.count);

    return 0;
}

const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind) {
    const char *ret;
    ret = get_dynamic_token_symbol(mint_address, is_token_2022_kind);
    if (ret == NULL) {
        PRINTF("No dynamic token info received, fallback on hardcoded list\n");
        ret = get_hardcoded_token_symbol(mint_address);
    }
    return ret;
}

int print_spl_token_transfer_info(const SplTokenTransferInfo *info,
                                  const PrintConfig *print_config,
                                  bool is_token2022_kind,
                                  bool primary) {
    SummaryItem *item;

    if (primary) {
        item = transaction_summary_primary_item();
    } else {
        item = transaction_summary_general_item();
    }

    const char *symbol = get_token_symbol(info->mint_account->data, is_token2022_kind);

    summary_item_set_token_amount(item,
                                  "Transfer tokens",
                                  info->body.amount,
                                  symbol,
                                  info->body.decimals);

    item = transaction_summary_general_item();
    if (info->is_transfer_checked_with_fee) {
        if (info->transfer_checked_with_fee_amount != 0) {
            summary_item_set_token_amount(item,
                                          "Token transfer fee",
                                          info->transfer_checked_with_fee_amount,
                                          symbol,
                                          info->body.decimals);
        }
    }

    char *to_address;
    if (get_transfer_to_address(&to_address) != 0) {
        return -1;
    }
    item = transaction_summary_general_item();
    summary_item_set_string(item, "To", to_address);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Token address", info->mint_account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "From (token account)", info->src_account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "To (token account)", info->dest_account);

    transaction_summary_set_token_fee_warning(is_token2022_kind &&
                                              !info->is_transfer_checked_with_fee);
    transaction_summary_set_token_hook_warning(is_token2022_kind &&
                                               info->is_transfer_checked_with_hook);
    transaction_summary_set_is_token_2022_transfer(is_token2022_kind);

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_approve_info(const SplTokenApproveInfo *info,
                                        const PrintConfig *print_config,
                                        bool is_token2022_kind) {
    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Approve delegate", info->delegate);

    item = transaction_summary_general_item();
    const char *symbol = get_token_symbol(info->mint_account->data, is_token2022_kind);
    summary_item_set_token_amount(item,
                                  "Allowance",
                                  info->body.amount,
                                  symbol,
                                  info->body.decimals);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Token address", info->mint_account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "From (token account)", info->token_account);

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_revoke_info(const SplTokenRevokeInfo *info,
                                       const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Revoke delegate", info->token_account);

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_set_authority_info(const SplTokenSetAuthorityInfo *info,
                                              const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;
    bool clear_authority = info->new_authority == NULL;
    const char *primary_title = "Set authority";
    if (clear_authority) {
        primary_title = "Clear authority";
    }

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, primary_title, info->account);

    const char *authority_type = stringify_token_authority_type(info->authority_type);
    BAIL_IF(authority_type == NULL);
    item = transaction_summary_general_item();
    summary_item_set_string(item, "Type", authority_type);

    if (!clear_authority) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Authority", info->new_authority);
    }

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_mint_to_info(const SplTokenMintToInfo *info,
                                        const PrintConfig *print_config,
                                        bool is_token2022_kind) {
    SummaryItem *item;

    item = transaction_summary_primary_item();
    const char *symbol = get_token_symbol(info->mint_account->data, is_token2022_kind);
    summary_item_set_token_amount(item,
                                  "Mint tokens",
                                  info->body.amount,
                                  symbol,
                                  info->body.decimals);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Token address", info->mint_account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "To (token account)", info->token_account);

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_burn_info(const SplTokenBurnInfo *info,
                                     const PrintConfig *print_config,
                                     bool is_token2022_kind) {
    UNUSED(print_config);

    SummaryItem *item;

    item = transaction_summary_primary_item();
    const char *symbol = get_token_symbol(info->mint_account->data, is_token2022_kind);
    summary_item_set_token_amount(item,
                                  "Burn tokens",
                                  info->body.amount,
                                  symbol,
                                  info->body.decimals);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Token address", info->mint_account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "From (token account)", info->token_account);

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_close_account_info(const SplTokenCloseAccountInfo *info,
                                              const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Close token account", info->token_account);

    item = transaction_summary_general_item();
    summary_item_set_pubkey(item, "Withdraw to", info->dest_account);

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_freeze_account_info(const SplTokenFreezeAccountInfo *info,
                                               const PrintConfig *print_config) {
    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Freeze token account", info->token_account);

    if (print_config->expert_mode) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Token address", info->mint_account);
    }

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_thaw_account_info(const SplTokenThawAccountInfo *info,
                                             const PrintConfig *print_config) {
    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Thaw token account", info->token_account);

    if (print_config->expert_mode) {
        item = transaction_summary_general_item();
        summary_item_set_pubkey(item, "Token address", info->mint_account);
    }

    print_spl_token_sign(&info->sign, print_config);

    return 0;
}

static int print_spl_token_sync_native_info(const SplTokenSyncNativeInfo *info,
                                            const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;

    item = transaction_summary_primary_item();
    summary_item_set_pubkey(item, "Sync native account", info->token_account);

    return 0;
}

int print_spl_token_info(const SplTokenInfo *info, const PrintConfig *print_config) {
    switch (info->kind) {
        case SplTokenKind(InitializeMint):
            return print_spl_token_initialize_mint_info("Init mint",
                                                        &info->initialize_mint,
                                                        print_config);
        case SplTokenKind(InitializeAccount):
        case SplTokenKind(InitializeAccount2):
            return print_spl_token_initialize_account_info("Init acct",
                                                           &info->initialize_account,
                                                           print_config);
        case SplTokenKind(InitializeMultisig):
            return print_spl_token_initialize_multisig_info("Init multisig",
                                                            &info->initialize_multisig,
                                                            print_config);
        case SplTokenKind(Revoke):
            return print_spl_token_revoke_info(&info->revoke, print_config);
        case SplTokenKind(SetAuthority):
            return print_spl_token_set_authority_info(&info->set_owner, print_config);
        case SplTokenKind(CloseAccount):
            return print_spl_token_close_account_info(&info->close_account, print_config);
        case SplTokenKind(FreezeAccount):
            return print_spl_token_freeze_account_info(&info->freeze_account, print_config);
        case SplTokenKind(ThawAccount):
            return print_spl_token_thaw_account_info(&info->thaw_account, print_config);
        case SplTokenKind(TransferChecked):
            return print_spl_token_transfer_info(&info->transfer,
                                                 print_config,
                                                 info->is_token2022_kind,
                                                 true);
        case SplTokenKind(ApproveChecked):
            return print_spl_token_approve_info(&info->approve,
                                                print_config,
                                                info->is_token2022_kind);
        case SplTokenKind(MintToChecked):
            return print_spl_token_mint_to_info(&info->mint_to,
                                                print_config,
                                                info->is_token2022_kind);
        case SplTokenKind(BurnChecked):
            return print_spl_token_burn_info(&info->burn, print_config, info->is_token2022_kind);
        case SplTokenKind(SyncNative):
            return print_spl_token_sync_native_info(&info->sync_native, print_config);

        case SplTokenExtensionKind(TransferFeeExtension):
            return print_spl_token_transfer_info(&info->transfer,
                                                 print_config,
                                                 info->is_token2022_kind,
                                                 true);

        // For now, we don't display any information about the extensions
        case SplTokenExtensionKind(ConfidentialTransferExtension):
        case SplTokenExtensionKind(DefaultAccountStateExtension):
        case SplTokenExtensionKind(MemoTransferExtension):
        case SplTokenExtensionKind(InterestBearingMintExtension):
        case SplTokenExtensionKind(CpiGuardExtension):
        case SplTokenExtensionKind(TransferHookExtension):
        case SplTokenExtensionKind(ConfidentialTransferFeeExtension):
        case SplTokenExtensionKind(MetadataPointerExtension):
        case SplTokenExtensionKind(GroupPointerExtension):
        case SplTokenExtensionKind(GroupMemberPointerExtension):

        // Deprecated instructions
        case SplTokenKind(Transfer):
        case SplTokenKind(Approve):
        case SplTokenKind(MintTo):
        case SplTokenKind(Burn):
            break;
    }

    return 1;
}

#define M_OF_N_MAX_LEN 9  // "11 of 11" + NUL
static int print_m_of_n_string(uint8_t m, uint8_t n, char *buf, size_t buflen) {
    BAIL_IF(n > Token_MAX_SIGNERS);
    BAIL_IF(m > n);
    BAIL_IF(buflen < M_OF_N_MAX_LEN);

    size_t i = 0;
    if (m > 9) buf[i++] = '1';
    buf[i++] = '0' + (m % 10);
    strncpy(&buf[i], " of ", 5);
    i += 4;
    if (n > 9) buf[i++] = '1';
    buf[i++] = '0' + (n % 10);
    buf[i] = '\0';

    return 0;
}

void summary_item_set_multisig_m_of_n(SummaryItem *item, uint8_t m, uint8_t n) {
    static char m_of_n[M_OF_N_MAX_LEN];

    if (print_m_of_n_string(m, n, m_of_n, sizeof(m_of_n)) == 0) {
        summary_item_set_string(item, "Required signers", m_of_n);
    }
}

const Pubkey *spl_token_option_pubkey_get(const SplTokenOptionPubkey *option_pubkey) {
    switch (option_pubkey->tag) {
        case SplTokenToOptionPubkeyKind(None):
            break;
        case SplTokenToOptionPubkeyKind(Some):
            return (const Pubkey *) &option_pubkey->some;
    }
    return NULL;
}

bool is_token2022_instruction(const Instruction *instruction, const MessageHeader *header) {
    PRINTF("is_token2022_instruction ?\n");
    const Pubkey *program_id = &header->pubkeys[instruction->program_id_index];
    return memcmp(program_id, &spl_token2022_program_id, PUBKEY_SIZE) == 0;
}
