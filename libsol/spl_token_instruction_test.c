#include "common_byte_strings.h"
#include "instruction.h"
#include "spl_token_instruction.c"
#include <stdio.h>
#include <assert.h>

void print_pubkey(const Pubkey *pubkey) {
    char buf[45];
    encode_base58(pubkey, 32, buf, sizeof(buf));
    printf("%s\n", buf);
}

#define BLOCKHASH        BYTES32_BS58_1
#define MINT_ACCOUNT     BYTES32_BS58_2
#define TOKEN_ACCOUNT    BYTES32_BS58_3
#define OWNER_ACCOUNT    BYTES32_BS58_4
#define MULTISIG_ACCOUNT OWNER_ACCOUNT
#define SIGNER1          BYTES32_BS58_5
#define SIGNER2          BYTES32_BS58_6
#define SIGNER3          BYTES32_BS58_7
#define DEST_ACCOUNT     BYTES32_BS58_8
#define DELEGATE         DEST_ACCOUNT
#define NEW_OWNER        DEST_ACCOUNT

void test_parse_spl_token_create_token() {
    uint8_t message[] = {2,
                         0,
                         3,
                         5,
                         OWNER_ACCOUNT,
                         MINT_ACCOUNT,
                         SYSVAR_RENT,
                         PROGRAM_ID_SYSTEM,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         2,
                         3,
                         2,
                         0,
                         1,
                         52,
                         0,
                         0,
                         0,
                         0,
                         245,
                         1,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         88,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         PROGRAM_ID_SPL_TOKEN,
                         4,
                         2,
                         1,
                         2,
                         35,
                         0,
                         9,
                         OWNER_ACCOUNT,
                         0};

    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SystemCreateAccount (ignored)
    assert(instruction_validate(&instruction, &header) == 0);
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenInitializeMint
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(InitializeMint));

    const SplTokenInitializeMintInfo *init_mint = &info.initialize_mint;

    const Pubkey mint_account = {{MINT_ACCOUNT}};
    assert_pubkey_equal(init_mint->mint_account, &mint_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(init_mint->mint_authority, &owner);

    assert(init_mint->decimals == 9);

    assert(init_mint->freeze_authority == NULL);
}

void test_parse_spl_token_create_account() {
    uint8_t message[] = {
        0x02,
        0x00,
        0x03,
        0x06,
        OWNER_ACCOUNT,
        TOKEN_ACCOUNT,
        MINT_ACCOUNT,
        SYSVAR_RENT,
        PROGRAM_ID_SYSTEM,
        PROGRAM_ID_SPL_TOKEN,
        BLOCKHASH,
        0x02,
        // SystemCreateAccount
        0x04,
        0x02,
        0x00,
        0x01,
        0x34,
        0x00,
        0x00,
        0x00,
        0x00,
        0x80,
        0x56,
        0x1a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x78,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        PROGRAM_ID_SPL_TOKEN,
        // SplTokenInitializeAccount
        0x05,
        0x04,
        0x01,
        0x02,
        0x00,
        0x03,
        0x01,
        0x01,
    };

    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SystemCreateAccount (ignored)
    assert(instruction_validate(&instruction, &header) == 0);
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenInitializeAccount
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(InitializeAccount));
    const SplTokenInitializeAccountInfo *init_acc = &info.initialize_account;

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(init_acc->token_account, &token_account);

    const Pubkey mint_account = {{MINT_ACCOUNT}};
    assert_pubkey_equal(init_acc->mint_account, &mint_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(init_acc->owner, &owner);
}

void test_parse_spl_token_create_account2() {
    uint8_t message[] = {0x02,
                         0x00,
                         0x04,
                         0x06,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         MINT_ACCOUNT,
                         SYSVAR_RENT,
                         PROGRAM_ID_SYSTEM,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         0x02,
                         // SystemCreateAccount
                         0x04,
                         0x02,
                         0x00,
                         0x01,
                         0x34,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x80,
                         0x56,
                         0x1a,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x78,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         PROGRAM_ID_SPL_TOKEN,
                         // SplTokenInitializeAccount2
                         0x05,
                         0x03,
                         0x01,
                         0x02,
                         0x03,
                         0x21,
                         0x10,
                         OWNER_ACCOUNT};

    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SystemCreateAccount (ignored)
    assert(instruction_validate(&instruction, &header) == 0);
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenInitializeAccount2
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(InitializeAccount2));
    const SplTokenInitializeAccountInfo *init_acc = &info.initialize_account;

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(init_acc->token_account, &token_account);

    const Pubkey mint_account = {{MINT_ACCOUNT}};
    assert_pubkey_equal(init_acc->mint_account, &mint_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(init_acc->owner, &owner);
}

void test_parse_spl_token_create_multisig() {
    uint8_t message[] = {2,
                         0,
                         5,
                         8,
                         OWNER_ACCOUNT,
                         MULTISIG_ACCOUNT,
                         SYSVAR_RENT,
                         SIGNER1,
                         SIGNER2,
                         SIGNER3,
                         PROGRAM_ID_SYSTEM,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         2,
                         // SystemCreateAccount
                         6,
                         2,
                         0,
                         1,
                         52,
                         0,
                         0,
                         0,
                         0,
                         245,
                         1,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         40,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         PROGRAM_ID_SPL_TOKEN,
                         // SplTokenInitializeMultisig
                         7,
                         5,
                         1,
                         2,
                         3,
                         4,
                         5,
                         2,
                         2,
                         2};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SystemCreateAccount (ignored)
    assert(instruction_validate(&instruction, &header) == 0);
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenInitializeMultisig
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(InitializeMultisig));
    const SplTokenInitializeMultisigInfo *init_ms = &info.initialize_multisig;

    assert(init_ms->body.m == 2);

    const Pubkey multisig_account = {{MULTISIG_ACCOUNT}};
    assert_pubkey_equal(init_ms->multisig_account, &multisig_account);

    assert(init_ms->signers.count == 3);
    const Pubkey *signer = init_ms->signers.first;
    const Pubkey signer1 = {{SIGNER1}};
    assert_pubkey_equal(signer++, &signer1);
    const Pubkey signer2 = {{SIGNER2}};
    assert_pubkey_equal(signer++, &signer2);
    const Pubkey signer3 = {{SIGNER3}};
    assert_pubkey_equal(signer++, &signer3);
}

void test_parse_spl_token_transfer() {
    uint8_t message[] = {1,
                         0,
                         2,
                         5,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         DEST_ACCOUNT,
                         MINT_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         1,
                         4,
                         4,
                         1,
                         3,
                         2,
                         0,
                         10,
                         12,
                         42,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         9};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenTransfer2
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(TransferChecked));
    const SplTokenTransferInfo *tr_info = &info.transfer;

    assert(tr_info->body.amount == 42);
    assert(tr_info->body.decimals == 9);

    const Pubkey src_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(tr_info->src_account, &src_account);

    const Pubkey dest_account = {{DEST_ACCOUNT}};
    assert_pubkey_equal(tr_info->dest_account, &dest_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(tr_info->sign.single.signer, &owner);

    const Pubkey mint_account = {{MINT_ACCOUNT}};
    assert_pubkey_equal(tr_info->mint_account, &mint_account);
}

void test_parse_spl_token_approve() {
    uint8_t message[] = {1,
                         0,
                         2,
                         4,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         DEST_ACCOUNT,
                         BLOCKHASH,
                         1,
                         2,
                         4,
                         1,
                         2,
                         3,
                         0,
                         10,
                         13,
                         42,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         9};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenApprove2
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(ApproveChecked));
    const SplTokenApproveInfo *ap_info = &info.approve;

    assert(ap_info->body.amount == 42);
    assert(ap_info->body.decimals == 9);

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(ap_info->token_account, &token_account);

    const Pubkey delegate = {{DELEGATE}};
    assert_pubkey_equal(ap_info->delegate, &delegate);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(ap_info->sign.single.signer, &owner);

    const Pubkey mint_account = {{PROGRAM_ID_SPL_TOKEN}};
    assert_pubkey_equal(ap_info->mint_account, &mint_account);
}

void test_parse_spl_token_revoke() {
    uint8_t message[] = {1,
                         0,
                         2,
                         3,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         1,
                         2,
                         2,
                         1,
                         0,
                         1,
                         5};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenRevoke
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(Revoke));
    const SplTokenRevokeInfo *re_info = &info.revoke;

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(re_info->token_account, &token_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(re_info->sign.single.signer, &owner);
}

void test_parse_spl_token_set_authority() {
    uint8_t message[] = {1,
                         0,
                         1,
                         3,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         1,
                         2,
                         2,
                         1,
                         0,
                         35,
                         6,
                         2,
                         1,
                         NEW_OWNER};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenSetAuthority
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(SetAuthority));
    const SplTokenSetAuthorityInfo *so_info = &info.set_owner;

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(so_info->account, &token_account);

    assert(so_info->authority_type == Token_AuthorityType_AccountOwner);

    const Pubkey new_owner = {{NEW_OWNER}};
    assert_pubkey_equal(so_info->new_authority, &new_owner);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(so_info->sign.single.signer, &owner);
}

void test_parse_spl_token_mint_to() {
    uint8_t message[] = {1,
                         0,
                         0,
                         3,
                         OWNER_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         TOKEN_ACCOUNT,
                         BLOCKHASH,
                         1,
                         1,
                         3,
                         1,
                         2,
                         0,
                         10,
                         14,
                         42,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         9};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenMintTo2
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(MintToChecked));
    const SplTokenMintToInfo *mt_info = &info.mint_to;

    assert(mt_info->body.amount == 42);
    assert(mt_info->body.decimals == 9);

    const Pubkey mint_account = {{PROGRAM_ID_SPL_TOKEN}};
    assert_pubkey_equal(mt_info->mint_account, &mint_account);

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(mt_info->token_account, &token_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(mt_info->sign.single.signer, &owner);
}

void test_parse_spl_token_burn() {
    uint8_t message[] = {1,
                         0,
                         0,
                         4,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         MINT_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         1,
                         3,
                         3,
                         1,
                         2,
                         0,
                         10,
                         15,
                         42,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         0,
                         9};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenBurn
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(BurnChecked));
    const SplTokenBurnInfo *bn_info = &info.burn;

    assert(bn_info->body.amount == 42);
    assert(bn_info->body.decimals == 9);

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(bn_info->token_account, &token_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(bn_info->sign.single.signer, &owner);

    const Pubkey mint_account = {{MINT_ACCOUNT}};
    assert_pubkey_equal(bn_info->mint_account, &mint_account);
}

void test_parse_spl_token_close_account() {
    uint8_t message[] = {
        0x01,
        0x00,
        0x01,
        0x03,
        OWNER_ACCOUNT,
        TOKEN_ACCOUNT,
        PROGRAM_ID_SPL_TOKEN,
        BLOCKHASH,
        0x01,
        // SplTokenCloseAccount
        0x02,
        0x03,
        0x01,
        0x00,
        0x00,
        0x01,
        0x09,
    };
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenCloseAccount
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(CloseAccount));
    const SplTokenCloseAccountInfo *close_acc = &info.close_account;

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(close_acc->token_account, &token_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(close_acc->dest_account, &owner);

    assert_pubkey_equal(close_acc->sign.single.signer, &owner);
}

void test_parse_spl_token_freeze_account() {
    uint8_t message[] = {1,
                         0,
                         2,
                         4,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         MINT_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         1,
                         3,
                         3,
                         1,
                         2,
                         0,
                         1,
                         10};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenFreezeAccount
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(FreezeAccount));
    const SplTokenFreezeAccountInfo *freeze_account = &info.freeze_account;

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(freeze_account->token_account, &token_account);

    const Pubkey mint_account = {{MINT_ACCOUNT}};
    assert_pubkey_equal(freeze_account->mint_account, &mint_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(freeze_account->sign.single.signer, &owner);
}

void test_parse_spl_token_thaw_account() {
    uint8_t message[] = {1,
                         0,
                         2,
                         4,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         MINT_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         1,
                         3,
                         3,
                         1,
                         2,
                         0,
                         1,
                         11};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenThawAccount
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(ThawAccount));
    const SplTokenThawAccountInfo *thaw_account = &info.thaw_account;

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(thaw_account->token_account, &token_account);

    const Pubkey mint_account = {{MINT_ACCOUNT}};
    assert_pubkey_equal(thaw_account->mint_account, &mint_account);

    const Pubkey owner = {{OWNER_ACCOUNT}};
    assert_pubkey_equal(thaw_account->sign.single.signer, &owner);
}

void test_parse_spl_token_sync_native() {
    uint8_t message[] = {1,
                         0,
                         1,
                         4,
                         OWNER_ACCOUNT,
                         TOKEN_ACCOUNT,
                         PROGRAM_ID_SPL_TOKEN,
                         BLOCKHASH,
                         1,
                         2,
                         1,
                         1,
                         1,
                         17};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);  // SplTokenSyncNative
    assert(instruction_validate(&instruction, &header) == 0);

    SplTokenInfo info;
    bool ignore_instruction_info;
    assert(parse_spl_token_instructions(&instruction, &header, &info, &ignore_instruction_info) ==
           0);
    assert(parser.buffer_length == 0);

    assert(info.kind == SplTokenKind(SyncNative));
    const SplTokenSyncNativeInfo *sync_native = &info.sync_native;

    const Pubkey token_account = {{TOKEN_ACCOUNT}};
    assert_pubkey_equal(sync_native->token_account, &token_account);
}

void test_parse_spl_token_instruction_kind() {
    SplTokenInstructionKind kind;
    uint8_t buf[] = {0};

    buf[0] = 0;
    Parser parser = {buf, ARRAY_LEN(buf)};
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(InitializeMint));

    buf[0] = 1;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(InitializeAccount));

    buf[0] = 2;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(InitializeMultisig));

    buf[0] = 5;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(Revoke));

    buf[0] = 6;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(SetAuthority));

    buf[0] = 9;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(CloseAccount));

    buf[0] = 10;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(FreezeAccount));

    buf[0] = 11;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(ThawAccount));

    buf[0] = 12;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(TransferChecked));

    buf[0] = 13;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(ApproveChecked));

    buf[0] = 14;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(MintToChecked));

    buf[0] = 15;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(BurnChecked));

    buf[0] = 16;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(InitializeAccount2));

    buf[0] = 17;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 0);
    assert(kind == SplTokenKind(SyncNative));

    // First unused enum value fails
    buf[0] = 18;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 1);

    // Largest buffer value fails
    buf[0] = 255;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 1);

    // Deprecated instructions fail
    buf[0] = 3;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 1);

    buf[0] = 4;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 1);

    buf[0] = 7;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 1);

    buf[0] = 8;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_spl_token_instruction_kind(&parser, &kind) == 1);
}

void test_parse_spl_token_sign() {
    const size_t max_signers = Token_MAX_SIGNERS;
    const size_t max_accounts = 1 + max_signers;   // multisig_account + signers
    const size_t accounts_len = max_accounts + 1;  // one too many
    const Pubkey pubkeys[1];
    const MessageHeader header = {
        .pubkeys_header = {0, 0, 0, 1},
        .pubkeys = pubkeys,
    };
    uint8_t accounts[accounts_len];
    explicit_bzero(accounts, accounts_len);
    Instruction ix = {
        .program_id_index = 0,
        .accounts = accounts,
        .accounts_length = 0,
    };
    InstructionAccountsIterator it;
    SplTokenSign sign;

    // too few remaining keys fails
    instruction_accounts_iterator_init(&it, &header, &ix);
    assert(parse_spl_token_sign(&it, &sign) == 1);

    // too many remaining keys fails
    ix.accounts_length = accounts_len;
    instruction_accounts_iterator_init(&it, &header, &ix);
    assert(parse_spl_token_sign(&it, &sign) == 1);

    // one key resolves to single signer
    ix.accounts_length = 1;
    instruction_accounts_iterator_init(&it, &header, &ix);
    assert(parse_spl_token_sign(&it, &sign) == 0);
    assert(sign.kind == SplTokenSignKindSingle);

    // two keys resolves to multi signer
    ix.accounts_length = 2;
    instruction_accounts_iterator_init(&it, &header, &ix);
    assert(parse_spl_token_sign(&it, &sign) == 0);
    assert(sign.kind == SplTokenSignKindMulti);
    assert(sign.multi.signers.count == 1);

    // max keys resolves to multi signer
    ix.accounts_length = max_accounts;
    instruction_accounts_iterator_init(&it, &header, &ix);
    assert(parse_spl_token_sign(&it, &sign) == 0);
    assert(sign.kind == SplTokenSignKindMulti);
    assert(sign.multi.signers.count == max_signers);
}

void test_print_m_of_n_string() {
    char s[M_OF_N_MAX_LEN];

    // n too big fails
    assert(print_m_of_n_string(0, Token_MAX_SIGNERS + 1, s, sizeof(s)) == 1);

    // m > n fails
    assert(print_m_of_n_string(1, 0, s, sizeof(s)) == 1);

    // Buffer too small fails
    assert(print_m_of_n_string(0, 0, s, sizeof(s) - 1) == 1);

    assert(print_m_of_n_string(3, 5, s, sizeof(s)) == 0);
    assert_string_equal(s, "3 of 5");
    assert(print_m_of_n_string(3, Token_MAX_SIGNERS, s, sizeof(s)) == 0);
    assert_string_equal(s, "3 of 11");
    assert(print_m_of_n_string(Token_MAX_SIGNERS, Token_MAX_SIGNERS, s, sizeof(s)) == 0);
    assert_string_equal(s, "11 of 11");
}

int main() {
    test_print_m_of_n_string();
    test_parse_spl_token_sign();
    test_parse_spl_token_instruction_kind();
    test_parse_spl_token_create_token();
    test_parse_spl_token_create_account();
    test_parse_spl_token_create_account2();
    test_parse_spl_token_create_multisig();
    test_parse_spl_token_transfer();
    test_parse_spl_token_approve();
    test_parse_spl_token_revoke();
    test_parse_spl_token_set_authority();
    test_parse_spl_token_mint_to();
    test_parse_spl_token_burn();
    test_parse_spl_token_close_account();
    test_parse_spl_token_freeze_account();
    test_parse_spl_token_thaw_account();

    printf("passed\n");
    return 0;
}
