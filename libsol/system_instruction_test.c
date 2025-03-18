#include "common_byte_strings.h"
#include "instruction.h"
#include "system_instruction.c"
#include "util.h"
#include <stdio.h>
#include <assert.h>

void test_parse_system_transfer_instructions() {
    uint8_t message[] = {1,   0,   1,   3,   171, 88,  202, 32,  185, 160, 182, 116, 130, 185, 73,
                         48,  13,  216, 170, 71,  172, 195, 165, 123, 87,  70,  130, 219, 5,   157,
                         240, 187, 26,  191, 158, 218, 204, 241, 115, 109, 41,  173, 110, 48,  24,
                         113, 210, 213, 163, 78,  1,   112, 146, 114, 235, 220, 96,  185, 184, 85,
                         163, 27,  124, 48,  54,  250, 233, 54,  0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   2,   2,
                         0,   1,   12,  2,   0,   0,   0,   42,  0,   0,   0,   0,   0,   0,   0};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);
    assert(instruction_validate(&instruction, &header) == 0);

    const Pubkey *fee_payer_pubkey = &header.pubkeys[0];
    SystemInfo info;
    assert(parse_system_instructions(&instruction, &header, &info) == 0);
    assert(parser.buffer_length == 0);
    assert(info.transfer.lamports == 42);
    assert(memcmp(fee_payer_pubkey, info.transfer.from, PUBKEY_SIZE) == 0);
}

void test_parse_system_transfer_instructions_with_payer() {
    uint8_t message[] = {2,   0,   1,   3,   204, 241, 115, 109, 41,  173, 110, 48,  24,  113, 210,
                         213, 163, 78,  1,   112, 146, 114, 235, 220, 96,  185, 184, 85,  163, 27,
                         124, 48,  54,  250, 233, 54,  171, 88,  202, 32,  185, 160, 182, 116, 130,
                         185, 73,  48,  13,  216, 170, 71,  172, 195, 165, 123, 87,  70,  130, 219,
                         5,   157, 240, 187, 26,  191, 158, 218, 0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   2,   2,
                         1,   0,   12,  2,   0,   0,   0,   42,  0,   0,   0,   0,   0,   0,   0};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);
    assert(instruction_validate(&instruction, &header) == 0);

    const Pubkey *fee_payer_pubkey = &header.pubkeys[0];
    SystemInfo info;
    assert(parse_system_instructions(&instruction, &header, &info) == 0);

    // "to", not "from", is paying for this transaction.
    assert(memcmp(fee_payer_pubkey, info.transfer.to, PUBKEY_SIZE) == 0);
}

void test_parse_system_advance_nonce_account_instruction() {
    uint8_t message[] = {
        1,   1,   2,  4,   18,  67,  85,  168, 124, 173, 88,  142, 77,  171, 80,  178, 8,   218,
        230, 68,  85, 231, 39,  54,  184, 42,  162, 85,  172, 139, 54,  173, 194, 7,   64,  250,
        1,   1,   1,  1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
        1,   1,   1,  1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   6,   167, 213, 23,
        25,  44,  86, 142, 224, 138, 132, 95,  115, 210, 151, 136, 207, 3,   92,  49,  69,  178,
        26,  179, 68, 216, 6,   46,  169, 64,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   1,  3,   3,   1,   2,   0,   4,   4,   0,   0,   0};
    Parser parser = {message, sizeof(message)};
    PrintConfig print_config;
    print_config.expert_mode = true;
    assert(parse_message_header(&parser, &print_config.header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);
    assert(instruction_validate(&instruction, &print_config.header) == 0);

    enum SystemInstructionKind kind;
    Parser instruction_parser = {instruction.data, instruction.data_length};
    assert(parse_system_instruction_kind(&instruction_parser, &kind) == 0);
    assert(kind == SystemAdvanceNonceAccount);

    SystemAdvanceNonceInfo info;
    assert(parse_system_advance_nonce_account_instruction(&instruction_parser,
                                                          &instruction,
                                                          &print_config.header,
                                                          &info) == 0);
    size_t account_index = instruction.accounts[0];
    size_t authority_index = instruction.accounts[2];
    assert(memcmp(info.account, &print_config.header.pubkeys[account_index], PUBKEY_SIZE) == 0);
    assert(memcmp(info.authority, &print_config.header.pubkeys[authority_index], PUBKEY_SIZE) == 0);

    transaction_summary_reset();
    assert(print_system_advance_nonce_account(&info, &print_config) == 0);
    enum SummaryItemKind kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_kinds;
    transaction_summary_set_fee_payer_pubkey(&print_config.header.pubkeys[0]);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
    assert(num_kinds == 3);

    SystemInfo info2;
    assert(parse_system_instructions(&instruction, &print_config.header, &info2) == 0);
    assert(memcmp(info.account, &print_config.header.pubkeys[account_index], PUBKEY_SIZE) == 0);
    assert(memcmp(info.authority, &print_config.header.pubkeys[authority_index], PUBKEY_SIZE) == 0);

    num_kinds = 0;
    transaction_summary_reset();
    assert(print_system_info(&info2, &print_config) == 0);
    transaction_summary_set_fee_payer_pubkey(&print_config.header.pubkeys[0]);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
    assert(num_kinds == 3);
}

void test_system_create_account_with_seed_instruction() {
#define FROM_PUBKEY BYTES32_BS58_2
#define TO_PUBKEY   BYTES32_BS58_3
#define BASE_PUBKEY BYTES32_BS58_4
    Pubkey pubkeys[3] = {
        {{FROM_PUBKEY}},
        {{TO_PUBKEY}},
    };
    memcpy(&pubkeys[2], &system_program_id, PUBKEY_SIZE);
    Blockhash blockhash = {{BYTES32_BS58_5}};
    MessageHeader header = {
        false,
        0,
        {2, 0, 0, ARRAY_LEN(pubkeys)},
        pubkeys,
        &blockhash,
        1,
    };
    uint8_t accounts[] = {0, 1};
    uint8_t ix_data[] = {/* kind */
                         0x03,
                         0x00,
                         0x00,
                         0x00,
                         /* base */
                         BASE_PUBKEY,
                         /* seed ("seed" as sized string) */
                         0x04,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x73,
                         0x65,
                         0x65,
                         0x64,
                         /* lamports (1) */
                         0x01,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         /* space (16) */
                         0x10,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         /* program id */
                         PROGRAM_ID_STAKE};
    Instruction instruction = {
        2,
        accounts,
        2,
        ix_data,
        sizeof(ix_data),
    };

    /* skip kind */
    Parser parser = {ix_data + sizeof(uint32_t), sizeof(ix_data) - sizeof(uint32_t)};
    SystemInfo info;
    assert(parse_system_create_account_with_seed_instruction(&parser,
                                                             &instruction,
                                                             &header,
                                                             &info.create_account_with_seed) == 0);
    SystemCreateAccountWithSeedInfo *cws_info = &info.create_account_with_seed;
    Pubkey from = {{FROM_PUBKEY}};
    assert(memcmp(&from, cws_info->from, PUBKEY_SIZE) == 0);
    Pubkey to = {{TO_PUBKEY}};
    assert(memcmp(&to, cws_info->to, PUBKEY_SIZE) == 0);
    Pubkey base = {{BASE_PUBKEY}};
    assert(memcmp(&base, cws_info->base, PUBKEY_SIZE) == 0);
    SizedString *seed = &cws_info->seed;
    assert(strncmp("seed", seed->string, seed->length) == 0);
    assert(cws_info->lamports == 1);

    /* check routing */
    assert(parse_system_instructions(&instruction, &header, &info) == 0);
}

void test_process_system_transfer() {
    uint8_t message[] = {1,   0,   1,   3,   171, 88,  202, 32,  185, 160, 182, 116, 130, 185, 73,
                         48,  13,  216, 170, 71,  172, 195, 165, 123, 87,  70,  130, 219, 5,   157,
                         240, 187, 26,  191, 158, 218, 204, 241, 115, 109, 41,  173, 110, 48,  24,
                         113, 210, 213, 163, 78,  1,   112, 146, 114, 235, 220, 96,  185, 184, 85,
                         163, 27,  124, 48,  54,  250, 233, 54,  0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
                         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   2,   2,
                         0,   1,   12,  2,   0,   0,   0,   42,  0,   0,   0,   0,   0,   0,   0};
    Parser parser = {message, sizeof(message)};
    PrintConfig print_config;
    print_config.expert_mode = true;
    assert(parse_message_header(&parser, &print_config.header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);
    assert(instruction_validate(&instruction, &print_config.header) == 0);

    SystemInfo info;
    assert(parse_system_instructions(&instruction, &print_config.header, &info) == 0);

    transaction_summary_reset();
    assert(print_system_info(&info, &print_config) == 0);

    enum SummaryItemKind kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_kinds;
    transaction_summary_set_fee_payer_pubkey(&print_config.header.pubkeys[0]);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
    assert(num_kinds == 4);

    transaction_summary_display_item(0, DisplayFlagNone);
    assert_string_equal(G_transaction_summary_text, "0.000000042 SOL");
}

void test_parse_system_instruction_kind() {
    enum SystemInstructionKind kind;
    uint8_t buf[] = {0, 0, 0, 0};
    Parser parser = {buf, ARRAY_LEN(buf)};
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemCreateAccount);

    buf[0] = 1;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemAssign);

    buf[0] = 2;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemTransfer);

    buf[0] = 3;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemCreateAccountWithSeed);

    buf[0] = 4;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemAdvanceNonceAccount);

    buf[0] = 5;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemWithdrawNonceAccount);

    buf[0] = 6;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemInitializeNonceAccount);

    buf[0] = 7;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemAuthorizeNonceAccount);

    buf[0] = 8;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemAllocate);

    buf[0] = 9;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemAllocateWithSeed);

    buf[0] = 10;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 0);
    assert(kind == SystemAssignWithSeed);

    // Fail the first unused enum value to be sure this test gets updated
    buf[0] = 11;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 1);

    // Should always fail
    buf[0] = 255;
    buf[1] = 255;
    buf[2] = 255;
    buf[3] = 255;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_system_instruction_kind(&parser, &kind) == 1);
}

int main() {
    test_parse_system_transfer_instructions();
    test_parse_system_transfer_instructions_with_payer();
    test_parse_system_advance_nonce_account_instruction();
    test_system_create_account_with_seed_instruction();
    test_process_system_transfer();

    printf("passed\n");
    return 0;
}
