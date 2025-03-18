#include "common_byte_strings.h"
#include "instruction.h"
#include "stake_instruction.c"
#include <stdio.h>
#include <assert.h>

void test_parse_delegate_stake_instructions() {
    uint8_t message[] = {
        1,   1,   5,   7,   204, 241, 115, 109, 41,  173, 110, 48,  24,  113, 210, 213, 163, 78,
        1,   112, 146, 114, 235, 220, 96,  185, 184, 85,  163, 27,  124, 48,  54,  250, 233, 54,
        171, 88,  202, 32,  185, 160, 182, 116, 130, 185, 73,  48,  13,  216, 170, 71,  172, 195,
        165, 123, 87,  70,  130, 219, 5,   157, 240, 187, 26,  191, 158, 218, 0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   6,   167, 213, 23,  24,  199, 116, 201,
        40,  86,  99,  152, 105, 29,  94,  182, 139, 94,  184, 163, 155, 75,  109, 92,  115, 85,
        91,  33,  0,   0,   0,   0,   6,   167, 213, 23,  25,  53,  132, 208, 254, 237, 155, 179,
        67,  29,  19,  32,  107, 229, 68,  40,  27,  87,  184, 86,  108, 197, 55,  95,  244, 0,
        0,   0,   6,   161, 216, 23,  165, 2,   5,   11,  104, 7,   145, 230, 206, 109, 184, 142,
        30,  91,  113, 80,  246, 31,  198, 121, 10,  78,  180, 209, 0,   0,   0,   0,   6,   161,
        216, 23,  145, 55,  84,  42,  152, 52,  55,  189, 254, 42,  122, 178, 85,  127, 83,  92,
        138, 120, 114, 43,  104, 164, 157, 192, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   1,   6,   6,   1,   2,   3,   4,   5,   0,   4,
        2,   0,   0,   0};
    Parser parser = {message, sizeof(message)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);
    assert(instruction_validate(&instruction, &header) == 0);

    StakeInfo info;
    assert(parse_stake_instructions(&instruction, &header, &info) == 0);
    assert(parser.buffer_length == 0);
}

void test_parse_stake_initialize_instruction() {
#define ACCOUNT_PUBKEY_BYTES      BYTES32_BS58_2
#define ST_AUTHORITY_PUBKEY_BYTES BYTES32_BS58_3
#define WD_AUTHORITY_PUBKEY_BYTES BYTES32_BS58_4
#define CUSTODIAN_PUBKEY_BYTES    BYTES32_BS58_5
    Pubkey pubkeys[3] = {
        {{ACCOUNT_PUBKEY_BYTES}},
        {{SYSVAR_RENT}},
    };
    memcpy(&pubkeys[2], &stake_program_id, PUBKEY_SIZE);
    Blockhash blockhash = {{BYTES32_BS58_6}};
    MessageHeader header = {false, 0, {1, 0, 1, ARRAY_LEN(pubkeys)}, pubkeys, &blockhash, 1};
    uint8_t accounts[] = {0, 1};
    uint8_t ix_data[] = {/* kind */
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         /* authorized */
                         /* staker */
                         ST_AUTHORITY_PUBKEY_BYTES,
                         /* withdrawer */
                         WD_AUTHORITY_PUBKEY_BYTES,
                         /* lockup */
                         /* unix_timestamp (16) */
                         0x10,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         /* epoch (1) */
                         0x01,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         0x00,
                         /* custodian */
                         CUSTODIAN_PUBKEY_BYTES};
    Instruction instruction = {
        2,
        accounts,
        2,
        ix_data,
        sizeof(ix_data),
    };

    /* kind is already parsed when we get here, skip it */
    Parser parser = {ix_data + sizeof(uint32_t), sizeof(ix_data) - sizeof(uint32_t)};
    StakeInfo info;
    assert(parse_stake_initialize_instruction(&parser, &instruction, &header, &info.initialize) ==
           0);
    StakeInitializeInfo *sii = &info.initialize;
    assert(sii->lockup.unix_timestamp == 16);
    assert(sii->lockup.epoch == 1);
    Pubkey new_account = {{ACCOUNT_PUBKEY_BYTES}};
    assert(memcmp(&new_account, sii->account, PUBKEY_SIZE) == 0);
    Pubkey stake_authority = {{ST_AUTHORITY_PUBKEY_BYTES}};
    assert(memcmp(&stake_authority, sii->stake_authority, PUBKEY_SIZE) == 0);
    Pubkey withdraw_authority = {{WD_AUTHORITY_PUBKEY_BYTES}};
    assert(memcmp(&withdraw_authority, sii->withdraw_authority, PUBKEY_SIZE) == 0);

    Pubkey custodian = {{CUSTODIAN_PUBKEY_BYTES}};
    assert(memcmp(&custodian, sii->lockup.custodian, PUBKEY_SIZE) == 0);

    /* Check that we're routed properly */
    assert(parse_stake_instructions(&instruction, &header, &info) == 0);
}

void test_parse_stake_instruction_kind() {
    enum StakeInstructionKind kind;
    uint8_t buf[] = {0, 0, 0, 0};
    Parser parser = {buf, ARRAY_LEN(buf)};
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeInitialize);

    buf[0] = 1;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeAuthorize);

    buf[0] = 2;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeDelegate);

    buf[0] = 3;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeSplit);

    buf[0] = 4;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeWithdraw);

    buf[0] = 5;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeDeactivate);

    buf[0] = 6;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeSetLockup);

    buf[0] = 7;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeMerge);

    buf[0] = 8;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeAuthorizeWithSeed);

    buf[0] = 9;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeInitializeChecked);

    buf[0] = 10;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeAuthorizeChecked);

    buf[0] = 11;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeAuthorizeCheckedWithSeed);

    buf[0] = 12;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 0);
    assert(kind == StakeSetLockupChecked);

    // Fail the first unused enum value to be sure this test gets updated
    buf[0] = 13;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 1);

    // Should always fail
    buf[0] = 255;
    buf[1] = 255;
    buf[2] = 255;
    buf[3] = 255;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_instruction_kind(&parser, &kind) == 1);
}

void test_parse_stake_authorize_enum() {
    enum StakeAuthorize authorize;
    uint8_t buf[] = {0, 0, 0, 0};
    Parser parser = {buf, ARRAY_LEN(buf)};
    assert(parse_stake_authorize(&parser, &authorize) == 0);
    assert(authorize == StakeAuthorizeStaker);

    buf[0] = 1;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_authorize(&parser, &authorize) == 0);
    assert(authorize == StakeAuthorizeWithdrawer);

    // Fail the first unused enum value to be sure this test gets updated
    buf[0] = 2;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_authorize(&parser, &authorize) == 1);

    // Should always fail
    buf[0] = 255;
    buf[1] = 255;
    buf[2] = 255;
    buf[3] = 255;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_stake_authorize(&parser, &authorize) == 1);
}

void test_parse_stake_lockup_args() {
    uint8_t buf[] = {
        // All None
        0x00,
        0x00,
        0x00,
        // Just timestamp
        0x01,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Just epoch
        0x00,
        0x01,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Just custodian
        0x00,
        0x00,
        0x01,
        BYTES32_BS58_1,
        // All Some
        0x01,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x05,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        BYTES32_BS58_2,
    };
    Parser parser = {buf, sizeof(buf)};
    StakeLockup lockup;

    assert(parse_stake_lockupargs(&parser, &lockup, true) == 0);
    assert(lockup.present == StakeLockupHasNone);

    assert(parse_stake_lockupargs(&parser, &lockup, true) == 0);
    assert(lockup.present == StakeLockupHasTimestamp);
    assert(lockup.unix_timestamp == 2);

    assert(parse_stake_lockupargs(&parser, &lockup, true) == 0);
    assert(lockup.present == StakeLockupHasEpoch);
    assert(lockup.epoch == 3);

    assert(parse_stake_lockupargs(&parser, &lockup, true) == 0);
    assert(lockup.present == StakeLockupHasCustodian);
    Pubkey custodian1 = {{BYTES32_BS58_1}};
    assert(memcmp(lockup.custodian, &custodian1, sizeof(Pubkey)) == 0);

    assert(parse_stake_lockupargs(&parser, &lockup, true) == 0);
    assert(lockup.present == StakeLockupHasAll);
    assert(lockup.unix_timestamp == 4);
    assert(lockup.epoch == 5);
    Pubkey custodian2 = {{BYTES32_BS58_2}};
    assert(memcmp(lockup.custodian, &custodian2, sizeof(Pubkey)) == 0);
}

void test_parse_stake_lockup_checked_args() {
    uint8_t buf[] = {
        // All None
        0x00,
        0x00,
        0x00,
        // Just timestamp
        0x01,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Just epoch
        0x00,
        0x01,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // All Some
        0x01,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x05,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };
    Parser parser = {buf, sizeof(buf)};
    StakeLockup lockup;

    assert(parse_stake_lockupargs(&parser, &lockup, false) == 0);
    assert(lockup.present == StakeLockupHasNone);

    assert(parse_stake_lockupargs(&parser, &lockup, false) == 0);
    assert(lockup.present == StakeLockupHasTimestamp);
    assert(lockup.unix_timestamp == 2);

    assert(parse_stake_lockupargs(&parser, &lockup, false) == 0);
    assert(lockup.present == StakeLockupHasEpoch);
    assert(lockup.epoch == 3);

    assert(parse_stake_lockupargs(&parser, &lockup, false) == 0);
    assert(lockup.present == (StakeLockupHasTimestamp | StakeLockupHasEpoch));
    assert(lockup.unix_timestamp == 4);
    assert(lockup.epoch == 5);
}

int main() {
    test_parse_delegate_stake_instructions();
    test_parse_stake_initialize_instruction();
    test_parse_stake_instruction_kind();
    test_parse_stake_authorize_enum();
    test_parse_stake_lockup_args();

    printf("passed\n");
    return 0;
}
