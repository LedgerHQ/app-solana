#include "vote_instruction.c"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>

void test_parse_vote_instruction_kind() {
    enum VoteInstructionKind kind;
    uint8_t buf[] = {0, 0, 0, 0};
    Parser parser = {buf, ARRAY_LEN(buf)};
    assert(parse_vote_instruction_kind(&parser, &kind) == 0);
    assert(kind == VoteInitialize);

    buf[0] = 1;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 0);
    assert(kind == VoteAuthorize);

    buf[0] = 2;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 0);
    assert(kind == VoteVote);

    buf[0] = 3;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 0);
    assert(kind == VoteWithdraw);

    buf[0] = 4;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 0);
    assert(kind == VoteUpdateValidatorId);

    buf[0] = 5;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 0);
    assert(kind == VoteUpdateCommission);

    buf[0] = 6;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 0);
    assert(kind == VoteSwitchVote);

    buf[0] = 7;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 0);
    assert(kind == VoteAuthorizeChecked);

    // Fail the first unused enum value to be sure this test gets updated
    buf[0] = 8;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 1);

    // Should always fail
    buf[0] = 255;
    buf[1] = 255;
    buf[2] = 255;
    buf[3] = 255;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_instruction_kind(&parser, &kind) == 1);
}

void test_parse_vote_authorize_enum() {
    enum VoteAuthorize authorize;
    uint8_t buf[] = {0, 0, 0, 0};
    Parser parser = {buf, ARRAY_LEN(buf)};
    assert(parse_vote_authorize(&parser, &authorize) == 0);
    assert(authorize == VoteAuthorizeVoter);

    buf[0] = 1;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_authorize(&parser, &authorize) == 0);
    assert(authorize == VoteAuthorizeWithdrawer);

    // Fail the first unused enum value to be sure this test gets updated
    buf[0] = 2;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_authorize(&parser, &authorize) == 1);

    // Should always fail
    buf[0] = 255;
    buf[1] = 255;
    buf[2] = 255;
    buf[3] = 255;
    parser.buffer = buf;
    parser.buffer_length = ARRAY_LEN(buf);
    assert(parse_vote_authorize(&parser, &authorize) == 1);
}

int main() {
    RUN_TEST(test_parse_vote_instruction_kind);
    RUN_TEST(test_parse_vote_authorize_enum);

    printf("passed\n");
    return 0;
}
