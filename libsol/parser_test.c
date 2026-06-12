#include "instruction.h"
#include "parser.c"
#include "sol/printer.h"
#include "test_utils.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void test_parse_u8() {
    uint8_t message[] = {1, 2};
    Parser parser = {message, sizeof(message)};
    uint8_t value;
    assert(parse_u8(&parser, &value) == 0);
    assert(parser.buffer_length == 1);
    assert(parser.buffer == message + 1);
    assert(value == 1);
}

void test_parse_u8_too_short() {
    uint8_t message[] = {42};
    Parser parser = {message, sizeof(message)};
    uint8_t value;
    assert(parse_u8(&parser, &value) == 0);
    assert(parse_u8(&parser, &value) == 1);
}

void test_parse_u16() {
    uint8_t message[] = {0, 0, 255, 255};
    Parser parser = {message, sizeof(message)};
    uint16_t value;
    assert(parse_u16(&parser, &value) == 0);
    assert(value == 0);
    assert(parse_u16(&parser, &value) == 0);
    assert(value == UINT16_MAX);
    assert(parser_is_empty(&parser));
}

void test_parse_u32() {
    uint8_t message[] = {0, 0, 0, 0, 255, 255, 255, 255};
    Parser parser = {message, sizeof(message)};
    uint32_t value;
    assert(parse_u32(&parser, &value) == 0);
    assert(value == 0);
    assert(parse_u32(&parser, &value) == 0);
    assert(value == UINT32_MAX);
    assert(parser_is_empty(&parser));
}

void test_parse_u64() {
    uint8_t message[] = {0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255};
    Parser parser = {message, sizeof(message)};
    uint64_t value;
    assert(parse_u64(&parser, &value) == 0);
    assert(value == 0);
    assert(parse_u64(&parser, &value) == 0);
    assert(value == UINT64_MAX);
    assert(parser_is_empty(&parser));
}

void test_parse_i64() {
    uint8_t buffer[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
    Parser parser = {buffer, sizeof(buffer)};
    int64_t value;
    assert(parse_i64(&parser, &value) == 0);
    assert(value == INT64_MIN);
    assert(parse_i64(&parser, &value) == 0);
    assert(value == 0);
    assert(parse_i64(&parser, &value) == 0);
    assert(value == INT64_MAX);
}

void test_parse_length() {
    uint8_t message[] = {1, 2};
    Parser parser = {message, sizeof(message)};
    size_t value;
    assert(parse_length(&parser, &value) == 0);
    assert(parser.buffer_length == 1);
    assert(parser.buffer == message + 1);
    assert(value == 1);
}

void test_parser_option() {
    uint8_t message[] = {0x00, 0x01, 0x02, 0xff};
    Parser parser = {message, sizeof(message)};
    enum Option value;

    assert(parse_option(&parser, &value) == 0);
    assert(value == OptionNone);
    assert(parse_option(&parser, &value) == 0);
    assert(value == OptionSome);
    // First bad value
    assert(parse_option(&parser, &value) == 1);
    // Last bad value
    assert(parse_option(&parser, &value) == 1);
    // Parser empty
    assert(parse_option(&parser, &value) == 1);
}

void test_parse_sized_string() {
    SizedString value;
    uint8_t buffer[] = {/* "test" */
                        0x04,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x74,
                        0x65,
                        0x73,
                        0x74,
                        /* length too long */
                        0xff,
                        0xff,
                        0xff,
                        0xff,
                        0xff,
                        0xff,
                        0xff,
                        0xff,
                        /* remaining buffer too short for length */
                        0x10,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        /* buffer to short to read length */
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00};
    Parser parser = {buffer, sizeof(buffer)};

    assert(parse_sized_string(&parser, &value) == 0);
    assert(value.length == 4);
    assert(strncmp("test", value.string, value.length) == 0);

    assert(parse_sized_string(&parser, &value) == 1);
    assert(parse_sized_string(&parser, &value) == 1);
    assert(parse_sized_string(&parser, &value) == 1);
}

void test_parse_pubkey() {
    const Pubkey *value;
    const char *expected_string = "11111111111111111111111111111111";
    char value_string[BASE58_PUBKEY_LENGTH];
    uint8_t buffer[] = {/* valid */
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        /* too short */
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00};
    Parser parser = {buffer, sizeof(buffer)};
    assert(parse_pubkey(&parser, &value) == 0);
    encode_base58(value, sizeof(Pubkey), value_string, sizeof(value_string));
    assert_string_equal(expected_string, value_string);

    assert(parse_pubkey(&parser, &value) == 1);
}

void test_parse_length_two_bytes() {
    uint8_t message[] = {128, 1};
    Parser parser = {message, sizeof(message)};
    size_t value;
    assert(parse_length(&parser, &value) == 0);
    assert(parser_is_empty(&parser));
    assert(parser.buffer == message + 2);
    assert(value == 128);
}

void test_parse_pubkeys_header() {
    uint8_t message[] = {1, 2, 3, 4};
    Parser parser = {message, sizeof(message)};
    PubkeysHeader header;
    assert(parse_pubkeys_header(&parser, &header) == 0);
    assert(parser_is_empty(&parser));
    assert(parser.buffer == message + 4);
    assert(header.pubkeys_length == 4);
}

void test_parse_pubkeys() {
    uint8_t message[PUBKEY_SIZE + 4] = {1, 2, 3, 1, 42};
    Parser parser = {message, sizeof(message)};
    PubkeysHeader header;
    const Pubkey *pubkeys;
    assert(parse_pubkeys(&parser, &header, &pubkeys) == 0);
    assert(parser_is_empty(&parser));
    assert(parser.buffer == message + PUBKEY_SIZE + 4);
    assert(pubkeys->data[0] == 42);
}

void test_parse_pubkeys_too_short() {
    uint8_t message[] = {1, 2, 3, 1};
    Parser parser = {message, sizeof(message)};
    PubkeysHeader header;
    const Pubkey *pubkeys;
    assert(parse_pubkeys(&parser, &header, &pubkeys) == 1);
}

void test_parse_hash() {
    uint8_t message[HASH_SIZE] = {42};
    Parser parser = {message, sizeof(message)};
    const Hash *hash;
    assert(parse_hash(&parser, &hash) == 0);
    assert(parser_is_empty(&parser));
    assert(parser.buffer == message + HASH_SIZE);
    assert(hash->data[0] == 42);
}

void test_parse_hash_too_short() {
    uint8_t message[31];  // <--- Too short!
    Parser parser = {message, sizeof(message)};
    const Hash *hash;
    assert(parse_hash(&parser, &hash) == 1);
}

void test_parse_data() {
    uint8_t message[] = {1, 2};
    Parser parser = {message, sizeof(message)};
    const uint8_t *data;
    size_t data_length;
    assert(parse_data(&parser, &data, &data_length) == 0);
    assert(parser_is_empty(&parser));
    assert(parser.buffer == message + 2);
    assert(data[0] == 2);
}

void test_parse_data_too_short() {
    uint8_t message[] = {1};  // <--- Too short!
    Parser parser = {message, sizeof(message)};
    const uint8_t *data;
    size_t data_length;
    assert(parse_data(&parser, &data, &data_length) == 1);
}

void test_parse_instruction() {
    uint8_t message[] = {0, 2, 33, 34, 1, 36};
    Parser parser = {message, sizeof(message)};
    Instruction instruction;
    assert(parse_instruction(&parser, &instruction) == 0);
    MessageHeader header = {false, 0, {0, 0, 0, 35}, NULL, NULL, 1};
    assert(instruction_validate(&instruction, &header) == 0);
    assert(parser_is_empty(&parser));
    assert(instruction.accounts[0] == 33);
    assert(instruction.data[0] == 36);
}

void test_parser_is_empty() {
    uint8_t buf[1] = {0};
    Parser nonempty = {buf, 1};
    assert(!parser_is_empty(&nonempty));
    Parser empty = {NULL, 0};
    assert(parser_is_empty(&empty));
}

// Helper: build a minimal legacy message header buffer (single-byte shortvec lengths only)
// Layout: num_required_signatures(1) | num_readonly_signed(1) | num_readonly_unsigned(1) |
//         pubkeys_length(1) | pubkeys(PUBKEY_SIZE*n) | blockhash(BLOCKHASH_SIZE) |
//         instructions_length(1)
#define MSG_HEADER_BUF_SIZE(n) (4 + PUBKEY_SIZE * (n) + BLOCKHASH_SIZE + 1)

static void build_message_header_buf(uint8_t *buf,
                                     uint8_t num_required_signatures,
                                     uint8_t num_readonly_signed,
                                     uint8_t num_readonly_unsigned,
                                     uint8_t pubkeys_length) {
    memset(buf, 0, MSG_HEADER_BUF_SIZE(pubkeys_length));
    buf[0] = num_required_signatures;
    buf[1] = num_readonly_signed;
    buf[2] = num_readonly_unsigned;
    buf[3] = pubkeys_length;
}

// Verify pubkeys_length is bounded to uint16_t range
void test_parse_pubkeys_header_too_many_pubkeys() {
    // shortvec encoding of 65536: 0x80 0x80 0x04
    uint8_t message[] = {1, 0, 0, 0x80, 0x80, 0x04};
    Parser parser = {message, sizeof(message)};
    PubkeysHeader header;
    assert(parse_pubkeys_header(&parser, &header) == 1);
}

// Verify parse_message_header accepts a valid header
void test_parse_message_header_valid() {
    // 3 pubkeys, 2 required sigs, 1 readonly signed, 1 readonly unsigned
    uint8_t buf[MSG_HEADER_BUF_SIZE(3)];
    build_message_header_buf(buf, 2, 1, 1, 3);
    Parser parser = {buf, sizeof(buf)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);
}

// Verify num_required_signatures cannot exceed pubkeys_length
void test_parse_message_header_too_many_signatures() {
    // 2 pubkeys but 3 required signatures
    uint8_t buf[MSG_HEADER_BUF_SIZE(2)];
    build_message_header_buf(buf, 3, 0, 0, 2);
    Parser parser = {buf, sizeof(buf)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 1);
}

// Verify num_readonly_signed_accounts cannot exceed num_required_signatures
void test_parse_message_header_too_many_readonly_signed() {
    // 3 pubkeys, 2 required, but 3 readonly signed
    uint8_t buf[MSG_HEADER_BUF_SIZE(3)];
    build_message_header_buf(buf, 2, 3, 0, 3);
    Parser parser = {buf, sizeof(buf)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 1);
}

// Verify num_readonly_unsigned_accounts cannot exceed (pubkeys_length - num_required_signatures)
void test_parse_message_header_too_many_readonly_unsigned() {
    // 4 pubkeys, 2 required -> 2 unsigned slots, but claim 3 readonly unsigned
    uint8_t buf[MSG_HEADER_BUF_SIZE(4)];
    build_message_header_buf(buf, 2, 0, 3, 4);
    Parser parser = {buf, sizeof(buf)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 1);
}

// skip_address_table_lookups: zero tables
void test_skip_alt_zero_tables() {
    uint8_t buf[] = {0};  // num_tables = 0
    Parser parser = {buf, sizeof(buf)};
    assert(skip_address_table_lookups(&parser) == 0);
    assert(parser_is_empty(&parser));
}

// skip_address_table_lookups: single table with writable and readonly indexes
void test_skip_alt_single_table() {
    uint8_t buf[32 + 6] = {0};
    // num_tables = 1
    buf[0] = 1;
    // account_key: 32 bytes (zeroed)
    // writable_indexes: length=2, indexes=[0, 1]
    buf[33] = 2;
    buf[34] = 0;
    buf[35] = 1;
    // readonly_indexes: length=1, index=[2]
    buf[36] = 1;
    buf[37] = 2;
    // Total: 1 + 32 + 1 + 2 + 1 + 1 = 38
    Parser parser = {buf, 38};
    assert(skip_address_table_lookups(&parser) == 0);
    assert(parser_is_empty(&parser));
}

// skip_address_table_lookups: two tables
void test_skip_alt_two_tables() {
    // Table 1: 32-byte key, 0 writable, 0 readonly
    // Table 2: 32-byte key, 1 writable, 0 readonly
    /* clang-format off */
    uint8_t buf[] = {
        2,  // num_tables
        // Table 1: 32-byte key (all zeros)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  // writable count = 0
        0,  // readonly count = 0
        // Table 2: 32-byte key (all 0x01)
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1,     // writable count = 1
        0x05,  // writable index
        0,     // readonly count = 0
    };
    /* clang-format on */
    Parser parser = {buf, sizeof(buf)};
    assert(skip_address_table_lookups(&parser) == 0);
    assert(parser_is_empty(&parser));
}

// skip_address_table_lookups: trailing data preserved after skip
void test_skip_alt_with_trailing_data() {
    /* clang-format off */
    uint8_t buf[] = {
        1,  // num_tables = 1
        // 32-byte key
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  // writable count = 0
        0,  // readonly count = 0
        0xAB, 0xCD,  // trailing data
    };
    /* clang-format on */
    Parser parser = {buf, sizeof(buf)};
    assert(skip_address_table_lookups(&parser) == 0);
    assert(parser.buffer_length == 2);
    assert(parser.buffer[0] == 0xAB);
    assert(parser.buffer[1] == 0xCD);
}

// skip_address_table_lookups: empty buffer fails
void test_skip_alt_empty_buffer() {
    Parser parser = {NULL, 0};
    assert(skip_address_table_lookups(&parser) == 1);
}

// skip_address_table_lookups: truncated account key fails
void test_skip_alt_truncated_key() {
    uint8_t buf[10] = {0};
    buf[0] = 1;  // num_tables = 1, but only 9 bytes remain (need 32 for key)
    Parser parser = {buf, sizeof(buf)};
    assert(skip_address_table_lookups(&parser) == 1);
}

// skip_address_table_lookups: writable count exceeds remaining buffer
void test_skip_alt_truncated_writable() {
    // 1 table, 32-byte key, writable_count=5 but no data for the 5 indexes
    uint8_t buf[34] = {0};
    buf[0] = 1;   // num_tables = 1
    buf[33] = 5;  // writable_count = 5, only 0 bytes remain
    Parser parser = {buf, sizeof(buf)};
    assert(skip_address_table_lookups(&parser) == 1);
}

// skip_address_table_lookups: readonly count exceeds remaining buffer
void test_skip_alt_truncated_readonly() {
    // 1 table, 32-byte key, writable_count=0, readonly_count=3 but no data
    uint8_t buf[35] = {0};
    buf[0] = 1;   // num_tables = 1
    buf[33] = 0;  // writable_count = 0
    buf[34] = 3;  // readonly_count = 3, only 0 bytes remain
    Parser parser = {buf, sizeof(buf)};
    assert(skip_address_table_lookups(&parser) == 1);
}

int main() {
    RUN_TEST(test_parse_u8);
    RUN_TEST(test_parse_u8_too_short);
    RUN_TEST(test_parse_u16);
    RUN_TEST(test_parse_u32);
    RUN_TEST(test_parse_u64);
    RUN_TEST(test_parse_i64);
    RUN_TEST(test_parse_length);
    RUN_TEST(test_parse_length_two_bytes);
    RUN_TEST(test_parse_sized_string);
    RUN_TEST(test_parse_pubkey);
    RUN_TEST(test_parse_pubkeys_header);
    RUN_TEST(test_parse_pubkeys_header_too_many_pubkeys);
    RUN_TEST(test_parse_pubkeys);
    RUN_TEST(test_parse_pubkeys_too_short);
    RUN_TEST(test_parse_hash);
    RUN_TEST(test_parse_hash_too_short);
    RUN_TEST(test_parse_data);
    RUN_TEST(test_parse_data_too_short);
    RUN_TEST(test_parse_instruction);
    RUN_TEST(test_parser_is_empty);
    RUN_TEST(test_parse_message_header_valid);
    RUN_TEST(test_parse_message_header_too_many_signatures);
    RUN_TEST(test_parse_message_header_too_many_readonly_signed);
    RUN_TEST(test_parse_message_header_too_many_readonly_unsigned);
    RUN_TEST(test_skip_alt_zero_tables);
    RUN_TEST(test_skip_alt_single_table);
    RUN_TEST(test_skip_alt_two_tables);
    RUN_TEST(test_skip_alt_with_trailing_data);
    RUN_TEST(test_skip_alt_empty_buffer);
    RUN_TEST(test_skip_alt_truncated_key);
    RUN_TEST(test_skip_alt_truncated_writable);
    RUN_TEST(test_skip_alt_truncated_readonly);

    printf("passed\n");
    return 0;
}
