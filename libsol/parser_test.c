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

// Build a versioned (v0) transaction with `num_static` static keys, zero
// instructions, and a two-table ALT lookup section:
//   Table A (key 0xA0): writable [10, 11], readonly [20]
//   Table B (key 0xB0): writable [12],     readonly [21, 22]
// Writable-loaded accounts (A/10, A/11, B/12) come before readonly-loaded
// (A/20, B/21, B/22) in the resolved key ordering. Returns the total length.
static size_t build_v0_tx_with_alt(uint8_t *buf, uint8_t num_static) {
    size_t cursor = 0;
    buf[cursor++] = 0x80;        // version prefix: versioned, version 0
    buf[cursor++] = 1;           // num_required_signatures
    buf[cursor++] = 0;           // num_readonly_signed
    buf[cursor++] = 0;           // num_readonly_unsigned
    buf[cursor++] = num_static;  // pubkeys_length (compact-u16, < 128)
    for (uint8_t k = 0; k < num_static; k++) {
        memset(buf + cursor, 0x10 + k, PUBKEY_SIZE);
        cursor += PUBKEY_SIZE;
    }
    memset(buf + cursor, 0xEE, BLOCKHASH_SIZE);  // blockhash
    cursor += BLOCKHASH_SIZE;
    buf[cursor++] = 0;  // instructions_length

    buf[cursor++] = 2;  // num_tables
    // Table A
    memset(buf + cursor, 0xA0, PUBKEY_SIZE);
    cursor += PUBKEY_SIZE;
    buf[cursor++] = 2;   // writable count
    buf[cursor++] = 10;  // writable index
    buf[cursor++] = 11;  // writable index
    buf[cursor++] = 1;   // readonly count
    buf[cursor++] = 20;  // readonly index
    // Table B
    memset(buf + cursor, 0xB0, PUBKEY_SIZE);
    cursor += PUBKEY_SIZE;
    buf[cursor++] = 1;   // writable count
    buf[cursor++] = 12;  // writable index
    buf[cursor++] = 2;   // readonly count
    buf[cursor++] = 21;  // readonly index
    buf[cursor++] = 22;  // readonly index
    return cursor;
}

// resolve_alt_loaded_index: writable-loaded accounts resolve first, across
// tables in order.
void test_resolve_alt_writable() {
    uint8_t buf[256];
    size_t len = build_v0_tx_with_alt(buf, 3);
    const uint8_t *alt = NULL;
    uint8_t entry = 0;

    // global 3 -> Table A, writable entry 10
    assert(resolve_alt_loaded_index(buf, len, 3, &alt, &entry) == 0);
    assert(alt[0] == 0xA0 && entry == 10);
    // global 4 -> Table A, writable entry 11
    assert(resolve_alt_loaded_index(buf, len, 4, &alt, &entry) == 0);
    assert(alt[0] == 0xA0 && entry == 11);
    // global 5 -> Table B, writable entry 12
    assert(resolve_alt_loaded_index(buf, len, 5, &alt, &entry) == 0);
    assert(alt[0] == 0xB0 && entry == 12);
}

// resolve_alt_loaded_index: readonly-loaded accounts follow all writable ones.
void test_resolve_alt_readonly() {
    uint8_t buf[256];
    size_t len = build_v0_tx_with_alt(buf, 3);
    const uint8_t *alt = NULL;
    uint8_t entry = 0;

    // global 6 -> Table A, readonly entry 20
    assert(resolve_alt_loaded_index(buf, len, 6, &alt, &entry) == 0);
    assert(alt[0] == 0xA0 && entry == 20);
    // global 7 -> Table B, readonly entry 21
    assert(resolve_alt_loaded_index(buf, len, 7, &alt, &entry) == 0);
    assert(alt[0] == 0xB0 && entry == 21);
    // global 8 -> Table B, readonly entry 22
    assert(resolve_alt_loaded_index(buf, len, 8, &alt, &entry) == 0);
    assert(alt[0] == 0xB0 && entry == 22);
}

// resolve_alt_loaded_index: a static index (below pubkeys_length) is not an
// ALT-loaded account.
void test_resolve_alt_static_index_rejected() {
    uint8_t buf[256];
    size_t len = build_v0_tx_with_alt(buf, 3);
    const uint8_t *alt = NULL;
    uint8_t entry = 0;
    assert(resolve_alt_loaded_index(buf, len, 2, &alt, &entry) != 0);
}

// resolve_alt_loaded_index: an index beyond every loaded entry is out of range.
void test_resolve_alt_out_of_range_rejected() {
    uint8_t buf[256];
    size_t len = build_v0_tx_with_alt(buf, 3);
    const uint8_t *alt = NULL;
    uint8_t entry = 0;
    // 3 static + 3 writable + 3 readonly = 9 total; global 9 is out of range.
    assert(resolve_alt_loaded_index(buf, len, 9, &alt, &entry) != 0);
}

// resolve_alt_loaded_index: a legacy (non-versioned) transaction has no ALT.
void test_resolve_alt_legacy_rejected() {
    uint8_t buf[MSG_HEADER_BUF_SIZE(3)];
    build_message_header_buf(buf, 1, 0, 0, 3);  // legacy header, no version prefix
    const uint8_t *alt = NULL;
    uint8_t entry = 0;
    assert(resolve_alt_loaded_index(buf, sizeof(buf), 3, &alt, &entry) != 0);
}

// message_alt_writable_count: the two-table fixture loads 3 writable accounts.
void test_alt_writable_count_versioned() {
    uint8_t buf[256];
    size_t len = build_v0_tx_with_alt(buf, 3);
    size_t count = SIZE_MAX;
    assert(message_alt_writable_count(buf, len, &count) == 0);
    assert(count == 3);
}

// message_alt_writable_count: a legacy transaction loads nothing through an ALT.
void test_alt_writable_count_legacy() {
    uint8_t buf[MSG_HEADER_BUF_SIZE(3)];
    build_message_header_buf(buf, 1, 0, 0, 3);
    size_t count = SIZE_MAX;
    assert(message_alt_writable_count(buf, sizeof(buf), &count) == 0);
    assert(count == 0);
}

// message_alt_writable_count: a truncated ALT section is an error, not a zero count.
void test_alt_writable_count_truncated() {
    uint8_t buf[256];
    size_t len = build_v0_tx_with_alt(buf, 3);
    size_t count = SIZE_MAX;
    // Cut the buffer mid-way through the second table's index lists.
    assert(message_alt_writable_count(buf, len - 4, &count) != 0);
}

// pubkey_index_is_writable: static signer / non-signer blocks each split into a
// writable then a readonly run.
void test_pubkey_index_is_writable_static() {
    // 5 static keys: 2 signers (1 readonly) + 3 unsigned (1 readonly)
    // index 0: writable signer, 1: readonly signer,
    // index 2,3: writable unsigned, 4: readonly unsigned
    uint8_t buf[MSG_HEADER_BUF_SIZE(5)];
    build_message_header_buf(buf, 2, 1, 1, 5);
    Parser parser = {buf, sizeof(buf)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    assert(pubkey_index_is_writable(&header, 0, 0) == true);
    assert(pubkey_index_is_writable(&header, 0, 1) == false);
    assert(pubkey_index_is_writable(&header, 0, 2) == true);
    assert(pubkey_index_is_writable(&header, 0, 3) == true);
    assert(pubkey_index_is_writable(&header, 0, 4) == false);
}

// pubkey_index_is_writable: every signer is writable when none is readonly.
void test_pubkey_index_is_writable_all_signers_writable() {
    uint8_t buf[MSG_HEADER_BUF_SIZE(3)];
    build_message_header_buf(buf, 2, 0, 0, 3);
    Parser parser = {buf, sizeof(buf)};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    assert(pubkey_index_is_writable(&header, 0, 0) == true);
    assert(pubkey_index_is_writable(&header, 0, 1) == true);
    assert(pubkey_index_is_writable(&header, 0, 2) == true);
}

// pubkey_index_is_writable: loaded accounts split at the total writable count, and
// an index past every loaded entry is not writable.
void test_pubkey_index_is_writable_alt_loaded() {
    uint8_t buf[256];
    size_t len = build_v0_tx_with_alt(buf, 3);
    Parser parser = {buf, len};
    MessageHeader header;
    assert(parse_message_header(&parser, &header) == 0);

    size_t alt_writable_count = 0;
    assert(message_alt_writable_count(buf, len, &alt_writable_count) == 0);

    // 3 static keys, then 3 writable-loaded (global 3..5), then readonly-loaded.
    assert(pubkey_index_is_writable(&header, alt_writable_count, 3) == true);
    assert(pubkey_index_is_writable(&header, alt_writable_count, 5) == true);
    assert(pubkey_index_is_writable(&header, alt_writable_count, 6) == false);
    assert(pubkey_index_is_writable(&header, alt_writable_count, 8) == false);
    // Beyond every loaded entry: still reported as not writable.
    assert(pubkey_index_is_writable(&header, alt_writable_count, 9) == false);
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
    RUN_TEST(test_resolve_alt_writable);
    RUN_TEST(test_resolve_alt_readonly);
    RUN_TEST(test_resolve_alt_static_index_rejected);
    RUN_TEST(test_resolve_alt_out_of_range_rejected);
    RUN_TEST(test_resolve_alt_legacy_rejected);
    RUN_TEST(test_alt_writable_count_versioned);
    RUN_TEST(test_alt_writable_count_legacy);
    RUN_TEST(test_alt_writable_count_truncated);
    RUN_TEST(test_pubkey_index_is_writable_static);
    RUN_TEST(test_pubkey_index_is_writable_all_signers_writable);
    RUN_TEST(test_pubkey_index_is_writable_alt_loaded);

    printf("passed\n");
    return 0;
}
