#include "sol/message_raw.h"
#include "sol/parser.h"
#include "sol/printer.h"
#include "message_raw.c"
#include "util.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* clang-format off */

// index 0: signer + writable, index 1: writable non-signer, index 2: readonly
// non-signer (the all-zero pubkey doubles as the "program" -> base58 "1"*32).
static const Pubkey g_accounts[] = {
    {{1}},
    {{2}},
    {{0}},
};
static const Blockhash g_blockhash = {{0}};
static const Hash g_hash = {{0xAB}};

#define BASE58_ALL_ZERO_PUBKEY "11111111111111111111111111111111"

static MessageHeader make_header(size_t instructions_length) {
    MessageHeader header = {
        .versioned = false,
        .version = 0,
        .pubkeys_header = {1, 0, 1, 3},  // sig=1, ro_signed=0, ro_unsigned=1, len=3
        .pubkeys = g_accounts,
        .blockhash = &g_blockhash,
        .instructions_length = instructions_length,
    };
    return header;
}

static int render(size_t index, char *title, char *value) {
    return raw_message_render_pair(index, title, TITLE_SIZE, value, RAW_MESSAGE_VALUE_BUF_SIZE);
}

// Single System-transfer-shaped instruction:
//   program_id_index=2, accounts=[0,1], data=12 bytes
void test_raw_single_instruction() {
    MessageHeader header = make_header(1);
    uint8_t body[] = {2, 2, 0, 1, 12, 2, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0};

    size_t pairs = 0;
    assert(raw_message_init(body, ARRAY_LEN(body), &header, &g_hash, false, &pairs) == 0);
    // 3 leading + (1 program + 2 accounts + 1 data) = 7
    assert(pairs == 7);

    char title[TITLE_SIZE];
    char value[RAW_MESSAGE_VALUE_BUF_SIZE];

    // The identity of what is being signed leads: hash, then fee payer.
    assert(render(0, title, value) == 0);
    assert(strcmp(title, "Message Hash") == 0);
    assert(strlen(value) > 0);

    assert(render(1, title, value) == 0);
    assert(strcmp(title, "Fee payer") == 0);
    // Fee payer is account 0, shown without flags.
    char expected_fee_payer[BASE58_PUBKEY_LENGTH];
    assert(encode_base58(&g_accounts[0], PUBKEY_SIZE, expected_fee_payer, sizeof(expected_fee_payer)) == 0);
    assert(strcmp(value, expected_fee_payer) == 0);

    assert(render(2, title, value) == 0);
    assert(strcmp(title, "Instructions") == 0);
    assert(strcmp(value, "1") == 0);

    assert(render(3, title, value) == 0);
    assert(strcmp(title, "Ix 1 program") == 0);
    assert(strcmp(value, BASE58_ALL_ZERO_PUBKEY) == 0);

    assert(render(4, title, value) == 0);
    assert(strcmp(title, "Ix 1 account 1/2") == 0);
    assert(strstr(value, "(signer, writable)") != NULL);

    assert(render(5, title, value) == 0);
    assert(strcmp(title, "Ix 1 account 2/2") == 0);
    assert(strstr(value, "(writable)") != NULL);
    assert(strstr(value, "signer") == NULL);

    assert(render(6, title, value) == 0);
    assert(strcmp(title, "Ix 1 data 1/1") == 0);
    assert(strcmp(value, "020000002A00000000000000") == 0);  // uppercase hex

    // Out of range index must fail rather than read past the end.
    assert(render(7, title, value) == -1);
}

// With short pubkeys, values are truncated (xxxxxxx..xxxxxxx) and flags
// abbreviated, so pairs are short enough to pack more per page.
void test_raw_short_pubkeys() {
    MessageHeader header = make_header(1);
    uint8_t body[] = {2, 2, 0, 1, 12, 2, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0};

    size_t pairs = 0;
    assert(raw_message_init(body, ARRAY_LEN(body), &header, &g_hash, true, &pairs) == 0);
    assert(pairs == 7);

    char title[TITLE_SIZE];
    char value[RAW_MESSAGE_VALUE_BUF_SIZE];

    // Account 1 (signer + writable): truncated key + abbreviated flags.
    assert(render(4, title, value) == 0);
    assert(strcmp(title, "Ix 1 account 1/2") == 0);
    assert(strstr(value, "..") != NULL);        // truncated
    assert(strstr(value, "(s,w)") != NULL);     // abbreviated flags
    assert(strstr(value, "signer") == NULL);
    assert(strlen(value) < 30);                 // much shorter than a full key

    // Account 2 (writable non-signer) -> "(w)".
    assert(render(5, title, value) == 0);
    assert(strstr(value, "(w)") != NULL);

    // Program: truncated, no flags.
    assert(render(3, title, value) == 0);
    assert(strcmp(title, "Ix 1 program") == 0);
    assert(strstr(value, "..") != NULL);
}

// Account index past the static key list (address lookup table) and empty data.
void test_raw_lookup_account_and_empty_data() {
    MessageHeader header = make_header(1);
    uint8_t body[] = {2, 1, 250, 0};  // program=2, accounts=[250], data_length=0

    size_t pairs = 0;
    assert(raw_message_init(body, ARRAY_LEN(body), &header, &g_hash, false, &pairs) == 0);
    // 3 leading + (1 program + 1 account + 1 empty-data) = 6
    assert(pairs == 6);

    char title[TITLE_SIZE];
    char value[RAW_MESSAGE_VALUE_BUF_SIZE];

    assert(render(4, title, value) == 0);
    assert(strcmp(title, "Ix 1 account 1/1") == 0);
    assert(strcmp(value, "lookup table account #250") == 0);

    assert(render(5, title, value) == 0);
    assert(strcmp(title, "Ix 1 data") == 0);
    assert(strcmp(value, "(empty)") == 0);
}

// Data longer than one chunk is split across multiple hex pairs.
// Chunks are RAW_DATA_BYTES_PER_PAIR (64) bytes each.
void test_raw_data_chunking() {
    MessageHeader header = make_header(1);
    uint8_t body[3 + 100];
    body[0] = 2;    // program_id_index
    body[1] = 0;    // accounts_length
    body[2] = 100;  // data_length (varint, < 128)
    for (uint8_t i = 0; i < 100; i++) {
        body[3 + i] = i;
    }

    size_t pairs = 0;
    assert(raw_message_init(body, sizeof(body), &header, &g_hash, false, &pairs) == 0);
    // 3 leading + (1 program + 0 accounts + 2 data) = 6
    assert(pairs == 6);

    char title[TITLE_SIZE];
    char value[RAW_MESSAGE_VALUE_BUF_SIZE];

    assert(render(4, title, value) == 0);
    assert(strcmp(title, "Ix 1 data 1/2") == 0);
    assert(strlen(value) == 128);  // 64 bytes * 2 hex chars
    assert(strncmp(value, "000102030405", 12) == 0);

    assert(render(5, title, value) == 0);
    assert(strcmp(title, "Ix 1 data 2/2") == 0);
    assert(strlen(value) == 72);  // remaining 36 bytes * 2 hex chars
    assert(strncmp(value, "404142", 6) == 0);  // byte 64 = 0x40
    assert(strcmp(value + strlen(value) - 2, "63") == 0);  // byte 99 = 0x63
}

// Two instructions exercise the flat-index -> instruction walk.
void test_raw_multiple_instructions() {
    MessageHeader header = make_header(2);
    uint8_t body[] = {
        2, 1, 0, 1, 7,         // ix0: program=2, accounts=[0], data=[7]
        2, 2, 0, 1, 0,         // ix1: program=2, accounts=[0,1], data=[]
    };

    size_t pairs = 0;
    assert(raw_message_init(body, ARRAY_LEN(body), &header, &g_hash, false, &pairs) == 0);
    // 3 leading + (1+1+1) + (1+2+1) = 10
    assert(pairs == 10);

    char title[TITLE_SIZE];
    char value[RAW_MESSAGE_VALUE_BUF_SIZE];

    // Instruction region starts at index 3 (after hash, fee payer, count).
    // ix0 program at 3, account at 4, data at 5
    assert(render(5, title, value) == 0);
    assert(strcmp(title, "Ix 1 data 1/1") == 0);
    assert(strcmp(value, "07") == 0);

    // ix1 program at 6
    assert(render(6, title, value) == 0);
    assert(strcmp(title, "Ix 2 program") == 0);

    // ix1 second account at 8
    assert(render(8, title, value) == 0);
    assert(strcmp(title, "Ix 2 account 2/2") == 0);

    // ix1 empty data at 9
    assert(render(9, title, value) == 0);
    assert(strcmp(title, "Ix 2 data") == 0);
    assert(strcmp(value, "(empty)") == 0);
}

// A read-only, non-signer account gets no flag suffix at all (only signer and
// writable are notable enough to call out).
void test_raw_readonly_account_no_flag() {
    MessageHeader header = make_header(1);
    // program=2, accounts=[2,1], data=[]. Account 2 is the read-only non-signer.
    uint8_t body[] = {2, 2, 2, 1, 0};

    size_t pairs = 0;
    assert(raw_message_init(body, ARRAY_LEN(body), &header, &g_hash, false, &pairs) == 0);

    char title[TITLE_SIZE];
    char value[RAW_MESSAGE_VALUE_BUF_SIZE];

    // Account 1 here is global index 2 (read-only non-signer): no parenthesised flag.
    assert(render(4, title, value) == 0);
    assert(strcmp(title, "Ix 1 account 1/2") == 0);
    assert(strcmp(value, BASE58_ALL_ZERO_PUBKEY) == 0);  // bare key, no " (...)" suffix
    assert(strchr(value, '(') == NULL);

    // Account 2 here is global index 1 (writable non-signer): "(writable)".
    assert(render(5, title, value) == 0);
    assert(strcmp(title, "Ix 1 account 2/2") == 0);
    assert(strstr(value, "(writable)") != NULL);
}

// A versioned (v0) message whose instruction references two lookup-table
// accounts: the table loads the first as writable and the second as read-only.
// The writable one is flagged; the read-only one is not.
void test_raw_versioned_lookup_writable() {
    MessageHeader header = make_header(1);
    header.versioned = true;
    header.version = 0;
    // ix: program=2 (static), accounts=[3, 4] (both from the lookup table), data=[].
    // Then the address-table-lookups section: one table with one writable index
    // and one read-only index, so global index 3 is writable and 4 is read-only.
    uint8_t body[] = {
        2, 2, 3, 4, 0,  // ix: program=2, accounts=[3,4], data_length=0
        1,              // 1 address table lookup
        // table account key (32 bytes)
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55,
        1, 5,  // writable_indexes = [5] -> one writable account (global index 3)
        1, 7,  // readonly_indexes = [7] -> one read-only account (global index 4)
    };

    size_t pairs = 0;
    assert(raw_message_init(body, ARRAY_LEN(body), &header, &g_hash, false, &pairs) == 0);
    // 3 leading + (1 program + 2 accounts + 1 empty-data) = 7
    assert(pairs == 7);

    char title[TITLE_SIZE];
    char value[RAW_MESSAGE_VALUE_BUF_SIZE];

    // Global index 3: first lookup-table account, loaded writable -> flagged.
    assert(render(4, title, value) == 0);
    assert(strcmp(title, "Ix 1 account 1/2") == 0);
    assert(strcmp(value, "lookup table account #3 (writable)") == 0);

    // Global index 4: read-only lookup-table account -> no flag.
    assert(render(5, title, value) == 0);
    assert(strcmp(title, "Ix 1 account 2/2") == 0);
    assert(strcmp(value, "lookup table account #4") == 0);
}

void test_raw_rejects_empty() {
    MessageHeader header = make_header(0);
    size_t pairs = 0;
    assert(raw_message_init(NULL, 0, &header, &g_hash, false, &pairs) == -1);
}

int main() {
    RUN_TEST(test_raw_single_instruction);
    RUN_TEST(test_raw_short_pubkeys);
    RUN_TEST(test_raw_lookup_account_and_empty_data);
    RUN_TEST(test_raw_data_chunking);
    RUN_TEST(test_raw_multiple_instructions);
    RUN_TEST(test_raw_readonly_account_no_flag);
    RUN_TEST(test_raw_versioned_lookup_writable);
    RUN_TEST(test_raw_rejects_empty);
    printf("passed\n");
    return 0;
}
