#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define PUBKEY_SIZE    32
#define HASH_SIZE      32
#define BLOCKHASH_SIZE HASH_SIZE

typedef struct Parser {
    const uint8_t *buffer;
    size_t buffer_length;
} Parser;

enum Option {
    OptionNone,
    OptionSome,
};

typedef struct SizedString {
    uint64_t length;
    // TODO: This can technically contain UTF-8. Need to figure out a
    // nano-s-compatible strategy for dealing with non-ASCII chars...
    const char *string;
} SizedString;

typedef struct Pubkey {
    uint8_t data[PUBKEY_SIZE];
} Pubkey;

typedef struct Hash {
    uint8_t data[HASH_SIZE];
} Hash;
typedef struct Hash Blockhash;

typedef struct Instruction {
    uint8_t program_id_index;
    const uint8_t *accounts;
    size_t accounts_length;
    const uint8_t *data;
    size_t data_length;
} Instruction;

typedef struct PubkeysHeader {
    uint8_t num_required_signatures;
    uint8_t num_readonly_signed_accounts;
    uint8_t num_readonly_unsigned_accounts;
    size_t pubkeys_length;
} PubkeysHeader;

typedef struct MessageHeader {
    bool versioned;
    uint8_t version;
    PubkeysHeader pubkeys_header;
    const Pubkey *pubkeys;
    const Blockhash *blockhash;
    size_t instructions_length;
} MessageHeader;

//@TODO move to offchain message sign .h
#define OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH 32
typedef struct OffchainMessageApplicationDomain {
    uint8_t data[OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH];
} OffchainMessageApplicationDomain;

typedef struct OffchainMessageHeader {
    uint8_t version;
    const OffchainMessageApplicationDomain *application_domain;
    uint8_t format;
    size_t signers_length;
    const Pubkey *signers;
    uint16_t length;
} OffchainMessageHeader;

static inline int parser_is_empty(Parser *parser) {
    return parser->buffer_length == 0;
}

int parse_u8(Parser *parser, uint8_t *value);

int parse_u32(Parser *parser, uint32_t *value);

int parse_u64(Parser *parser, uint64_t *value);

int parse_i64(Parser *parser, int64_t *value);

int parse_length(Parser *parser, size_t *value);

int parse_option(Parser *parser, enum Option *value);

int parse_sized_string(Parser *parser, SizedString *string);

int parse_pubkey(Parser *parser, const Pubkey **pubkey);

int parse_pubkeys_header(Parser *parser, PubkeysHeader *header);

int parse_pubkeys(Parser *parser, PubkeysHeader *header, const Pubkey **pubkeys);

int parse_blockhash(Parser *parser, const Hash **hash);
#define parse_blockhash parse_hash

int parse_message_header(Parser *parser, MessageHeader *header);

int parse_offchain_message_header(Parser *parser, OffchainMessageHeader *header);

int parse_instruction(Parser *parser, Instruction *instruction);

// FIXME: I don't belong here
static inline bool pubkeys_equal(const Pubkey *pubkey1, const Pubkey *pubkey2) {
    return memcmp(pubkey1, pubkey2, PUBKEY_SIZE) == 0;
}
