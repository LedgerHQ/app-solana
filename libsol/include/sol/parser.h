#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "sol/offchain_message_signing.h"
#include "sol/pubkey.h"

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
    uint16_t pubkeys_length;
} PubkeysHeader;

typedef struct MessageHeader {
    bool versioned;
    uint8_t version;
    PubkeysHeader pubkeys_header;
    const Pubkey *pubkeys;
    const Blockhash *blockhash;
    size_t instructions_length;
} MessageHeader;

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

int skip_address_table_lookups(Parser *parser);
