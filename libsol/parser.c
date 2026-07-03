#include "sol/parser.h"
#include "util.h"

static int check_buffer_length(Parser *parser, size_t num) {
    return parser->buffer_length < num ? 1 : 0;
}

static void advance(Parser *parser, size_t num) {
    parser->buffer += num;
    parser->buffer_length -= num;
}

int parse_u8(Parser *parser, uint8_t *value) {
    BAIL_IF(check_buffer_length(parser, 1));
    *value = *parser->buffer;
    advance(parser, 1);
    return 0;
}

static int parse_u16(Parser *parser, uint16_t *value) {
    uint8_t lower, upper;
    BAIL_IF(parse_u8(parser, &lower));
    BAIL_IF(parse_u8(parser, &upper));
    *value = lower + ((uint16_t) upper << 8);
    return 0;
}

int parse_u32(Parser *parser, uint32_t *value) {
    uint16_t lower, upper;
    BAIL_IF(parse_u16(parser, &lower));
    BAIL_IF(parse_u16(parser, &upper));
    *value = lower + ((uint32_t) upper << 16);
    return 0;
}

int parse_u64(Parser *parser, uint64_t *value) {
    BAIL_IF(check_buffer_length(parser, 8));
    uint32_t lower, upper;
    BAIL_IF(parse_u32(parser, &lower));
    BAIL_IF(parse_u32(parser, &upper));
    *value = lower + ((uint64_t) upper << 32);
    return 0;
}

int parse_i64(Parser *parser, int64_t *value) {
    uint64_t *as_u64 = (uint64_t *) value;
    return parse_u64(parser, as_u64);
}

int parse_length(Parser *parser, size_t *value) {
    uint8_t value_u8;
    BAIL_IF(parse_u8(parser, &value_u8));
    *value = value_u8 & 0x7f;

    if (value_u8 & 0x80) {
        BAIL_IF(parse_u8(parser, &value_u8));
        *value = ((value_u8 & 0x7f) << 7) | *value;
        if (value_u8 & 0x80) {
            BAIL_IF(parse_u8(parser, &value_u8));
            *value = ((value_u8 & 0x7f) << 14) | *value;
        }
    }
    return 0;
}

int parse_option(Parser *parser, enum Option *value) {
    uint8_t maybe_option;
    BAIL_IF(parse_u8(parser, &maybe_option));
    switch (maybe_option) {
        case OptionNone:
        case OptionSome:
            *value = (enum Option) maybe_option;
            return 0;
        default:
            break;
    }
    return 1;
}

int parse_sized_string(Parser *parser, SizedString *string) {
    BAIL_IF(parse_u64(parser, &string->length));
    BAIL_IF(string->length > SIZE_MAX);
    size_t len = (size_t) string->length;
    BAIL_IF(check_buffer_length(parser, len));
    string->string = (const char *) parser->buffer;
    advance(parser, len);
    return 0;
}

int parse_pubkey(Parser *parser, const Pubkey **pubkey) {
    BAIL_IF(check_buffer_length(parser, PUBKEY_SIZE));
    *pubkey = (const Pubkey *) parser->buffer;
    advance(parser, PUBKEY_SIZE);
    return 0;
}

int parse_pubkeys_header(Parser *parser, PubkeysHeader *header) {
    BAIL_IF(parse_u8(parser, &header->num_required_signatures));
    BAIL_IF(parse_u8(parser, &header->num_readonly_signed_accounts));
    BAIL_IF(parse_u8(parser, &header->num_readonly_unsigned_accounts));
    size_t pubkeys_length;
    BAIL_IF(parse_length(parser, &pubkeys_length));
    BAIL_IF(pubkeys_length > UINT16_MAX);
    header->pubkeys_length = (uint16_t) pubkeys_length;
    return 0;
}

int parse_pubkeys(Parser *parser, PubkeysHeader *header, const Pubkey **pubkeys) {
    BAIL_IF(parse_pubkeys_header(parser, header));
    size_t pubkeys_size = header->pubkeys_length * PUBKEY_SIZE;
    BAIL_IF(check_buffer_length(parser, pubkeys_size));
    *pubkeys = (const Pubkey *) parser->buffer;
    advance(parser, pubkeys_size);
    return 0;
}

int parse_pubkeys_with_len(Parser *parser, size_t num_pubkeys, const Pubkey **pubkeys) {
    size_t pubkeys_size = num_pubkeys * PUBKEY_SIZE;
    BAIL_IF(check_buffer_length(parser, pubkeys_size));
    *pubkeys = (const Pubkey *) parser->buffer;
    advance(parser, pubkeys_size);
    return 0;
}

int parse_hash(Parser *parser, const Hash **hash) {
    BAIL_IF(check_buffer_length(parser, HASH_SIZE));
    *hash = (const Hash *) parser->buffer;
    advance(parser, HASH_SIZE);
    return 0;
}

int parse_version(Parser *parser, MessageHeader *header) {
    BAIL_IF(check_buffer_length(parser, 1));
    const uint8_t version = *parser->buffer;
    if (version & 0x80) {
        header->versioned = true;
        header->version = version & 0x7f;
        advance(parser, 1);
    } else {
        header->versioned = false;
        header->version = 0;
    }
    return 0;
}

int parse_offchain_message_application_domain(Parser *parser,
                                              const OffchainMessageApplicationDomain **app_domain) {
    BAIL_IF(check_buffer_length(parser, OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH));
    *app_domain = (const OffchainMessageApplicationDomain *) parser->buffer;
    advance(parser, OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH);
    return 0;
}

int parse_message_header(Parser *parser, MessageHeader *header) {
    BAIL_IF(parse_version(parser, header));
    BAIL_IF(parse_pubkeys_header(parser, &header->pubkeys_header));
    BAIL_IF(header->pubkeys_header.num_required_signatures > header->pubkeys_header.pubkeys_length);
    BAIL_IF(header->pubkeys_header.num_readonly_signed_accounts >
            header->pubkeys_header.num_required_signatures);
    BAIL_IF(
        header->pubkeys_header.num_readonly_unsigned_accounts >
        (header->pubkeys_header.pubkeys_length - header->pubkeys_header.num_required_signatures));
    BAIL_IF(
        parse_pubkeys_with_len(parser, header->pubkeys_header.pubkeys_length, &header->pubkeys));
    BAIL_IF(parse_blockhash(parser, &header->blockhash));
    BAIL_IF(parse_length(parser, &header->instructions_length));
    return 0;
}

int parse_offchain_message_header(Parser *parser, OffchainMessageHeader *header) {
    const size_t domain_len = OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH;
    int res = check_offchain_signing_domain(parser->buffer, parser->buffer_length);
    if (res != 0) {
        return res;
    }
    advance(parser, domain_len);  // Signing domain - 16 bytes

    BAIL_IF(parse_u8(parser, &header->version));  // Header version

    if (header->version == 0) {
        // V0: parse application domain and format
        BAIL_IF(parse_offchain_message_application_domain(parser, &header->application_domain));
        BAIL_IF(parse_u8(parser, &header->format));  // Message format
    } else {
        // V1+: no application domain or format
        header->application_domain = NULL;
        header->format = 0;  // unused for V1
    }

    uint8_t signers_length = 0;
    BAIL_IF(parse_u8(parser, &signers_length));  // Signer count
    header->signers_length = signers_length;
    BAIL_IF(parse_pubkeys_with_len(parser, header->signers_length, &header->signers));

    // V1+: enforce strict ascending lexicographic order on signers (implies uniqueness)
    if (header->version >= 1) {
        for (size_t i = 1; i < header->signers_length; i++) {
            if (memcmp(&header->signers[i - 1], &header->signers[i], PUBKEY_SIZE) >= 0) {
                return -1;
            }
        }
    }

    if (header->version == 0) {
        uint16_t msg_length = 0;
        BAIL_IF(parse_u16(parser, &msg_length));  // V0: explicit message length
        header->length = msg_length;
    } else {
        // V1+: no length prefix, content is the trailing bytes
        header->length = parser->buffer_length;
    }
    return 0;
}

static int parse_data(Parser *parser, const uint8_t **data, size_t *data_length) {
    BAIL_IF(parse_length(parser, data_length));
    BAIL_IF(check_buffer_length(parser, *data_length));
    *data = parser->buffer;
    advance(parser, *data_length);
    return 0;
}

int skip_address_table_lookups(Parser *parser) {
    size_t num_tables;
    BAIL_IF(parse_length(parser, &num_tables));
    for (size_t i = 0; i < num_tables; i++) {
        // account_key: 32 bytes
        BAIL_IF(check_buffer_length(parser, PUBKEY_SIZE));
        advance(parser, PUBKEY_SIZE);
        // writable_indexes: compact-u16 length + N bytes
        size_t num_writable;
        BAIL_IF(parse_length(parser, &num_writable));
        BAIL_IF(check_buffer_length(parser, num_writable));
        advance(parser, num_writable);
        // readonly_indexes: compact-u16 length + N bytes
        size_t num_readonly;
        BAIL_IF(parse_length(parser, &num_readonly));
        BAIL_IF(check_buffer_length(parser, num_readonly));
        advance(parser, num_readonly);
    }
    return 0;
}

int parse_instruction(Parser *parser, Instruction *instruction) {
    BAIL_IF(parse_u8(parser, &instruction->program_id_index));
    BAIL_IF(parse_data(parser, &instruction->accounts, &instruction->accounts_length));
    BAIL_IF(parse_data(parser, &instruction->data, &instruction->data_length));
    return 0;
}
