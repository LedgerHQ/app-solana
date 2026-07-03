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

// Parse one address-table-lookup entry, advancing the parser past it and
// exposing borrowed pointers to its ALT account key and its writable/readonly
// index lists. Every out-pointer references bytes inside the parser buffer.
static int parse_alt_table(Parser *parser,
                           const uint8_t **alt_address,
                           const uint8_t **writable_indexes,
                           size_t *num_writable,
                           const uint8_t **readonly_indexes,
                           size_t *num_readonly) {
    // ALT account key: the 32-byte address of the on-chain lookup table.
    BAIL_IF(check_buffer_length(parser, PUBKEY_SIZE));
    *alt_address = parser->buffer;
    advance(parser, PUBKEY_SIZE);

    // Writable index list: compact-u16 count followed by that many 1-byte entries.
    BAIL_IF(parse_length(parser, num_writable));
    BAIL_IF(check_buffer_length(parser, *num_writable));
    *writable_indexes = parser->buffer;
    advance(parser, *num_writable);

    // Readonly index list: same layout, immediately after the writable list.
    BAIL_IF(parse_length(parser, num_readonly));
    BAIL_IF(check_buffer_length(parser, *num_readonly));
    *readonly_indexes = parser->buffer;
    advance(parser, *num_readonly);

    PRINTF("parse_alt_table: alt_address=%.*H num_writable=%d num_readonly=%d\n",
           PUBKEY_SIZE,
           *alt_address,
           *num_writable,
           *num_readonly);
    return 0;
}

int resolve_alt_loaded_index(const uint8_t *transaction,
                             size_t transaction_size,
                             uint16_t global_index,
                             const uint8_t **out_alt_address,
                             uint8_t *out_entry_index) {
    Parser parser = {transaction, transaction_size};
    MessageHeader header;
    BAIL_IF(parse_message_header(&parser, &header));
    PRINTF("resolve_alt_loaded_index: global_index=%d pubkeys_length=%d versioned=%d\n",
           global_index,
           header.pubkeys_header.pubkeys_length,
           header.versioned);

    // ALT-loaded accounts only exist in versioned (v0) transactions, and only
    // for global indices beyond the statically listed keys.
    BAIL_IF(!header.versioned);
    BAIL_IF(global_index < header.pubkeys_header.pubkeys_length);

    // Walk past every instruction so the parser lands on the address-table-lookup
    // section, which is the last part of a v0 message body.
    for (size_t i = 0; i < header.instructions_length; i++) {
        Instruction instruction;
        BAIL_IF(parse_instruction(&parser, &instruction));
    }
    PRINTF("resolve_alt_loaded_index: reached ALT section, remaining_bytes=%d\n",
           parser.buffer_length);

    // The resolved key ordering places every writable loaded account (across
    // tables in order, each table's writable indices in order) before every
    // readonly loaded account. A readonly position must therefore be offset
    // past the total writable count, which the first scan computes.
    size_t loaded_index = global_index - header.pubkeys_header.pubkeys_length;
    // Capture the ALT section bounds so both scans below start from a fresh parser
    // over the exact same bytes, without mutating the walk parser.
    const uint8_t *section_start = parser.buffer;
    size_t section_length = parser.buffer_length;

    // First scan: sum the writable indices across all tables to learn the boundary
    // between the writable block and the readonly block in the resolved ordering.
    size_t total_writable = 0;
    Parser count_scan = {section_start, section_length};
    size_t table_count;
    BAIL_IF(parse_length(&count_scan, &table_count));
    PRINTF("resolve_alt_loaded_index: table_count=%d\n", table_count);
    for (size_t i = 0; i < table_count; i++) {
        const uint8_t *alt_address;
        const uint8_t *writable_indexes;
        size_t num_writable;
        const uint8_t *readonly_indexes;
        size_t num_readonly;
        BAIL_IF(parse_alt_table(&count_scan,
                                &alt_address,
                                &writable_indexes,
                                &num_writable,
                                &readonly_indexes,
                                &num_readonly));
        total_writable += num_writable;
    }

    bool want_writable = (loaded_index < total_writable);
    size_t target;
    if (want_writable) {
        target = loaded_index;
    } else {
        target = loaded_index - total_writable;
    }
    PRINTF("resolve_alt_loaded_index: loaded_index=%d total_writable=%d want_writable=%d target=%d\n",
           loaded_index,
           total_writable,
           want_writable,
           target);

    // Second scan: replay the same tables and consume entries from the selected
    // list (writable or readonly) until the target position lands inside a table.
    Parser scan = {section_start, section_length};
    BAIL_IF(parse_length(&scan, &table_count));
    for (size_t i = 0; i < table_count; i++) {
        const uint8_t *alt_address;
        const uint8_t *writable_indexes;
        size_t num_writable;
        const uint8_t *readonly_indexes;
        size_t num_readonly;
        BAIL_IF(parse_alt_table(&scan,
                                &alt_address,
                                &writable_indexes,
                                &num_writable,
                                &readonly_indexes,
                                &num_readonly));
        // Select the index list this table contributes to the chosen block.
        const uint8_t *entry_list;
        size_t entry_count;
        if (want_writable) {
            entry_list = writable_indexes;
            entry_count = num_writable;
        } else {
            entry_list = readonly_indexes;
            entry_count = num_readonly;
        }
        // Target falls in this table: the entry byte is the ALT slot to resolve.
        if (target < entry_count) {
            *out_alt_address = alt_address;
            *out_entry_index = entry_list[target];
            PRINTF("resolve_alt_loaded_index: hit table %d, entry_index=%d\n", i, entry_list[target]);
            return 0;
        }
        target -= entry_count;
    }

    PRINTF("resolve_alt_loaded_index: global index %u beyond loaded range\n", global_index);
    return -1;
}


int parse_instruction(Parser *parser, Instruction *instruction) {
    BAIL_IF(parse_u8(parser, &instruction->program_id_index));
    BAIL_IF(parse_data(parser, &instruction->accounts, &instruction->accounts_length));
    BAIL_IF(parse_data(parser, &instruction->data, &instruction->data_length));
    return 0;
}
