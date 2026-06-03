#include "os.h"
#include "sol/message_raw.h"
#include "sol/parser.h"
#include "sol/printer.h"
#include "util.h"
#include <string.h>

// Number of instruction-data bytes shown per display pair. A pair holds the
// hex encoding (2 chars/byte) plus a NUL, so 2*64+1 = 129 <= the value buffer.
#define RAW_DATA_BYTES_PER_PAIR 64

// The NBGL review callback indexes pairs with a uint8_t, so at most 255 pairs
// can ever be displayed. Messages that would need more are not enumerable here.
#define RAW_MAX_PAIRS 255

typedef struct RawMessageContext {
    const uint8_t *body;
    size_t body_length;
    const Pubkey *pubkeys;
    uint16_t pubkeys_length;
    uint8_t num_required_signatures;
    uint8_t num_readonly_signed;
    uint8_t num_readonly_unsigned;
    size_t instructions_length;
    const Hash *message_hash;
    size_t total_pairs;
    bool short_pubkeys;  // truncate pubkeys to xxxxxxx..xxxxxxx (Short keys setting)
} RawMessageContext;

static RawMessageContext G_raw;

// Number of display pairs needed for an instruction's data field.
static size_t data_pairs_for(size_t data_length) {
    if (data_length == 0) {
        return 1;  // a single "(empty)" pair
    }
    size_t pairs = data_length / RAW_DATA_BYTES_PER_PAIR;
    if (data_length % RAW_DATA_BYTES_PER_PAIR != 0) {
        pairs++;  // partial trailing chunk needs its own pair
    }
    return pairs;
}

// Display pairs for one instruction: 1 program + N accounts + ceil(data).
static size_t pairs_for_instruction(const Instruction *ix) {
    return 1 + ix->accounts_length + data_pairs_for(ix->data_length);
}

// Signer/writable flag for a global account index, from the positional rules of
// a compiled Solana message header. Only the notable properties are flagged;
// a plain read-only account returns "" (no flag). `short_form` gives the terse
// "s,w" style used when pubkeys are truncated.
static const char *account_flags(uint16_t global_index, bool short_form) {
    uint8_t num_signers = G_raw.num_required_signatures;
    bool is_signer = global_index < num_signers;
    bool is_writable;
    if (is_signer) {
        // The first (num_signers - num_readonly_signed) signers are writable.
        is_writable = global_index < (uint16_t) (num_signers - G_raw.num_readonly_signed);
    } else {
        uint16_t num_unsigned = (uint16_t) (G_raw.pubkeys_length - num_signers);
        uint16_t unsigned_index = (uint16_t) (global_index - num_signers);
        // The first (num_unsigned - num_readonly_unsigned) non-signers are writable.
        is_writable = unsigned_index < (uint16_t) (num_unsigned - G_raw.num_readonly_unsigned);
    }
    if (is_signer && is_writable) {
        return short_form ? "s,w" : "signer, writable";
    }
    if (is_signer) {
        return short_form ? "s" : "signer";
    }
    if (is_writable) {
        return short_form ? "w" : "writable";
    }
    return "";  // read-only, not a signer: no flag
}

// Render the pubkey at `global_index` into `value`. Accounts referenced through
// an address lookup table are not present in the message and are rendered as a
// placeholder. When `with_flags` is set, a non-empty signer/writable tag is
// appended.
static int render_pubkey(uint16_t global_index, char *value, size_t value_len, bool with_flags) {
    if (global_index >= G_raw.pubkeys_length) {
        snprintf(value, value_len, "lookup table account #%u", global_index);
        return 0;
    }
    if (G_raw.short_pubkeys) {
        char full[BASE58_PUBKEY_LENGTH];
        if (encode_base58(&G_raw.pubkeys[global_index], PUBKEY_SIZE, full, sizeof(full)) != 0) {
            return -1;
        }
        // Truncate to xxxxxxx..xxxxxxx, matching the normal review screens.
        if (print_summary(full, value, BASE58_PUBKEY_SHORT, SUMMARY_LENGTH, SUMMARY_LENGTH) != 0) {
            return -1;
        }
    } else if (encode_base58(&G_raw.pubkeys[global_index], PUBKEY_SIZE, value, value_len) != 0) {
        return -1;
    }
    if (with_flags) {
        const char *flags = account_flags(global_index, G_raw.short_pubkeys);
        if (flags[0] != '\0') {
            strlcat(value, " (", value_len);
            strlcat(value, flags, value_len);
            strlcat(value, ")", value_len);
        }
    }
    return 0;
}

int raw_message_init(const uint8_t *body,
                     size_t body_length,
                     const MessageHeader *header,
                     const Hash *message_hash,
                     bool short_pubkeys,
                     size_t *out_pairs) {
    memset(&G_raw, 0, sizeof(G_raw));
    G_raw.body = body;
    G_raw.body_length = body_length;
    G_raw.pubkeys = header->pubkeys;
    G_raw.pubkeys_length = header->pubkeys_header.pubkeys_length;
    G_raw.num_required_signatures = header->pubkeys_header.num_required_signatures;
    G_raw.num_readonly_signed = header->pubkeys_header.num_readonly_signed_accounts;
    G_raw.num_readonly_unsigned = header->pubkeys_header.num_readonly_unsigned_accounts;
    G_raw.instructions_length = header->instructions_length;
    G_raw.message_hash = message_hash;
    G_raw.short_pubkeys = short_pubkeys;

    if (header->instructions_length == 0) {
        PRINTF("raw_message_init: no instructions to enumerate\n");
        return -1;
    }

    // Three leading pairs (Message Hash, Fee payer, Instructions count) precede
    // the per-instruction pairs.
    size_t total = 3;
    Parser parser = {body, body_length};
    for (size_t i = 0; i < header->instructions_length; i++) {
        Instruction ix;
        if (parse_instruction(&parser, &ix) != 0) {
            PRINTF("raw_message_init: parse_instruction %d failed\n", (int) i);
            return -1;
        }
        total += pairs_for_instruction(&ix);
        if (total > RAW_MAX_PAIRS) {
            // too large to enumerate; caller falls back to hash-only
            PRINTF("raw_message_init: %d pairs exceeds limit %d\n", (int) total, RAW_MAX_PAIRS);
            return -1;
        }
    }

    G_raw.total_pairs = total;
    *out_pairs = total;
    PRINTF("raw_message_init: %d display pairs\n", (int) total);
    return 0;
}

int raw_message_render_pair(size_t index,
                            char *title,
                            size_t title_len,
                            char *value,
                            size_t value_len) {
    if (index >= G_raw.total_pairs || title_len == 0 || value_len == 0) {
        return -1;
    }

    // Leading pairs: the identity of what is being signed. The hash goes
    // first so it is reachable without paging through every instruction and
    // mirrors the hash-only fallback screen; the fee payer and instruction
    // count follow before the per-instruction breakdown.
    if (index == 0) {
        strlcpy(title, "Message Hash", title_len);
        return encode_base58(G_raw.message_hash, HASH_SIZE, value, value_len);
    }
    if (index == 1) {
        strlcpy(title, "Fee payer", title_len);
        if (G_raw.pubkeys_length == 0) {
            strlcpy(value, "(none)", value_len);
            return 0;
        }
        return render_pubkey(0, value, value_len, false);
    }
    if (index == 2) {
        strlcpy(title, "Instructions", title_len);
        snprintf(value, value_len, "%u", (unsigned) G_raw.instructions_length);
        return 0;
    }

    // Instruction region: walk instructions, accumulating their pair counts
    // until `local` lands inside one of them.
    size_t local = index - 3;
    Parser parser = {G_raw.body, G_raw.body_length};
    for (size_t i = 0; i < G_raw.instructions_length; i++) {
        Instruction ix;
        if (parse_instruction(&parser, &ix) != 0) {
            return -1;
        }
        size_t accounts = ix.accounts_length;
        size_t data_pairs = data_pairs_for(ix.data_length);
        if (local >= 1 + accounts + data_pairs) {
            local -= 1 + accounts + data_pairs;
            continue;
        }

        // Program id.
        if (local == 0) {
            snprintf(title, title_len, "Ix %u program", (unsigned) (i + 1));
            return render_pubkey(ix.program_id_index, value, value_len, false);
        }

        // Account meta.
        if (local <= accounts) {
            size_t account_ordinal = local - 1;  // 0-based within this instruction
            snprintf(title,
                     title_len,
                     "Ix %u account %u/%u",
                     (unsigned) (i + 1),
                     (unsigned) (account_ordinal + 1),
                     (unsigned) accounts);
            return render_pubkey(ix.accounts[account_ordinal], value, value_len, true);
        }

        // Instruction data (hex, chunked).
        size_t chunk = local - 1 - accounts;
        if (ix.data_length == 0) {
            snprintf(title, title_len, "Ix %u data", (unsigned) (i + 1));
            strlcpy(value, "(empty)", value_len);
            return 0;
        }
        snprintf(title,
                 title_len,
                 "Ix %u data %u/%u",
                 (unsigned) (i + 1),
                 (unsigned) (chunk + 1),
                 (unsigned) data_pairs);
        size_t start = chunk * RAW_DATA_BYTES_PER_PAIR;
        size_t remaining = ix.data_length - start;
        size_t n = remaining < RAW_DATA_BYTES_PER_PAIR ? remaining : RAW_DATA_BYTES_PER_PAIR;
        // encode_hex returns >0 (bytes written incl. NUL) on success, -1 on error.
        return (encode_hex(ix.data + start, n, value, value_len) < 0) ? -1 : 0;
    }

    return -1;  // unreachable when total_pairs is consistent with the body
}

bool raw_message_starts_instruction(size_t index) {
    // True for the first (program) pair of every instruction except the first,
    // so the review starts each one on a new page. The leading pairs (hash, fee
    // payer, count) and instruction 1 pack together; instructions 2+ each break.
    if (index < 3) {
        return false;
    }
    size_t local = index - 3;
    Parser parser = {G_raw.body, G_raw.body_length};
    for (size_t i = 0; i < G_raw.instructions_length; i++) {
        Instruction ix;
        if (parse_instruction(&parser, &ix) != 0) {
            return false;
        }
        size_t pairs = pairs_for_instruction(&ix);
        if (local < pairs) {
            return (local == 0) && (i >= 1);
        }
        local -= pairs;
    }
    return false;
}
