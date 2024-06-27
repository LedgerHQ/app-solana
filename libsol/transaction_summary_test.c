#include "common_byte_strings.h"
#include "sol/transaction_summary.h"
#include "transaction_summary.c"
#include <assert.h>
#include <stdio.h>

void test_summary_item_setters() {
    SummaryItem item;

    summary_item_set_amount(&item, "amount", 42);
    assert(item.kind == SummaryItemAmount);
    assert_string_equal(item.title, "amount");
    assert(item.u64 == 42);

    summary_item_set_token_amount(&item, "token", 42, "TST", 2);
    assert(item.kind == SummaryItemTokenAmount);
    assert_string_equal(item.title, "token");
    assert(item.token_amount.value == 42);
    assert_string_equal(item.token_amount.symbol, "TST");
    assert(item.token_amount.decimals == 2);

    summary_item_set_i64(&item, "i64", -42);
    assert(item.kind == SummaryItemI64);
    assert_string_equal(item.title, "i64");
    assert(item.i64 == -42);

    summary_item_set_u64(&item, "u64", 4242);
    assert(item.kind == SummaryItemU64);
    assert_string_equal(item.title, "u64");
    assert(item.u64 == 4242);

    Pubkey pubkey = {{BYTES32_BS58_2}};
    summary_item_set_pubkey(&item, "pubkey", &pubkey);
    assert(item.kind == SummaryItemPubkey);
    assert_string_equal(item.title, "pubkey");
    assert(item.pubkey == &pubkey);

    Hash hash = {{BYTES32_BS58_3}};
    summary_item_set_hash(&item, "hash", &hash);
    assert(item.kind == SummaryItemHash);
    assert_string_equal(item.title, "hash");
    assert(item.hash == &hash);

    const char* string = "value";
    summary_item_set_string(&item, "string", string);
    assert(item.kind == SummaryItemString);
    assert_string_equal(item.title, "string");
    assert(item.string == string);

    uint8_t string_data[4] = {0x74, 0x65, 0x73, 0x74};
    SizedString sized_string = {
        sizeof(string_data),
        (char*) string_data,
    };
    summary_item_set_sized_string(&item, "sizedString", &sized_string);
    assert(item.kind == SummaryItemSizedString);
    assert_string_equal(item.title, "sizedString");
    assert(item.sized_string.length == sizeof(string_data));
    assert(strncmp("test", item.sized_string.string, item.sized_string.length) == 0);

    summary_item_set_timestamp(&item, "timestamp", 42);
    assert(item.kind == SummaryItemTimestamp);
    assert_string_equal(item.title, "timestamp");
    assert(item.i64 == 42);
}

void test_summary_item_as_unused() {
    SummaryItem item;

    item.kind = SummaryItemNone;
    assert(summary_item_as_unused(&item) != NULL);

    item.kind = SummaryItemAmount;
    assert(summary_item_as_unused(&item) == NULL);

    item.kind = SummaryItemTokenAmount;
    assert(summary_item_as_unused(&item) == NULL);

    item.kind = SummaryItemI64;
    assert(summary_item_as_unused(&item) == NULL);

    item.kind = SummaryItemU64;
    assert(summary_item_as_unused(&item) == NULL);

    item.kind = SummaryItemPubkey;
    assert(summary_item_as_unused(&item) == NULL);

    item.kind = SummaryItemHash;
    assert(summary_item_as_unused(&item) == NULL);

    item.kind = SummaryItemSizedString;
    assert(summary_item_as_unused(&item) == NULL);

    item.kind = SummaryItemString;
    assert(summary_item_as_unused(&item) == NULL);

    item.kind = SummaryItemTimestamp;
    assert(summary_item_as_unused(&item) == NULL);
}

void test_transaction_summary_reset() {
    memset(&G_transaction_summary, 1, sizeof(TransactionSummary));
    memset(G_transaction_summary_title, 1, TITLE_SIZE);
    memset(G_transaction_summary_text, 1, TEXT_BUFFER_LENGTH);

    transaction_summary_reset();

    assert(strlen(G_transaction_summary_title) == 0);
    assert(strlen(G_transaction_summary_text) == 0);

    SummaryItem* item;

    assert((item = transaction_summary_primary_item()) != NULL);
    assert(item->kind == SummaryItemNone);

    assert((item = transaction_summary_fee_payer_item()) != NULL);
    assert(item->kind == SummaryItemNone);

    assert((item = transaction_summary_nonce_account_item()) != NULL);
    assert(item->kind == SummaryItemNone);

    assert((item = transaction_summary_nonce_authority_item()) != NULL);
    assert(item->kind == SummaryItemNone);

    for (size_t i = 0; i < NUM_GENERAL_ITEMS; i++) {
        assert((item = transaction_summary_general_item()) != NULL);
        assert(item->kind == SummaryItemNone);
    }
}

void test_transaction_summary_item_getters() {
    SummaryItem* item;

    assert((item = transaction_summary_primary_item()) != NULL);
    summary_item_set_u64(item, "item", 42);
    assert(transaction_summary_primary_item() == NULL);

    assert((item = transaction_summary_fee_payer_item()) != NULL);
    summary_item_set_u64(item, "item", 42);
    assert(transaction_summary_fee_payer_item() == NULL);

    assert((item = transaction_summary_nonce_account_item()) != NULL);
    summary_item_set_u64(item, "item", 42);
    assert(transaction_summary_nonce_account_item() == NULL);

    assert((item = transaction_summary_nonce_authority_item()) != NULL);
    summary_item_set_u64(item, "item", 42);
    assert(transaction_summary_nonce_authority_item() == NULL);

    for (size_t i = 0; i < NUM_GENERAL_ITEMS; i++) {
        assert((item = transaction_summary_general_item()) != NULL);
        summary_item_set_u64(item, "item", 42);
    }
    assert(transaction_summary_general_item() == NULL);
}

#define assert_transaction_summary_display(title, text)          \
    do {                                                         \
        assert_string_equal(G_transaction_summary_title, title); \
        assert_string_equal(G_transaction_summary_text, text);   \
    } while (0)

void test_transaction_summary_update_display_for_item() {
    SummaryItem item;

    item.kind = SummaryItemNone;
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 1);

    summary_item_set_amount(&item, "amount", 42);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("amount", "0.000000042 SOL");

    summary_item_set_token_amount(&item, "token", 42, "TST", 2);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("token", "0.42 TST");

    summary_item_set_i64(&item, "i64", -42);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("i64", "-42");

    summary_item_set_u64(&item, "u64", 4242);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("u64", "4242");

    Pubkey pubkey;
    explicit_bzero(&pubkey, sizeof(Pubkey));
    summary_item_set_pubkey(&item, "pubkey", &pubkey);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("pubkey", "1111111..1111111");
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagLongPubkeys) == 0);
    assert_transaction_summary_display("pubkey", "11111111111111111111111111111111");

    Hash hash;
    explicit_bzero(&hash, sizeof(Hash));
    summary_item_set_hash(&item, "hash", &hash);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("hash", "11111111111111111111111111111111");

    uint8_t string_data[] = {0x74, 0x65, 0x73, 0x74};
    SizedString sized_string = {sizeof(string_data), (char*) string_data};
    summary_item_set_sized_string(&item, "sizedString", &sized_string);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("sizedString", "test");

    const char* string = "value";
    summary_item_set_string(&item, "string", string);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("string", "value");

    summary_item_set_timestamp(&item, "timestamp", 42);
    assert(transaction_summary_update_display_for_item(&item, DisplayFlagNone) == 0);
    assert_transaction_summary_display("timestamp", "1970-01-01 00:00:42");
}

#define display_item_test_helper(item, item_index)                                  \
    do {                                                                            \
        SummaryItem* si;                                                            \
        assert((si = transaction_summary_##item##_item()) != NULL);                 \
        summary_item_set_u64(si, #item, 42);                                        \
        assert(transaction_summary_display_item(item_index, DisplayFlagNone) == 0); \
        assert_transaction_summary_display(#item, "42");                            \
    } while (0)

#define display_item_test_helper_general_item(general_index)                               \
    do {                                                                                   \
        SummaryItem* si;                                                                   \
        const char* title = "general_" #general_index;                                     \
        assert((si = transaction_summary_general_item()) != NULL);                         \
        summary_item_set_u64(si, title, 42);                                               \
        assert(transaction_summary_display_item(general_index + 1, DisplayFlagNone) == 0); \
        assert_transaction_summary_display(title, "42");                                   \
    } while (0)

void test_transaction_summary_display_item() {
    transaction_summary_reset();

    display_item_test_helper(primary, 0);

    for (size_t i = 0; i < NUM_GENERAL_ITEMS; i++) {
        display_item_test_helper_general_item(i);
    }

    display_item_test_helper(nonce_account, 1 + NUM_GENERAL_ITEMS);
    display_item_test_helper(nonce_authority, 1 + NUM_GENERAL_ITEMS + 1);
    display_item_test_helper(fee_payer, 1 + NUM_GENERAL_ITEMS + 2);
}

#define zero_kinds_array(kinds) \
    explicit_bzero(kinds, MAX_TRANSACTION_SUMMARY_ITEMS * sizeof(enum SummaryItemKind))

#define assert_kinds_array(kinds, num_kinds)                         \
    do {                                                             \
        for (size_t k = 0; k < MAX_TRANSACTION_SUMMARY_ITEMS; k++) { \
            if (k < num_kinds) {                                     \
                assert(kinds[k] == SummaryItemU64);                  \
            } else {                                                 \
                assert(kinds[k] == SummaryItemNone);                 \
            }                                                        \
        }                                                            \
    } while (0)

void test_transaction_summary_finalize() {
    enum SummaryItemKind kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_kinds;
    SummaryItem* item;

    transaction_summary_reset();

    // No items set fails
    assert(transaction_summary_finalize(kinds, &num_kinds) == 1);

    // Only optional items set fails
    size_t i;
    for (i = 0; i < NUM_GENERAL_ITEMS; i++) {
        item = transaction_summary_general_item();
        summary_item_set_u64(item, "item", 42);
    }
    item = transaction_summary_nonce_account_item();
    summary_item_set_u64(item, "item", 42);
    item = transaction_summary_nonce_authority_item();
    summary_item_set_u64(item, "item", 42);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 1);

    // No primary set fails
    item = transaction_summary_fee_payer_item();
    summary_item_set_u64(item, "item", 42);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 1);

    // Minimum items set (primary) succeeds
    transaction_summary_reset();
    item = transaction_summary_primary_item();
    summary_item_set_u64(item, "item", 42);
    num_kinds = 0;
    zero_kinds_array(kinds);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
    assert(num_kinds == 1);
    assert_kinds_array(kinds, num_kinds);

    item = transaction_summary_fee_payer_item();
    summary_item_set_u64(item, "item", 42);
    num_kinds = 0;
    zero_kinds_array(kinds);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
    assert(num_kinds == 2);
    assert_kinds_array(kinds, num_kinds);

    // Optionals still succeed and count
    for (i = 0; i < NUM_GENERAL_ITEMS; i++) {
        item = transaction_summary_general_item();
        summary_item_set_u64(item, "item", 42);
        num_kinds = 0;
        zero_kinds_array(kinds);
        assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
        assert(num_kinds == (2 + 1 + i));
        assert_kinds_array(kinds, num_kinds);
    }

    item = transaction_summary_nonce_account_item();
    summary_item_set_u64(item, "item", 42);
    num_kinds = 0;
    zero_kinds_array(kinds);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
    assert(num_kinds == (2 + NUM_GENERAL_ITEMS + 1));
    assert_kinds_array(kinds, num_kinds);

    item = transaction_summary_nonce_authority_item();
    summary_item_set_u64(item, "item", 42);
    num_kinds = 0;
    zero_kinds_array(kinds);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
    assert(num_kinds == (2 + NUM_GENERAL_ITEMS + 2));
    assert_kinds_array(kinds, num_kinds);
}

void test_repro_unrecognized_format_reverse_nav_hash_corruption_bug() {
    SummaryItem* item;
    const char* primary_title = "Unrecognized";
    const char* primary_text = "format";
    const char* fee_payer_title = FEE_PAYER_TITLE;
    const char* fee_payer_text = "1111111..1111111";
    Pubkey fee_payer = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const char* message_hash_title = "Message hash";
    const char* message_hash_text = "22222222222222222222222222222222222222222222";
    Hash message_hash = {{0x0f, 0x1e, 0x6b, 0x14, 0x21, 0xc0, 0x4a, 0x07, 0x04, 0x31, 0x26,
                          0x5c, 0x19, 0xc5, 0xbb, 0xee, 0x19, 0x92, 0xba, 0xe8, 0xaf, 0xd1,
                          0xcd, 0x07, 0x8e, 0xf8, 0xaf, 0x70, 0x47, 0xdc, 0x11, 0xf7}};

    transaction_summary_reset();

    item = transaction_summary_fee_payer_item();
    summary_item_set_pubkey(item, fee_payer_title, &fee_payer);
    item = transaction_summary_general_item();
    summary_item_set_hash(item, message_hash_title, &message_hash);
    item = transaction_summary_primary_item();
    summary_item_set_string(item, primary_title, primary_text);

    enum SummaryItemKind kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_kinds = 0;
    zero_kinds_array(kinds);
    assert(transaction_summary_finalize(kinds, &num_kinds) == 0);
    assert(num_kinds == 3);

    assert(transaction_summary_display_item(0, DisplayFlagNone) == 0);
    assert_transaction_summary_display(primary_title, primary_text);
    assert(transaction_summary_display_item(1, DisplayFlagNone) == 0);
    assert_transaction_summary_display(message_hash_title, message_hash_text);
    assert(transaction_summary_display_item(2, DisplayFlagNone) == 0);
    assert_transaction_summary_display(fee_payer_title, fee_payer_text);
    assert(transaction_summary_display_item(1, DisplayFlagNone) == 0);
    assert_transaction_summary_display(message_hash_title, message_hash_text);
    assert(transaction_summary_display_item(0, DisplayFlagNone) == 0);
    assert_transaction_summary_display(primary_title, primary_text);
}

int main() {
    test_summary_item_setters();
    test_summary_item_as_unused();

    test_transaction_summary_reset();
    test_transaction_summary_item_getters();
    test_transaction_summary_update_display_for_item();
    test_transaction_summary_display_item();
    test_transaction_summary_finalize();

    test_repro_unrecognized_format_reverse_nav_hash_corruption_bug();

    printf("passed\n");
    return 0;
}
