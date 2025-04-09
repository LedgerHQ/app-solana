#pragma once

#include "sol/parser.h"
#include "sol/printer.h"

// TransactionSummary management
//
// TransactionSummary sits behind a singleton and is expected to be accessed
// via the following methods
//
// A TransactionSummary consists of several SummaryItems.  If set previously,
// they will be displayed in the following order:
//
// primary          -- Required
// general[0..N]    -- Optional
// nonce_account    -- Optional
// nonce_authority  -- Optional
// fee_payer        -- Required
//
// If all _Required_ `SummaryItem`s have not been set, finalization will fail.

#define NUM_GENERAL_ITEMS          11
#define DEFAULT_COMPUTE_UNIT_LIMIT 200000
#define COMPUTE_UNIT_PRICE_DIVIDER 1000000
#define MAX_TRANSACTION_SUMMARY_ITEMS              \
    (1                       /* primary */         \
     + NUM_GENERAL_ITEMS + 1 /* nonce_account */   \
     + 1                     /* nonce_authority */ \
     + 1                     /* fee_payer */       \
    )

typedef struct TokenAmount {
    uint64_t value;
    const char *symbol;
    uint8_t decimals;
} TokenAmount;

enum SummaryItemKind {
    SummaryItemNone = 0,  // SummaryItemNone always zero
    SummaryItemAmount,
    SummaryItemTokenAmount,
    SummaryItemI64,
    SummaryItemU64,
    SummaryItemPubkey,
    SummaryItemHash,
    SummaryItemSizedString,
    SummaryItemString,
    SummaryItemTimestamp,
};
typedef enum SummaryItemKind SummaryItemKind_t;

typedef struct SummaryItem SummaryItem;

extern char G_transaction_summary_title[TITLE_SIZE];
#define TEXT_BUFFER_LENGTH BASE58_PUBKEY_LENGTH
extern char G_transaction_summary_text[TEXT_BUFFER_LENGTH];

void transaction_summary_reset();
enum DisplayFlags {
    DisplayFlagNone = 0,
    DisplayFlagLongPubkeys = 1 << 0,
    DisplayFlagAll = DisplayFlagLongPubkeys,
};
int transaction_summary_display_item(size_t item_index, enum DisplayFlags flags);
int transaction_summary_finalize(enum SummaryItemKind *item_kinds, size_t *item_kinds_len);

// Get a pointer to the requested SummaryItem. NULL if it has already been set
SummaryItem *transaction_summary_primary_item();
SummaryItem *transaction_summary_fee_payer_item();
SummaryItem *transaction_summary_nonce_account_item();
SummaryItem *transaction_summary_nonce_authority_item();
SummaryItem *transaction_summary_general_item();

int transaction_summary_set_fee_payer_pubkey(const Pubkey *pubkey);

// Assign type/title/value to a SummaryItem
void summary_item_set_amount(SummaryItem *item, const char *title, uint64_t value);
void summary_item_set_token_amount(SummaryItem *item,
                                   const char *title,
                                   uint64_t value,
                                   const char *symbol,
                                   uint8_t decimals);
void summary_item_set_i64(SummaryItem *item, const char *title, int64_t value);
void summary_item_set_u64(SummaryItem *item, const char *title, uint64_t value);
void summary_item_set_pubkey(SummaryItem *item, const char *title, const Pubkey *value);
void summary_item_set_hash(SummaryItem *item, const char *title, const Hash *value);
void summary_item_set_sized_string(SummaryItem *item, const char *title, const SizedString *value);
void summary_item_set_string(SummaryItem *item, const char *title, const char *value);
void summary_item_set_timestamp(SummaryItem *item, const char *title, int64_t value);
void transaction_summary_set_token_fee_warning(bool fee_warning);
void transaction_summary_set_token_hook_warning(bool hook_warning);
void transaction_summary_get_token_warnings(bool *fee_warning, bool *hook_warning);
void transaction_summary_set_is_token_2022_transfer(bool is_token_2022_transfer);
void transaction_summary_get_is_token_2022_transfer(bool *is_token_2022_transfer);
