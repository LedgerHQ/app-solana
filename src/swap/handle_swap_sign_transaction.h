#pragma once

#include "swap_lib_calls.h"
#include "sol/parser.h"
#include "swap_common.h"

bool swap_copy_transaction_parameters(create_transaction_parameters_t *sign_transaction_params);

swap_mode_t get_swap_mode(void);

bool check_template_id(uint32_t template_id);

bool check_swap_tx_hash(const uint8_t *computed_hash);

bool check_swap_amount_raw_less_or_equal(uint64_t amount);

int get_swap_amount_raw(uint64_t *amount);

bool check_swap_amount(const char *text);

const char *get_swap_ticker(void);

bool check_swap_fee(const char *text);

// Checks that the lamports the transaction spends outside of the swap amount stay within the fee
// validated by Exchange
bool check_swap_fee_raw_less_or_equal(uint64_t lamports);

bool check_swap_recipient(const char *text);

int get_swap_recipient(uint8_t recipient_address[PUBKEY_SIZE]);

// Reports whether the swap validated by Exchange pays with a token
bool is_token_transaction(void);
