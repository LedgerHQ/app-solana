#pragma once

#include "swap_lib_calls.h"
#include "sol/parser.h"

bool swap_copy_transaction_parameters(create_transaction_parameters_t *sign_transaction_params);

bool check_swap_amount_raw(uint64_t amount);

bool check_swap_amount(const char *text);

bool check_swap_ticker(const char *ticker);

const char *get_swap_ticker();

bool check_swap_fee(const char *text);

bool check_swap_recipient(const char *text);

int get_swap_recipient(uint8_t recipient_address[PUBKEY_SIZE]);

bool is_token_transaction();

void __attribute__((noreturn)) finalize_exchange_sign_transaction(bool is_success);
