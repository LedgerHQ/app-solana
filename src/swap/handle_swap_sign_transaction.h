#pragma once

#include "swap_lib_calls.h"

bool copy_transaction_parameters(create_transaction_parameters_t *sign_transaction_params);

bool check_swap_amount(const char *text);

bool check_swap_fee(const char *text);

bool check_swap_recipient(const char *text);

bool is_token_transaction();

void __attribute__((noreturn)) finalize_exchange_sign_transaction(bool is_success);
