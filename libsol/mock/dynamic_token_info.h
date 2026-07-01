#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "../instruction.h"
#include "sol/parser.h"

const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind);
int get_token_magnitude(const uint8_t *mint_address, bool is_token_2022_kind);
const uint8_t *get_token_mint_address(const char *symbol, bool *is_token_2022_kind);

// Test control: set a mock entry so get_token_symbol / get_token_magnitude
// return non-NULL/non-negative for a specific mint during unit tests.
void mock_dynamic_token_info_set(const uint8_t *mint, const char *ticker, uint8_t magnitude);
void mock_dynamic_token_info_reset(void);
