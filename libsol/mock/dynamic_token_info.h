#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "../instruction.h"
#include "sol/parser.h"

const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind);
const uint8_t *get_token_mint_address(const char *symbol, bool *is_token_2022_kind);
