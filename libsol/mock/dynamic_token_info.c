#include "dynamic_token_info.h"
#include "../token_info.h"

const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind) {
    UNUSED(is_token_2022_kind);
    return get_hardcoded_token_symbol(mint_address);
}
const uint8_t *get_token_mint_address(const char *symbol, bool *is_token_2022_kind) {
    return get_hardcoded_token_mint_address(symbol, is_token_2022_kind);
}
