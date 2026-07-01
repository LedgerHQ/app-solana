#include "dynamic_token_info.h"
#include "../token_info.h"
#include <string.h>

#define MOCK_TOKEN_MAX 8

typedef struct {
    uint8_t mint[32];
    char ticker[33];
    uint8_t magnitude;
    bool active;
} mock_token_entry_t;

static mock_token_entry_t G_mock_tokens[MOCK_TOKEN_MAX];
static size_t G_mock_token_count = 0;

void mock_dynamic_token_info_set(const uint8_t *mint, const char *ticker, uint8_t magnitude) {
    if (G_mock_token_count >= MOCK_TOKEN_MAX) {
        return;
    }
    memcpy(G_mock_tokens[G_mock_token_count].mint, mint, 32);
    strncpy(G_mock_tokens[G_mock_token_count].ticker, ticker, 32);
    G_mock_tokens[G_mock_token_count].ticker[32] = '\0';
    G_mock_tokens[G_mock_token_count].magnitude = magnitude;
    G_mock_tokens[G_mock_token_count].active = true;
    G_mock_token_count++;
}

void mock_dynamic_token_info_reset(void) {
    memset(G_mock_tokens, 0, sizeof(G_mock_tokens));
    G_mock_token_count = 0;
}

const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind) {
    UNUSED(is_token_2022_kind);
    for (size_t i = 0; i < G_mock_token_count; i++) {
        if (G_mock_tokens[i].active && memcmp(G_mock_tokens[i].mint, mint_address, 32) == 0) {
            return G_mock_tokens[i].ticker;
        }
    }
    return get_hardcoded_token_symbol(mint_address);
}

int get_token_magnitude(const uint8_t *mint_address, bool is_token_2022_kind) {
    UNUSED(is_token_2022_kind);
    for (size_t i = 0; i < G_mock_token_count; i++) {
        if (G_mock_tokens[i].active && memcmp(G_mock_tokens[i].mint, mint_address, 32) == 0) {
            return (int) G_mock_tokens[i].magnitude;
        }
    }
    return -1;
}

const uint8_t *get_token_mint_address(const char *symbol, bool *is_token_2022_kind) {
    return get_hardcoded_token_mint_address(symbol, is_token_2022_kind);
}
