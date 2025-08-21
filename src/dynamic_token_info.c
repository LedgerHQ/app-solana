#include "os.h"
#include "dynamic_token_info.h"
#include "ed25519_helpers.h"

const char *get_dynamic_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind) {
    if (!g_dynamic_token_info.received || mint_address == NULL) {
        return NULL;
    }

    // We have received a descriptor that should apply to the current token. use it.
    if (memcmp(g_dynamic_token_info.mint_address, mint_address, PUBKEY_SIZE) != 0) {
        PRINTF("Received dynamic token info for token '%.*H' != token '%.*H'\n",
               PUBKEY_SIZE,
               g_dynamic_token_info.mint_address,
               PUBKEY_SIZE,
               mint_address);
        return NULL;
    }

    if (is_token_2022_kind != g_dynamic_token_info.is_token_2022_kind) {
        PRINTF("Token kind mismatch %d != %d\n",
               is_token_2022_kind,
               g_dynamic_token_info.is_token_2022_kind);
        return NULL;
    }

    PRINTF("Using dynamic token info to map token '%.*H' == ticker '%s'\n",
           PUBKEY_SIZE,
           g_dynamic_token_info.mint_address,
           g_dynamic_token_info.ticker);
    return g_dynamic_token_info.ticker;
}

const char *get_token_symbol(const uint8_t *mint_address, bool is_token_2022_kind) {
    const char *symbol = get_dynamic_token_symbol(mint_address, is_token_2022_kind);
    if (symbol == NULL) {
        PRINTF("No suitable dynamic token info received, fallback on hardcoded list\n");
        symbol = get_hardcoded_token_symbol(mint_address);
    }
    return symbol;
}

const uint8_t *get_dynamic_token_mint_address(const char *symbol, bool *is_token_2022_kind) {
    if (!g_dynamic_token_info.received || symbol == NULL) {
        return NULL;
    }

    // We have received a descriptor that should apply to the current token. use it.
    if (strcmp(symbol, g_dynamic_token_info.ticker) != 0) {
        PRINTF("Received dynamic token info for token '%s' != token '%s'\n",
               symbol,
               g_dynamic_token_info.ticker);
        return NULL;
    }

    *is_token_2022_kind = g_dynamic_token_info.is_token_2022_kind;
    return g_dynamic_token_info.mint_address;
}

const uint8_t *get_token_mint_address(const char *symbol, bool *is_token_2022_kind) {
    const uint8_t *mint_address = get_dynamic_token_mint_address(symbol, is_token_2022_kind);
    if (mint_address == NULL) {
        PRINTF("No suitable dynamic token info retrieved, fallback on hardcoded data\n");
        mint_address = get_hardcoded_token_mint_address(symbol, is_token_2022_kind);
    }
    return mint_address;
}
