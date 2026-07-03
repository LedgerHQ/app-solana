#pragma once

#include <stdbool.h>
#include <stdint.h>

#define PUBKEY_SIZE 32

typedef struct Pubkey {
    uint8_t data[PUBKEY_SIZE];
} Pubkey;

bool pubkeys_equal(const Pubkey *pubkey1, const Pubkey *pubkey2);
