#include "sol/pubkey.h"
#include <string.h>

bool pubkeys_equal(const Pubkey *pubkey1, const Pubkey *pubkey2) {
    return memcmp(pubkey1, pubkey2, PUBKEY_SIZE) == 0;
}
