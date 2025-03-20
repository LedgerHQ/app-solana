#include <string.h>

#include "handle_check_address.h"
#include "os.h"
#include "utils.h"
#include "sol/printer.h"

static int derive_public_key(const uint8_t *buffer,
                             uint16_t buffer_length,
                             uint8_t public_key[PUBKEY_LENGTH],
                             char public_key_str[BASE58_PUBKEY_LENGTH]) {
    uint32_t derivation_path[MAX_BIP32_PATH_LENGTH];
    uint32_t path_length;
    int ret;

    ret = read_derivation_path(buffer, buffer_length, derivation_path, &path_length) != 0;
    if (ret != 0) {
        return ret;
    }

    get_public_key(public_key, derivation_path, path_length);

    return encode_base58(public_key, PUBKEY_LENGTH, public_key_str, BASE58_PUBKEY_LENGTH);
}

int handle_check_address(const check_address_parameters_t *params) {
    PRINTF("Inside Solana handle_check_address\n");
    PRINTF("Params on the address %d\n", (unsigned int) params);

    if (params->address_parameters == NULL) {
        PRINTF("derivation path expected\n");
        return 0;
    }

    if (params->address_to_check == NULL) {
        PRINTF("Address to check expected\n");
        return 0;
    }
    PRINTF("Address to check %s\n", params->address_to_check);

    if (params->extra_id_to_check == NULL) {
        PRINTF("extra_id_to_check expected\n");
        return 0;
    } else if (params->extra_id_to_check[0] != '\0') {
        PRINTF("extra_id_to_check expected empty, not '%s'\n", params->extra_id_to_check);
        return 0;
    }

    uint8_t public_key[PUBKEY_LENGTH];
    char public_key_str[BASE58_PUBKEY_LENGTH];
    if (derive_public_key(params->address_parameters,
                          params->address_parameters_length,
                          public_key,
                          public_key_str) != 0) {
        PRINTF("Failed to derive public key\n");
        return 0;
    }
    // Only public_key_str is useful in this context
    UNUSED(public_key);

    if (strcmp(params->address_to_check, public_key_str) != 0) {
        PRINTF("Address %s != %s\n", params->address_to_check, public_key_str);
        return 0;
    }

    PRINTF("Addresses match\n");
    return 1;
}
