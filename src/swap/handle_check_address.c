// --8<-- [start:file]

#include <string.h>

#include "handle_check_address.h"
#include "os.h"
#include "utils.h"
#include "sol/printer.h"

// Helper to get our public key in base58 format for a given derivation path
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

// Check that params->address_to_check belongs to us on derivation path params->address_parameters
void swap_handle_check_address(check_address_parameters_t *params) {
    PRINTF("Inside Solana swap_handle_check_address\n");
    // ensure result is zero even if an exception is thrown
    params->result = 0;
    PRINTF("Params on the address %d\n", (unsigned int) params);

    if (params->address_parameters == NULL) {
        PRINTF("derivation path expected\n");
        return;
    }

    if (params->address_to_check == NULL) {
        PRINTF("Address to check expected\n");
        return;
    }
    PRINTF("Address to check %s\n", params->address_to_check);

    if (params->extra_id_to_check == NULL) {
        PRINTF("extra_id_to_check expected\n");
        return;
    } else if (params->extra_id_to_check[0] != '\0') {
        PRINTF("extra_id_to_check expected empty, not '%s'\n", params->extra_id_to_check);
        return;
    }

    uint8_t public_key[PUBKEY_LENGTH];
    char public_key_str[BASE58_PUBKEY_LENGTH];
    if (derive_public_key(params->address_parameters,
                          params->address_parameters_length,
                          public_key,
                          public_key_str) != 0) {
        PRINTF("Failed to derive public key\n");
        return;
    }
    // Only public_key_str is useful in this context
    UNUSED(public_key);

    if (strcmp(params->address_to_check, public_key_str) != 0) {
        PRINTF("Address %s != %s\n", params->address_to_check, public_key_str);
        return;
    }

    PRINTF("Addresses match\n");
    params->result = 1;
}

// --8<-- [end:file]
