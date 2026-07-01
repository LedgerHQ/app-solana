#include <string.h>

#include "sol/offchain_message_signing.h"
#include "common_byte_strings.h"

int check_offchain_signing_domain(const uint8_t *buffer, size_t buffer_length) {
    if (buffer_length < OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH) {
        return -1;
    }
    const OffchainMessageSigningDomain domain = {{OFFCHAIN_MESSAGE_SIGNING_DOMAIN}};
    return memcmp(domain.data, buffer, OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH);
}

bool is_offchain_application_domain_empty(const OffchainMessageApplicationDomain *domain) {
    uint8_t zeros[OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH];
    memset(zeros, 0, sizeof(zeros));
    return memcmp(domain->data, zeros, OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH) == 0;
}

size_t get_offchain_message_header_length(const OffchainMessageHeader *header) {
    // Common: signing_domain + version(1) + signer_count(1) + signers(32*n)
    size_t base_length = OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH + 1 + 1 +
                         (PUBKEY_SIZE * header->signers_length);
    if (header->version == 0) {
        // V0 adds: application_domain(32) + format(1) + message_length(2)
        base_length += OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH + 1 + 2;
    }
    return base_length;
}
