#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "sol/pubkey.h"

#define OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH 16

#define OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH 32

/**
 * V0 layout:
 *   1. Signing domain (16 bytes)
 *   2. Header version (1 byte) = 0x00
 *   3. Application domain (32 bytes)
 *   4. Message format (1 byte)
 *   5. Signer count (1 byte)
 *   6. Signers (signer_count * 32 bytes)
 *   7. Message length (2 bytes, LE)
 *   8. Message body (message_length bytes)
 *
 * V1 layout (sRFC 38):
 *   1. Signing domain (16 bytes)
 *   2. Header version (1 byte) = 0x01
 *   3. Signer count (1 byte)
 *   4. Signers (signer_count * 32 bytes, lexicographically sorted, unique)
 *   5. Message body (trailing bytes, no length prefix)
 */

typedef struct OffchainMessageSigningDomain {
    uint8_t data[OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH];
} OffchainMessageSigningDomain;

int check_offchain_signing_domain(const uint8_t *buffer, size_t buffer_length);

typedef struct OffchainMessageApplicationDomain {
    uint8_t data[OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH];
} OffchainMessageApplicationDomain;

bool is_offchain_application_domain_empty(const OffchainMessageApplicationDomain *domain);

typedef struct OffchainMessageHeader {
    uint8_t version;
    // V0 only: application_domain is NULL for V1
    const OffchainMessageApplicationDomain *application_domain;
    // V0 only: format is unused for V1
    uint8_t format;
    size_t signers_length;
    const Pubkey *signers;
    size_t length;
} OffchainMessageHeader;

size_t get_offchain_message_header_length(const OffchainMessageHeader *header);
