#pragma once
#include <stdint.h>

#define OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH 16

/**
* 1. Signing domain (16 bytes)
* 2. Header version (1 byte)
* 3. Application domain (32 bytes)
* 4. Message format (1 byte)
* 5. Signer count (1 bytes)
* 6. Signers (signer_count *  32 bytes) - assume that only one signer is present
* 7. Message length (2 bytes)
*/
typedef struct OffchainMessageSigningDomain {
    uint8_t data[OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH];
} OffchainMessageSigningDomain;

extern const OffchainMessageSigningDomain offchain_message_signing_domain;

