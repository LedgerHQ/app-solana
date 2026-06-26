#pragma once

// Public-domain SHA-256 (Brad Conte, https://github.com/B-Con/crypto-algorithms),
// vendored for host-side libsol unit tests only. Lets the cx.h mock provide a
// real SHA-256 without depending on a system crypto library, so tests behave
// identically across host and Docker. NOT compiled into the device firmware.

#include <stddef.h>
#include <stdint.h>

#define MOCK_SHA256_DIGEST_SIZE 32

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} mock_sha256_ctx;

void mock_sha256_init(mock_sha256_ctx *ctx);
void mock_sha256_update(mock_sha256_ctx *ctx, const uint8_t *data, size_t len);
void mock_sha256_final(mock_sha256_ctx *ctx, uint8_t hash[MOCK_SHA256_DIGEST_SIZE]);
