#pragma once

// Host-side mock of the Ledger cx.h crypto API, limited to the SHA-256 surface
// used by libsol modules (cs_substructure). Backed by the vendored public-domain
// SHA-256 in mock_sha256.c so unit tests compute real digests without any system
// crypto dependency. The device firmware uses the real SDK cx.h; this shim is
// only on the test include path (-Imock).

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "mock_sha256.h"

#define CX_SHA256_SIZE 32
#define CX_OK          0

typedef int cx_err_t;

typedef struct {
    mock_sha256_ctx impl;
} cx_sha256_t;

// On device, cx_hash_t is the generic base of cx_sha256_t and callers cast
// between them. Aliasing the two here makes that cast an identity.
typedef cx_sha256_t cx_hash_t;

static inline int cx_sha256_init(cx_sha256_t *hash) {
    mock_sha256_init(&hash->impl);
    return CX_OK;
}

static inline cx_err_t cx_hash_update(cx_hash_t *hash, const uint8_t *in, size_t in_len) {
    mock_sha256_update(&hash->impl, in, in_len);
    return CX_OK;
}

static inline cx_err_t cx_hash_final(cx_hash_t *hash, uint8_t *digest) {
    mock_sha256_final(&hash->impl, digest);
    return CX_OK;
}

#define CX_ASSERT(call)                \
    do {                               \
        cx_err_t _assert_err = (call); \
        assert(_assert_err == CX_OK);  \
    } while (0)
