// #include <cx.h>

#include "common_byte_strings.h"

#include "cx.h"
#include "sol/printer.h"
#include "ed25519_helpers.h"

static bool is_on_curve_internal(const uint8_t compressed_point[PUBKEY_LENGTH]) {
    cx_ecpoint_t point;
    cx_err_t result;
    bool is_on_curve;
    uint8_t compressed_point_tmp[PUBKEY_LENGTH];

    memset(&point, 0, sizeof(point));
    result = cx_ecpoint_alloc(&point, CX_CURVE_Ed25519);
    if (result != CX_OK) {
        PRINTF("cx_ecpoint_alloc failed %x\n", result);
        return false;
    }

    // cx_decode_coord may hide the flag sign byte from the compressed point, we make a local copy
    memcpy(compressed_point_tmp, compressed_point, PUBKEY_LENGTH);
    int sign = cx_decode_coord(compressed_point_tmp, PUBKEY_LENGTH);
    result = cx_ecpoint_decompress(&point, compressed_point_tmp, PUBKEY_LENGTH, sign);
    if (result != CX_OK) {
        PRINTF("cx_ecpoint_decompress failed %x\n", result);
        return false;
    }

    result = cx_ecpoint_is_on_curve(&point, &is_on_curve);
    if (result != CX_OK) {
        PRINTF("cx_ecpoint_is_on_curve failed %x\n", result);
        return false;
    }
    return is_on_curve;
}

static bool is_on_curve(const uint8_t compressed_point[PUBKEY_LENGTH]) {
    CX_ASSERT(cx_bn_lock(PUBKEY_LENGTH, 0));
    bool is_on_curve = is_on_curve_internal(compressed_point);
    if (cx_bn_is_locked()) {
        CX_ASSERT(cx_bn_unlock());
    }

    return is_on_curve;
}

static int derivate_ata_candidate(const uint8_t *owner_account,
                                  const uint8_t *mint_account,
                                  uint8_t nonce,
                                  bool is_token_2022,
                                  uint8_t (*derived_ata_candidate)[PUBKEY_LENGTH]) {
    cx_sha256_t hash_ctx;
    cx_sha256_init(&hash_ctx);
    if (cx_hash_no_throw((cx_hash_t *) &hash_ctx, 0, owner_account, PUBKEY_LENGTH, NULL, 0) !=
        CX_OK) {
        PRINTF("ERROR: Failed to hash owner account\n");
        return -1;
    }

    uint8_t program_id_spl_token[32] = {PROGRAM_ID_SPL_TOKEN};
    uint8_t program_id_spl_token_2022[32] = {PROGRAM_ID_SPL_TOKEN_2022};
    uint8_t *program_id;
    if (is_token_2022) {
        program_id = program_id_spl_token_2022;
    } else {
        program_id = program_id_spl_token;
    }
    if (cx_hash_no_throw((cx_hash_t *) &hash_ctx, 0, program_id, PUBKEY_LENGTH, NULL, 0) != CX_OK) {
        PRINTF("ERROR: Failed to hash program ID\n");
        return -1;
    }

    if (cx_hash_no_throw((cx_hash_t *) &hash_ctx, 0, mint_account, PUBKEY_LENGTH, NULL, 0) !=
        CX_OK) {
        PRINTF("ERROR: Failed to hash mint account\n");
        return -1;
    }

    if (cx_hash_no_throw((cx_hash_t *) &hash_ctx, 0, &nonce, sizeof(nonce), NULL, 0) != CX_OK) {
        PRINTF("ERROR: Failed to hash nonce\n");
        return -1;
    }

    uint8_t program_id_spl_associated_token_account[32] = {PROGRAM_ID_SPL_ASSOCIATED_TOKEN_ACCOUNT};
    if (cx_hash_no_throw((cx_hash_t *) &hash_ctx,
                         0,
                         program_id_spl_associated_token_account,
                         PUBKEY_LENGTH,
                         NULL,
                         0) != CX_OK) {
        PRINTF("ERROR: Failed to hash program ID\n");
        return -1;
    }

    const char program_derived_address[] = "ProgramDerivedAddress";
    if (cx_hash_no_throw((cx_hash_t *) &hash_ctx,
                         0,
                         (const uint8_t *) program_derived_address,
                         strlen(program_derived_address),
                         NULL,
                         0) != CX_OK) {
        PRINTF("ERROR: Failed to hash ProgramDerivedAddress string\n");
        return -1;
    }

    if (cx_hash_no_throw((cx_hash_t *) &hash_ctx,
                         CX_LAST,
                         NULL,
                         0,
                         *derived_ata_candidate,
                         PUBKEY_LENGTH) != CX_OK) {
        PRINTF("ERROR: Failed to finalize hash\n");
        return -1;
    }

    return 0;
}

bool validate_associated_token_address(const uint8_t owner_account[PUBKEY_LENGTH],
                                       const uint8_t mint_account[PUBKEY_LENGTH],
                                       const uint8_t provided_ata[PUBKEY_LENGTH],
                                       bool is_token_2022) {
    uint8_t derived_ata[PUBKEY_LENGTH];

    // Start with the maximum nonce value
    // As this is how official libraries do, we minimize the number of checks of valid case
    uint8_t nonce = 255;

    PRINTF("Trying to validate provided_ata %.*H\n", PUBKEY_LENGTH, provided_ata);
    while (nonce > 0) {
        // Worst case scenario is 255 hash + 255 memcmp. The performance hit is not noticeable.
        if (derivate_ata_candidate(owner_account,
                                   mint_account,
                                   nonce,
                                   is_token_2022,
                                   &derived_ata) != 0) {
            PRINTF("Error derivate_ata_candidate for nonce %d\n", nonce);
            return false;
        }
        // Compare the derived ATA with the provided ATA
        PRINTF("derived_ata %.*H with nonce%d\n", PUBKEY_LENGTH, derived_ata, nonce);
        nonce--;

        if (memcmp(derived_ata, provided_ata, PUBKEY_LENGTH) == 0) {
            PRINTF("Successful ATA match\n");
            // A valid ATA cannot be on the curve, check that the one we received is valid
            // Official online libraries do it before the memcmp
            // we do it after to do it at most once
            if (is_on_curve(derived_ata)) {
                PRINTF("Error, derived ATA is on the curve\n");
                return false;
            } else {
                return true;
            }
        }
    }

    // We exhausted all nonces without matching the provided ATA
    PRINTF("ERROR: Unable to find a valid nonce for ATA derivation\n");
    return false;
}
