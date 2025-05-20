#pragma once

#include "tlv_library.h"
#include "buffer.h"

// TLV use cases API on top of the TLV library

// SDK implementation of the following specification
// https://ledgerhq.atlassian.net/wiki/spaces/TrustServices/pages/3736863735/LNS+Arch+Nano+Trusted+Names+Descriptor+Format+APIs#TLV-description

#define TRUSTED_NAME_STRINGS_MAX_SIZE 44
#define NFT_ID_SIZE                   32

#define SEMVER_SIZE 3

typedef enum tlv_structure_type_e {
    TLV_STRUCTURE_TYPE_TRUSTED_NAME = 0x03,
} tlv_structure_type_t;

typedef enum tlv_trusted_name_type_e {
    TLV_TRUSTED_NAME_TYPE_EOA = 0x01,
    TLV_TRUSTED_NAME_TYPE_SMART_CONTRACT = 0x02,
    TLV_TRUSTED_NAME_TYPE_COLLECTION = 0x03,
    TLV_TRUSTED_NAME_TYPE_TOKEN = 0x04,
    TLV_TRUSTED_NAME_TYPE_WALLET = 0x05,
    TLV_TRUSTED_NAME_TYPE_CONTEXT_ADDRESS = 0x06,
} tlv_trusted_name_type_t;

typedef enum tlv_trusted_name_source_e {
    TLV_TRUSTED_NAME_SOURCE_LOCAL_ADDRESS_BOOK = 0x00,
    TLV_TRUSTED_NAME_SOURCE_CRYPTO_ASSET_LIST = 0x01,
    TLV_TRUSTED_NAME_SOURCE_ENS = 0x02,
    TLV_TRUSTED_NAME_SOURCE_UNSTOPPABLE_DOMAINS = 0x03,
    TLV_TRUSTED_NAME_SOURCE_FREENAME = 0x04,
    TLV_TRUSTED_NAME_SOURCE_DNS = 0x05,
    TLV_TRUSTED_NAME_SOURCE_DYNAMIC_RESOLVER = 0x06,
} tlv_trusted_name_source_t;

typedef enum tlv_trusted_name_signer_key_id_e {
    TLV_TRUSTED_NAME_SIGNER_KEY_ID_TEST = 0x00,
    TLV_TRUSTED_NAME_SIGNER_KEY_ID_PROD = 0x07,
} tlv_trusted_name_signer_key_id_t;

typedef enum tlv_trusted_name_signer_algorithm_e {
    TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_SHA256 = 0x01,
    TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_SHA3_256 = 0x02,
    TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_KECCAK_256 = 0x03,
    TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_RIPEMD160 = 0x04,
    TLV_TRUSTED_NAME_SIGNER_ALGORITHM_ECDSA_SHA512 = 0x16,
    TLV_TRUSTED_NAME_SIGNER_ALGORITHM_EDDSA_KECCAK_256 = 0x17,
    TLV_TRUSTED_NAME_SIGNER_ALGORITHM_EDDSA_SHA3_256 = 0x18,
} tlv_trusted_name_signer_algorithm_t;

typedef struct semver_s {
    uint8_t major;
    uint8_t minor;
    uint16_t patch;
} semver_t;

typedef struct tlv_trusted_name_out_s {
    uint8_t version;
    uint8_t trusted_name_type;
    uint8_t trusted_name_source;
    buffer_t trusted_name;
    uint64_t chain_id;
    buffer_t address;
    buffer_t nft_id;
    buffer_t source_contract;
    uint32_t challenge;
    semver_t not_valid_after;

    // Flag optional tags reception
    bool nft_id_received;
    bool source_contract_received;
    bool challenge_received;
    bool not_valid_after_received;
} tlv_trusted_name_out_t;

typedef enum tlv_trusted_name_status_e {
    TLV_TRUSTED_NAME_SUCCESS = 0,
    TLV_TRUSTED_NAME_PARSING_ERROR = 1,
    TLV_TRUSTED_NAME_MISSING_STRUCTURE_TAG = 2,
    TLV_TRUSTED_NAME_WRONG_TYPE = 3,
    TLV_TRUSTED_NAME_MISSING_TAG = 4,
    TLV_TRUSTED_NAME_UNKNOWN_VERSION = 5,
    TLV_TRUSTED_NAME_UNSUPPORTED_TAG = 6,
    TLV_TRUSTED_NAME_WRONG_KEY_ID = 7,
    TLV_TRUSTED_NAME_HASH_FAILED = 8,
    // Combined with check_signature_with_pki_status_t
    TLV_TRUSTED_NAME_SIGNATURE_ERROR = 0x80,
} tlv_trusted_name_status_t;

tlv_trusted_name_status_t tlv_use_case_trusted_name(const buffer_t *payload,
                                                    tlv_trusted_name_out_t *output);
