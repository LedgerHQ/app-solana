#include <os.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "globals.h"
#include "utils.h"
#include "handle_provide_trusted_info.h"
#include "handle_get_challenge.h"

#include "sol/printer.h"

#include "os_pki.h"

#include "ledger_pki.h"

#define TYPE_ADDRESS      0x06
#define TYPE_DYN_RESOLVER 0x06

#define STRUCT_TYPE_TRUSTED_NAME 0x03
#define ALGO_SECP256K1           1

#define DER_LONG_FORM_FLAG        0x80  // 8th bit set
#define DER_FIRST_BYTE_VALUE_MASK 0x7f

#define INT256_LENGTH 32

typedef enum { TLV_TAG, TLV_LENGTH, TLV_VALUE } e_tlv_step;

// This enum needs to be ordered the same way as the e_tlv_tag one !
typedef enum {
    STRUCT_TYPE_RCV_BIT = 0,
    STRUCT_VERSION_RCV_BIT,
    TRUSTED_NAME_TYPE_RCV_BIT,
    TRUSTED_NAME_SOURCE_RCV_BIT,
    TRUSTED_NAME_RCV_BIT,
    CHAIN_ID_RCV_BIT,
    ADDRESS_RCV_BIT,
    SOURCE_CONTRACT_RCV_BIT,
    CHALLENGE_RCV_BIT,
    SIGNER_KEY_ID_RCV_BIT,
    SIGNER_ALGO_RCV_BIT,
    SIGNATURE_RCV_BIT,
} e_tlv_rcv_bit;

#define RCV_FLAG(a) (1 << a)

/*
trusted_name_descriptor =   tlv(TAG_STRUCTURE_TYPE, u8(TYPE_TRUSTED_NAME))  3 bytes +
                        &   tlv(TAG_VERSION, u8(0x02))                      3 bytes +
                        &   tlv(TAG_TRUSTED_NAME_TYPE, 0x06)                3 bytes +
                        &   tlv(TAG_TRUSTED_NAME_SOURCE, 0x06)              3 bytes +
                        &   tlv(TAG_TRUSTED_NAME, trusted_name)             2 + 44 bytes +
                        &   tlv(TAG_CHAIN_ID, chain_id)                     2 + 8 bytes +
                        &   tlv(TAG_ADDRESS, address)                       2 + 44 bytes +
                        &   tlv(TAG_SOURCE_CONTRACT, source_contract)*      2 + 44 bytes +
                        &   tlv(TAG_CHALLENGE, challenge)                   2 + 4 bytes +
                        &   tlv(TAG_SIGNER_KEY_ID, key_id)                  2 + 2 bytes +
                        &   tlv(TAG_SIGNER_ALGORITHM, signature_algorithm)  2 + 1 byte +
                        &   tlv(TAG_SIGNATURE, signature(~,~))              2 + 72 bytes => 247

T  L  V
01 01 03                                                                TAG_STRUCTURE_TYPE
02 01 02                                                                TAG_VERSION
70 01 06                                                                TAG_TRUSTED_NAME_TYPE
71 01 06                                                                TAG_TRUSTED_NAME_SOURCE
20 20 276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9db  TAG_TRUSTED_NAME
23 01 65                                                                TAG_CHAIN_ID
22 20 606501b302e1801892f80a2979f585f8855d0f2034790a2455f744fac503d7b5  TAG_ADDRESS
73 20 c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61  TAG_SOURCE_CONTRACT
12 04 deadbeef                                                          TAG_CHALLENGE
13 01 03                                                                TAG_SIGNER_KEY_ID
14 01 01                                                                TAG_SIGNER_ALGORITHM
15 47 30..2e


01 01 03
02 01 02
70 01 06
71 01 06
20 20 276497BA0BB8659172B72EDD8C66E18F561764D9C86A610A3A7E0F79C0BAF9DB
23 01 65
22 20 606501B302E1801892F80A2979F585F8855D0F2034790A2455F744FAC503D7B5
73 20 C6FA7AF3BEDBAD3A3D65F36AABC97431B1BBE4C2D2F6E0E47CA60203452F5D61
12 04 DEADBEEF
13 01 00
14 01 01
15 47 30..CF

*/

#define TLV_BUFFER_LENGTH 255 /* >= 247, APDU max payload */
static uint8_t tlv_buffer[TLV_BUFFER_LENGTH] = {0};

typedef enum {
    STRUCT_TYPE = 0x01,
    STRUCT_VERSION = 0x02,
    TRUSTED_NAME_TYPE = 0x70,
    TRUSTED_NAME_SOURCE = 0x71,
    TRUSTED_NAME = 0x20,
    CHAIN_ID = 0x23,
    ADDRESS = 0x22,
    SOURCE_CONTRACT = 0x73,
    CHALLENGE = 0x12,
    SIGNER_KEY_ID = 0x13,
    SIGNER_ALGO = 0x14,
    SIGNATURE = 0x15,
} e_tlv_tag;

typedef enum { KEY_ID_TEST = 0x00, KEY_ID_PROD = 0x03 } e_key_id;

typedef struct {
    uint8_t *buf;
    uint8_t size;
    uint8_t expected_size;
} s_tlv_payload;

typedef struct {
    e_tlv_tag tag;
    uint8_t length;
    const uint8_t *value;
} s_tlv_data;

typedef struct {
    uint32_t rcv_flags;
    bool valid;
    uint8_t struct_version;
    uint8_t token_account[MAX_ADDRESS_LENGTH + 1];
    uint8_t *owner;
    uint8_t spl_token[MAX_ADDRESS_LENGTH + 1];
    uint64_t chain_id;
    uint8_t name_type;
    uint8_t name_source;
} s_trusted_name_info;

typedef struct {
    e_key_id key_id;
    uint8_t input_sig_size;
    const uint8_t *input_sig;
    cx_sha256_t hash_ctx;
} s_sig_ctx;

typedef bool(t_tlv_handler)(const s_tlv_data *data,
                            s_trusted_name_info *trusted_name_info,
                            s_sig_ctx *sig_ctx);

typedef struct {
    e_tlv_tag tag;
    t_tlv_handler *func;
    e_tlv_rcv_bit rcv_bit;
} s_tlv_handler;

static s_tlv_payload g_tlv_payload = {0};
static s_trusted_name_info g_trusted_name_info = {0};

uint8_t g_trusted_token_account_owner_pubkey[MAX_ADDRESS_LENGTH + 1] = {0};
bool g_trusted_token_account_owner_pubkey_set = false;

/**
 * Get uint from tlv data
 *
 * Get an unsigned integer from variable length tlv data (up to 4 bytes)
 *
 * @param[in] data tlv data
 * @param[out] value the returned value
 * @return whether it was successful
 */
static bool get_uint_from_data(const s_tlv_data *data, uint32_t *value) {
    uint8_t size_diff;
    uint8_t buffer[sizeof(uint32_t)];

    if (data->length > sizeof(buffer)) {
        PRINTF("Unexpectedly long value (%u bytes) for tag 0x%x\n", data->length, data->tag);
        return false;
    }
    size_diff = sizeof(buffer) - data->length;
    memset(buffer, 0, size_diff);
    memcpy(buffer + size_diff, data->value, data->length);
    *value = U4BE(buffer, 0);
    return true;
}

/**
 * Handler for tag \ref STRUCT_TYPE
 *
 * @param[in] data the tlv data
 * @param[] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_struct_type(const s_tlv_data *data,
                               s_trusted_name_info *trusted_name_info,
                               s_sig_ctx *sig_ctx) {
    uint32_t value;

    (void) trusted_name_info;
    (void) sig_ctx;
    if (!get_uint_from_data(data, &value)) {
        return false;
    }
    return (value == STRUCT_TYPE_TRUSTED_NAME);
}

/**
 * Handler for tag \ref STRUCT_VERSION
 *
 * @param[in] data the tlv data
 * @param[out] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_struct_version(const s_tlv_data *data,
                                  s_trusted_name_info *trusted_name_info,
                                  s_sig_ctx *sig_ctx) {
    uint32_t value;

    (void) sig_ctx;
    if (!get_uint_from_data(data, &value) || (value > UINT8_MAX)) {
        return false;
    }
    trusted_name_info->struct_version = value;
    return true;
}

/**
 * Handler for tag \ref CHALLENGE
 *
 * @param[in] data the tlv data
 * @param[] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_challenge(const s_tlv_data *data,
                             s_trusted_name_info *trusted_name_info,
                             s_sig_ctx *sig_ctx) {
    uint32_t value;
    (void) trusted_name_info;
    (void) sig_ctx;

    if (!get_uint_from_data(data, &value)) {
        return false;
    }
    return (value == get_challenge());
}

/**
 * Handler for tag \ref SIGNER_KEY_ID
 *
 * @param[in] data the tlv data
 * @param[] trusted_name_info the trusted name information
 * @param[out] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_sign_key_id(const s_tlv_data *data,
                               s_trusted_name_info *trusted_name_info,
                               s_sig_ctx *sig_ctx) {
    uint32_t value;
    (void) trusted_name_info;

    if (!get_uint_from_data(data, &value) || (value > UINT8_MAX)) {
        return false;
    }
    sig_ctx->key_id = value;
    return true;
}

/**
 * Handler for tag \ref SIGNER_ALGO
 *
 * @param[in] data the tlv data
 * @param[] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_sign_algo(const s_tlv_data *data,
                             s_trusted_name_info *trusted_name_info,
                             s_sig_ctx *sig_ctx) {
    uint32_t value;

    (void) trusted_name_info;
    (void) sig_ctx;
    if (!get_uint_from_data(data, &value)) {
        return false;
    }
    return (value == ALGO_SECP256K1);
}

/**
 * Handler for tag \ref SIGNATURE
 *
 * @param[in] data the tlv data
 * @param[] trusted_name_info the trusted name information
 * @param[out] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_signature(const s_tlv_data *data,
                             s_trusted_name_info *trusted_name_info,
                             s_sig_ctx *sig_ctx) {
    (void) trusted_name_info;
    sig_ctx->input_sig_size = data->length;
    sig_ctx->input_sig = data->value;
    return true;
}

/**
 * Handler for tag \ref SOURCE_CONTRACT
 *
 * @param[in] data the tlv data
 * @param[] trusted_name_info the trusted name information
 * @param[out] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_source_contract(const s_tlv_data *data,
                                   s_trusted_name_info *trusted_name_info,
                                   s_sig_ctx *sig_ctx) {
    (void) sig_ctx;
    if (data->length > MAX_ADDRESS_LENGTH) {
        PRINTF("SPL Token address too long! (%u)\n", data->length);
        return false;
    }

    memcpy(trusted_name_info->spl_token, data->value, data->length);

    trusted_name_info->spl_token[data->length] = '\0';
    return true;
}

/**
 * Tests if the given account name character is valid (in our subset of allowed characters)
 *
 * @param[in] c given character
 * @return whether the character is valid
 */
/*static bool is_valid_account_character(char c) {
    if (isalpha((int) c)) {
        if (!islower((int) c)) {
            return false;
        }
    } else if (!isdigit((int) c)) {
        switch (c) {
            case '.':
            case '-':
            case '_':
                break;
            default:
                return false;
        }
    }
    return true;
}*/

/**
 * Handler for tag \ref TRUSTED_NAME
 *
 * @param[in] data the tlv data
 * @param[out] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_trusted_name(const s_tlv_data *data,
                                s_trusted_name_info *trusted_name_info,
                                s_sig_ctx *sig_ctx) {
    (void) sig_ctx;
    if (data->length > MAX_ADDRESS_LENGTH) {
        PRINTF("Token Account address too long! (%u)\n", data->length);
        return false;
    }

    memcpy(trusted_name_info->token_account, data->value, data->length);

    trusted_name_info->token_account[data->length] = '\0';
    return true;
}

/**
 * Handler for tag \ref ADDRESS
 *
 * @param[in] data the tlv data
 * @param[out] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_address(const s_tlv_data *data,
                           s_trusted_name_info *trusted_name_info,
                           s_sig_ctx *sig_ctx) {
    (void) sig_ctx;
    if (data->length > MAX_ADDRESS_LENGTH) {
        PRINTF("Address too long! (%u)\n", data->length);
        return false;
    }
    memcpy(trusted_name_info->owner, data->value, data->length);
    trusted_name_info->owner[data->length] = '\0';
    return true;
}

/**
 * Handler for tag \ref CHAIN_ID
 *
 * @param[in] data the tlv data
 * @param[out] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_chain_id(const s_tlv_data *data,
                            s_trusted_name_info *trusted_name_info,
                            s_sig_ctx *sig_ctx) {
    (void) sig_ctx;
    bool res = false;

    switch (data->length) {
        case 1: {
            trusted_name_info->chain_id = data->value[0];
            res = true;
            break;
        }
        case 2: {
            trusted_name_info->chain_id = (data->value[0] << 8) | data->value[1];
            res = true;
            break;
        }
        default:
            PRINTF("Error while parsing chain ID: length = %d\n", data->length);
    }
    return res;
}

/**
 * Handler for tag \ref TRUSTED_NAME_TYPE
 *
 * @param[in] data the tlv data
 * @param[out] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_trusted_name_type(const s_tlv_data *data,
                                     s_trusted_name_info *trusted_name_info,
                                     s_sig_ctx *sig_ctx) {
    uint32_t value;

    (void) trusted_name_info;
    (void) sig_ctx;
    if (!get_uint_from_data(data, &value) || (value > UINT8_MAX)) {
        return false;
    }

    if (value != TYPE_ADDRESS) {
        PRINTF("Error: unsupported trusted name type (%u)!\n", value);
        return false;
    }
    trusted_name_info->name_type = value;
    return true;
}

/**
 * Handler for tag \ref TRUSTED_NAME_SOURCE
 *
 * @param[in] data the tlv data
 * @param[out] trusted_name_info the trusted name information
 * @param[] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_trusted_name_source(const s_tlv_data *data,
                                       s_trusted_name_info *trusted_name_info,
                                       s_sig_ctx *sig_ctx) {
    uint32_t value;

    (void) trusted_name_info;
    (void) sig_ctx;
    if (!get_uint_from_data(data, &value) || (value > UINT8_MAX)) {
        return false;
    }

    if (value != TYPE_DYN_RESOLVER) {
        PRINTF("Error: unsupported trusted name source (%u)!\n", value);
        return false;
    }

    trusted_name_info->name_source = value;
    return true;
}

/**
 * Verify the signature context
 *
 * Verify the SHA-256 hash of the payload against the public key
 *
 * @param[in] sig_ctx the signature context
 * @return whether it was successful
 */
static bool verify_signature(const s_sig_ctx *sig_ctx) {
    uint8_t hash[INT256_LENGTH];
    cx_err_t error = CX_INTERNAL_ERROR;

#ifdef HAVE_TRUSTED_NAME_TEST
    e_key_id valid_key_id = KEY_ID_TEST;
#else
    e_key_id valid_key_id = KEY_ID_PROD;
#endif
    bool ret_code = false;

    if (sig_ctx->key_id != valid_key_id) {
        PRINTF("Error: Unknown metadata key ID %u\n", sig_ctx->key_id);
        return false;
    }

    CX_CHECK(
        cx_hash_no_throw((cx_hash_t *) &sig_ctx->hash_ctx, CX_LAST, NULL, 0, hash, INT256_LENGTH));

    CX_CHECK(check_signature_with_pubkey("Trusted Name",
                                         hash,
                                         sizeof(hash),
                                         CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME,
                                         (uint8_t *) (sig_ctx->input_sig),
                                         sig_ctx->input_sig_size));

    ret_code = true;
end:
    return ret_code;
}

/**
 * Calls the proper handler for the given TLV data
 *
 * Checks if there is a proper handler function for the given TLV tag and then calls it
 *
 * @param[in] handlers list of tag / handler function pairs
 * @param[in] handler_count number of handlers
 * @param[in] data the TLV data
 * @param[out] trusted_name_info the trusted name information
 * @param[out] sig_ctx the signature context
 * @return whether it was successful
 */
static bool handle_tlv_data(s_tlv_handler *handlers,
                            int handler_count,
                            const s_tlv_data *data,
                            s_trusted_name_info *trusted_name_info,
                            s_sig_ctx *sig_ctx) {
    t_tlv_handler *fptr;

    // check if a handler exists for this tag
    for (int idx = 0; idx < handler_count; ++idx) {
        if (handlers[idx].tag == data->tag) {
            trusted_name_info->rcv_flags |= RCV_FLAG(handlers[idx].rcv_bit);
            fptr = PIC(handlers[idx].func);
            if (!(*fptr)(data, trusted_name_info, sig_ctx)) {
                PRINTF("Error while handling tag 0x%x\n", handlers[idx].tag);
                return false;
            }
            break;
        }
    }
    return true;
}

/**
 * Verify the validity of the received trusted struct
 *
 * @param[in] trusted_name_info the trusted name information
 * @return whether the struct is valid
 */
static bool verify_struct(const s_trusted_name_info *trusted_name_info) {
    uint32_t required_flags;

    if (!(RCV_FLAG(STRUCT_VERSION_RCV_BIT) & trusted_name_info->rcv_flags)) {
        PRINTF("Error: no struct version specified!\n");
        return false;
    }
    required_flags = RCV_FLAG(STRUCT_TYPE_RCV_BIT) | RCV_FLAG(STRUCT_VERSION_RCV_BIT) |
                     RCV_FLAG(TRUSTED_NAME_TYPE_RCV_BIT) | RCV_FLAG(TRUSTED_NAME_SOURCE_RCV_BIT) |
                     RCV_FLAG(TRUSTED_NAME_RCV_BIT) | RCV_FLAG(CHAIN_ID_RCV_BIT) |
                     RCV_FLAG(ADDRESS_RCV_BIT) | RCV_FLAG(SOURCE_CONTRACT_RCV_BIT) |
                     RCV_FLAG(CHALLENGE_RCV_BIT) | RCV_FLAG(SIGNER_KEY_ID_RCV_BIT) |
                     RCV_FLAG(SIGNER_ALGO_RCV_BIT) | RCV_FLAG(SIGNATURE_RCV_BIT);

    switch (trusted_name_info->struct_version) {
        case 2:
            if ((trusted_name_info->rcv_flags & required_flags) != required_flags) {
                PRINTF("Error: missing required fields in struct version 2\n");
                return false;
            }
            switch (trusted_name_info->name_type) {
                case TYPE_ADDRESS:
                    if (trusted_name_info->name_source != TYPE_DYN_RESOLVER) {
                        PRINTF("Error: unsupported trusted name source (%u)!\n",
                               trusted_name_info->name_source);
                        return false;
                    }
                    break;
                default:
                    PRINTF("Error: unsupported trusted name type (%u)!\n",
                           trusted_name_info->name_type);
                    return false;
            }
            break;
        default:
            PRINTF("Error: unsupported trusted name struct version (%u) !\n",
                   trusted_name_info->struct_version);
            return false;
    }
    return true;
}

/** Parse DER-encoded value
 *
 * Parses a DER-encoded value (up to 4 bytes long)
 * https://en.wikipedia.org/wiki/X.690
 *
 * @param[in] payload the TLV payload
 * @param[in,out] offset the payload offset
 * @param[out] value the parsed value
 * @return whether it was successful
 */
static bool parse_der_value(const s_tlv_payload *payload, size_t *offset, uint32_t *value) {
    bool ret = false;
    uint8_t byte_length;
    uint8_t buf[sizeof(*value)];

    if (value != NULL) {
        if (payload->buf[*offset] & DER_LONG_FORM_FLAG) {  // long form
            byte_length = payload->buf[*offset] & DER_FIRST_BYTE_VALUE_MASK;
            *offset += 1;
            if ((*offset + byte_length) > payload->size) {
                PRINTF("TLV payload too small for DER encoded value\n");
            } else {
                if (byte_length > sizeof(buf) || byte_length == 0) {
                    PRINTF("Unexpectedly long DER-encoded value (%u bytes)\n", byte_length);
                } else {
                    memset(buf, 0, (sizeof(buf) - byte_length));
                    memcpy(buf + (sizeof(buf) - byte_length), &payload->buf[*offset], byte_length);
                    *value = U4BE(buf, 0);
                    *offset += byte_length;
                    ret = true;
                }
            }
        } else {  // short form
            *value = payload->buf[*offset];
            *offset += 1;
            ret = true;
        }
    }
    return ret;
}

/**
 * Get DER-encoded value as an uint8
 *
 * Parses the value and checks if it fits in the given \ref uint8_t value
 *
 * @param[in] payload the TLV payload
 * @param[in,out] offset
 * @param[out] value the parsed value
 * @return whether it was successful
 */
static bool get_der_value_as_uint8(const s_tlv_payload *payload, size_t *offset, uint8_t *value) {
    bool ret = false;
    uint32_t tmp_value;

    if (value != NULL) {
        if (!parse_der_value(payload, offset, &tmp_value)) {
        } else {
            if (tmp_value <= UINT8_MAX) {
                *value = tmp_value;
                ret = true;
            } else {
                PRINTF("TLV DER-encoded value larger than 8 bits\n");
            }
        }
    }
    return ret;
}

/**
 * Parse the TLV payload
 *
 * Does the TLV parsing but also the SHA-256 hash of the payload.
 *
 * @param[in] payload the raw TLV payload
 * @param[out] trusted_name_info the trusted name information
 * @param[out] sig_ctx the signature context
 * @return whether it was successful
 */
static bool parse_tlv(const s_tlv_payload *payload,
                      s_trusted_name_info *trusted_name_info,
                      s_sig_ctx *sig_ctx) {
    s_tlv_handler handlers[] = {
        {.tag = STRUCT_TYPE, .func = &handle_struct_type},
        {.tag = STRUCT_VERSION, .func = &handle_struct_version},
        {.tag = TRUSTED_NAME_TYPE, .func = &handle_trusted_name_type},
        {.tag = TRUSTED_NAME_SOURCE, .func = &handle_trusted_name_source},
        {.tag = TRUSTED_NAME, .func = &handle_trusted_name},
        {.tag = CHAIN_ID, .func = &handle_chain_id},
        {.tag = ADDRESS, .func = &handle_address},
        {.tag = SOURCE_CONTRACT, .func = &handle_source_contract},
        {.tag = CHALLENGE, .func = &handle_challenge},
        {.tag = SIGNER_KEY_ID, .func = &handle_sign_key_id},
        {.tag = SIGNER_ALGO, .func = &handle_sign_algo},
        {.tag = SIGNATURE, .func = &handle_signature},
    };
    e_tlv_step step = TLV_TAG;
    s_tlv_data data;
    size_t offset = 0;
    size_t tag_start_off;

    for (size_t i = 0; i < ARRAYLEN(handlers); ++i) handlers[i].rcv_bit = i;
    cx_sha256_init(&sig_ctx->hash_ctx);
    // handle TLV payload
    while (offset < payload->size) {
        switch (step) {
            case TLV_TAG:
                tag_start_off = offset;
                if (!get_der_value_as_uint8(payload, &offset, &data.tag)) {
                    return false;
                }
                step = TLV_LENGTH;
                break;

            case TLV_LENGTH:
                if (!get_der_value_as_uint8(payload, &offset, &data.length)) {
                    return false;
                }
                step = TLV_VALUE;
                break;

            case TLV_VALUE:
                if ((offset + data.length) > payload->size) {
                    PRINTF("Error: value would go beyond the TLV payload!\n");
                    return false;
                }
                data.value = &payload->buf[offset];
                if (!handle_tlv_data(handlers,
                                     (sizeof(handlers) / sizeof(handlers[0])),
                                     &data,
                                     trusted_name_info,
                                     sig_ctx)) {
                    return false;
                }
                offset += data.length;
                if (data.tag != SIGNATURE) {  // the signature wasn't computed on itself
                    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &sig_ctx->hash_ctx,
                                               0,
                                               &payload->buf[tag_start_off],
                                               (offset - tag_start_off),
                                               NULL,
                                               0));
                }
                step = TLV_TAG;
                break;

            default:
                return false;
        }
    }
    if (step != TLV_TAG) {
        PRINTF("Error: unexpected data at the end of the TLV payload!\n");
        return false;
    }
    return verify_struct(trusted_name_info);
}

/**
 * Deallocate and unassign TLV payload
 *
 * @param[in] payload payload structure
 */
static void free_payload(s_tlv_payload *payload) {
    memset(tlv_buffer, 0, sizeof(tlv_buffer));
    memset(payload, 0, sizeof(*payload));
}

static bool init_tlv_payload(uint8_t length, s_tlv_payload *payload) {
    // check if no payload is already in memory
    if (payload->buf != NULL) {
        free_payload(payload);
        return false;
    }

    payload->buf = tlv_buffer;
    payload->expected_size = length;

    return true;
}

/**
 * Handle provide trusted info APDU
 *
 * @param[in] is_first_chunk first APDU instruction parameter
 * @param[in] data APDU payload
 * @param[in] length payload size
 */
void handle_provide_trusted_info(void) {
    s_sig_ctx sig_ctx;

    uint8_t *data = G_command.message;
    uint8_t data_length = G_command.message_length;

    PRINTF("Received chunk of trusted info, length = %d\n", data_length);
    if (!init_tlv_payload(data_length, &g_tlv_payload)) {
        free_payload(&g_tlv_payload);
        PRINTF("Error while initializing TLV payload\n");
        THROW(ApduReplySolanaInvalidTrustedInfo);
    }

    PRINTF("Expected size of trusted info: %d\n", g_tlv_payload.expected_size);

    if ((g_tlv_payload.size + data_length) > g_tlv_payload.expected_size) {
        free_payload(&g_tlv_payload);
        PRINTF("TLV payload size mismatch!\n");
        THROW(ApduReplySolanaInvalidTrustedInfo);
    }
    // feed into tlv payload
    memcpy(g_tlv_payload.buf + g_tlv_payload.size, data, data_length);
    g_tlv_payload.size += data_length;

    PRINTF("Received %d bytes of trusted info\n", g_tlv_payload.size);

    // everything has been received
    if (g_tlv_payload.size == g_tlv_payload.expected_size) {
        g_trusted_name_info.owner = g_trusted_token_account_owner_pubkey;
        g_trusted_token_account_owner_pubkey_set = true;
        if (!parse_tlv(&g_tlv_payload, &g_trusted_name_info, &sig_ctx) ||
            !verify_signature(&sig_ctx)) {
            free_payload(&g_tlv_payload);
            roll_challenge();  // prevent brute-force guesses
            g_trusted_name_info.rcv_flags = 0;
            memset(g_trusted_token_account_owner_pubkey,
                   0,
                   sizeof(g_trusted_token_account_owner_pubkey));
            g_trusted_token_account_owner_pubkey_set = false;
            THROW(ApduReplySolanaInvalidTrustedInfo);
        }

        PRINTF("Token account : %s owned by %s\n",
               g_trusted_name_info.token_account,
               g_trusted_token_account_owner_pubkey);

        free_payload(&g_tlv_payload);
        roll_challenge();  // prevent replays
        THROW(ApduReplySuccess);
    }
    THROW(ApduReplySolanaInvalidTrustedInfo);
}