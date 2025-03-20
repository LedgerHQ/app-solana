#pragma once

#ifdef HAVE_SDK_TLV_PARSER

#include <os.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#include "tlv.h"

/** Common TLV parser for Ledger embedded applications
 * To use it in your application:
 *     - enable the HAVE_SDK_TLV_PARSER flag in your Makefile
 *
 *     - write a "tlv.h" file containing:
 *         - a 'tlv_out_t' structure that will be given to your handlers. Its content is up to you
 *
 *         - a 'TLV_TAGS' X-Macro of your tags, example:
 #define TLV_TAGS \
    X(MY_TAG_1, 0x01) \
    X(MY_TAG_2, 0x09) \
    X(ANOTHER_TAG, 0xcafe)

 *     - include "tlv_utils.h"
 *         - to have the enum of the X-Macro tags expanded.
 *             - In this example MY_TAG_1 = 0x01, MY_TAG_2 = 0x09 and so on
 *         - to have the TAGS_COUNT automatically defined
 *         - to access the parse_tlv() top function
 *         - to call get_tag_flag() to know which tags were received
 *         - to use the get_X_from_tlv_data() helpers
 */

#define INT256_LENGTH 32

// Some Xmacro dark magic to assign to each tag its value
typedef enum tlv_tag_e {
#define X(name, value) name = value,
    TLV_TAGS
#undef X
} tlv_tag_t;

// Some Xmacro dark magic to calculate TLV_COUNT
typedef enum tlv_tag_count_e {
// Define a garbage enum member for each TAG, starting at 0
#define X(name, value) name##_AUTOCOUNT,
    TLV_TAGS
#undef X
        // Automatically defines TLV_COUNT as the total number of tags
        TLV_COUNT
} tlv_tag_count_t;

// The received TLV data that will be fed to each handler
typedef struct tlv_data_s {
    tlv_tag_t tag;
    uint16_t length;
    const uint8_t *value;
} tlv_data_t;

// The handlers prototype to give to parse_tlv()
typedef bool(tlv_handler_cb_t)(const tlv_data_t *data, tlv_out_t *tlv_extracted);

typedef struct {
    tlv_tag_t tag;
    tlv_handler_cb_t *func;
} tlv_handler_t;

/**
 * Get uint from tlv data
 *
 * This function extracts an unsigned 32-bit integer (up to 4 bytes) from the TLV data.
 * The length of the data must not exceed 4 bytes.
 *
 * The data is padded with leading zeros if it is less than 4 bytes, and the resulting value is
 * converted to a 32-bit unsigned integer in big-endian byte order.
 *
 * @param[in] data The TLV data containing the value to be extracted
 * @param[out] value Pointer to a uint32_t where the result will be stored
 * @return True if the extraction was successful, false otherwise (invalid length or data)
 */
bool get_uint32_from_tlv_data(const tlv_data_t *data, uint32_t *value);

/**
 * Get uint16_t from tlv data
 *
 * This function extracts a uint16_t value from the TLV data by calling `get_uint32_from_tlv_data`.
 * The extracted value is then checked to ensure it fits within the uint16_t range.
 *
 * If the value is too large (greater than `UINT16_MAX`), the extraction fails.
 *
 * @param[in] data The TLV data containing the value to be extracted
 * @param[out] value Pointer to a uint16_t where the result will be stored
 * @return True if the extraction was successful, false otherwise (either failed extraction or
 * out-of-range value)
 */
bool get_uint16_t_from_tlv_data(const tlv_data_t *data, uint16_t *value);

/**
 * Get uint8_t from tlv data
 *
 * This function extracts a uint8_t value from the TLV data by calling `get_uint32_from_tlv_data`.
 * The extracted value is then checked to ensure it fits within the uint8_t range.
 *
 * If the value is too large (greater than `UINT8_MAX`), the extraction fails.
 *
 * @param[in] data The TLV data containing the value to be extracted
 * @param[out] value Pointer to a uint8_t where the result will be stored
 * @return True if the extraction was successful, false otherwise (either failed extraction or
 * out-of-range value)
 */
bool get_uint8_t_from_tlv_data(const tlv_data_t *data, uint8_t *value);

/**
 * Get a buffer_t from tlv data
 *
 * This function extracts a `buffer_t` (circular buffer) from the TLV data, ensuring that the
 * extracted data's length is within the specified bounds (`min_size` and `max_size`).
 *
 * The `buffer_t` structure will be populated with the data's size and pointer to the actual bytes.
 *
 * @param[in] data The TLV data containing the value to be extracted
 * @param[out] out The `buffer_t` where the extracted value will be stored
 * @param[in] min_size The minimum acceptable size for the extracted data
 * @param[in] max_size The maximum acceptable size for the extracted data (0 if no upper limit)
 * @return True if the extraction was successful, false otherwise (data length is outside the
 * allowed range)
 */
bool get_buffer_from_tlv_data(const tlv_data_t *data,
                              buffer_t *out,
                              uint16_t min_size,
                              uint16_t max_size);

/**
 * Get the receive bit flag associated with a TLV tag.
 *
 * Maps a TLV tag to its corresponding receive bit flag
 * The flag is represented as a single bit in a 32-bit
 * integer, allowing for efficient bitwise operations.
 *
 * @param[in] tag The TLV tag for which the flag is required.
 * @return The corresponding flag value for the given TLV tag.
 *         If the tag is invalid, returns (uint32_t)-1.
 */
uint32_t get_tag_flag(tlv_tag_t tag);

/**
 * Parse the TLV payload
 *
 * Does the TLV parsing but also the SHA-256 hash of the payload.
 *
 * @param[in] handlers the handlers to use to parse the TLV
 * @param[in] payload the raw TLV payload
 * @param[out] tlv_out the parsed TLV data
 * @param[in] signature_tag a tag to ignore while computing the hash
 * @param[out] tlv_hash the computed hash of the entire TLV except the signature tag
 * @param[out] received_tags_flags the flags of all received tags
 * @return whether it was successful
 */
bool parse_tlv(const tlv_handler_t *handlers,
               uint8_t handlers_count,
               const buffer_t *payload,
               tlv_out_t *tlv_out,
               tlv_tag_t signature_tag,
               uint8_t hash[INT256_LENGTH],
               uint32_t *received_tags_flags);

bool received_required_tags(uint32_t rcv_flags, const tlv_tag_t *tags, size_t tag_count);

// Wrapper around above function that accepts a tag list as argument
#define RECEIVED_REQUIRED_TAGS(rcv_flags, ...)         \
    received_required_tags(rcv_flags,                  \
                           (tlv_tag_t[]){__VA_ARGS__}, \
                           sizeof((tlv_tag_t[]){__VA_ARGS__}) / sizeof(tlv_tag_t))

#endif  // HAVE_SDK_TLV_PARSER
