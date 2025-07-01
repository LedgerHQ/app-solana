#pragma once

#include <os.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "tlv_internals.h"
#include "buffer.h"

// ─────────────────────────────────────────────────────────────────────────────
// TLV example
// ─────────────────────────────────────────────────────────────────────────────

/* As usage of this library can seem complicated at first, here is as an introduction a minimalist
 * example implementation
 *
 * ```c

typedef struct my_tlv_output_s {
    TLV_reception_t received_tags;
    uint8_t my_value_1;
    uint32_t my_value_2;
} my_tlv_output_t;

static bool my_handler_1(const tlv_data_t *data, my_tlv_output_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->my_value_1);
}

static bool my_handler_2(const tlv_data_t *data, my_tlv_output_t *out) {
    return get_uint32_t_from_tlv_data(data, &out->my_value_2);
}

#define MY_TAGS(X) \
    X(0x0A, TAG_A, my_handler_1, ENFORCE_UNIQUE_TAG) \
    X(0x1F, TAG_B, my_handler_2, ENFORCE_UNIQUE_TAG) \
    X(0x77, TAG_C, NULL, ALLOW_MULTIPLE_TAG)

DEFINE_TLV_PARSER(MY_TAGS, NULL, my_tlv_parser)

bool my_tlv_parser(buffer_t payload, uint8_t *my_value_to_receive) {
    my_tlv_output_t out = {0};
    if (!parse_tlv_trusted_name(&payload, &out, &out.received_tags)) {
        return false;
    }
    if (!CHECK_RECEIVED_TAGS(out.received_tags, TAG_A, TAG_B)) {
        return false;
    }
    *my_value_to_receive = out.my_value_1;
    return true;
}

 * ```
 */

// ─────────────────────────────────────────────────────────────────────────────
// TLV library API
// ─────────────────────────────────────────────────────────────────────────────

// The received TLV data that will be fed as input to each handler
typedef struct tlv_data_s {
    // The tag is reminded in case the handler is generic and covers multiple tags
    TLV_tag_t tag;
    // The length of the value buffer
    // uint16_t length;
    // The value buffer
    buffer_t value;

    // In case the handler needs to do some processing on the raw TLV-encoded data
    // Computing a signature for example
    // const uint8_t *raw;
    // uint16_t raw_size;
    buffer_t raw;
} tlv_data_t;

// The handlers prototype to give to give to DEFINE_TLV_PARSER() through the TAG_LIST parameter
// The type of tlv_extracted must be the same for every handler of a given TLV use case
typedef bool(tlv_handler_cb_t)(const tlv_data_t *data, void *tlv_extracted);

// The generated TLV parser will set in this structure the flags of each received tag
// Actual structure content is private, use check_received_tags or CHECK_RECEIVED_TAGS
typedef TLV_reception_internal_t TLV_reception_t;

typedef enum tag_unicity_e {
    // The parser will fail if the associated tag is received more than once
    ENFORCE_UNIQUE_TAG,
    // The parser will call the handler every time this tag is received
    ALLOW_MULTIPLE_TAG,
} tag_unicity_t;

/**
 * @brief Creates a parser function for a given TLV use case
 *
 * @param TAG_LIST A X-macro of TAG and associated handles of the following format:
 * ```c
TAG_LIST(X) \
    X(<uint32_t>, TAG_NAME, <tlv_handler_cb_t>, <tag_unicity_t>)
 * ```
 * @param COMMON_HANDLER An optional handler to call for all tags in addition to the specific one
 * @param PARSE_FUNCTION_NAME Name of the function that will parse the TAG_LIST
 *
 * Example:
 * ```c
 * #define MY_TAGS(X) \
 *     X(0x0A, TAG_A, my_handler_1, ALLOW_MULTIPLE_TAG) \
 *     X(0x1F, TAG_B, my_handler_2, ENFORCE_UNIQUE_TAG) \
 *     X(0x77, TAG_C, my_handler_2, ENFORCE_UNIQUE_TAG)
 *
 * DEFINE_TLV_PARSER(MY_TAGS, NULL, my_tlv_parser)
 * ```
 *
 * Expands to:
 * - `enum { TAG_A = 0x0A, TAG_B = 0x1F, TAG_C = 0x77};`
 * - `enum { TAG_A_INDEX, TAG_B_INDEX, TAG_C_INDEX, my_tlv_parser_TAG_COUNT };`
 * - `enum { TAG_A_FLAG = 1 << 0, TAG_B_FLAG = 1 << 1, TAG_C_FLAG = 1 << 2 };`
 * - `my_tlv_parser_tag_to_flag()`
 * - `my_tlv_parser()`
 */
// clang-format off
#define DEFINE_TLV_PARSER(TAG_LIST, COMMON_HANDLER, PARSE_FUNCTION_NAME)                 \
    /* Create an enum associating tags with their values */                              \
    enum {                                                                               \
        TAG_LIST(__X_DEFINE_TLV__TAG_ASSIGN)                                             \
    };                                                                                   \
                                                                                         \
    /* Create an enum associating tags with their indexes (for internal use). */         \
    enum {                                                                               \
        TAG_LIST(__X_DEFINE_TLV__TAG_INDEX)                                              \
        PARSE_FUNCTION_NAME##_TAG_COUNT,                                                 \
    };                                                                                   \
                                                                                         \
    /* Create an enum associating tags with their flags (for internal use). */           \
    enum {                                                                               \
        TAG_LIST(__X_DEFINE_TLV__TAG_FLAG)                                               \
    };                                                                                   \
                                                                                         \
    /* A dynamically generated function that maps tags to flags (for internal use). */   \
    /* */                                                                                \
    /* @param[in] tag The tag to get the flag of*/                                       \
    /* @return The associated flag or 0 if none exist */                                 \
    static inline TLV_flag_t PARSE_FUNCTION_NAME##_tag_to_flag(TLV_tag_t tag) {          \
        switch (tag) {                                                                   \
            TAG_LIST(__X_DEFINE_TLV__TAG_TO_FLAG_CASE)                                   \
            default:                                                                     \
                return 0;                                                                \
        }                                                                                \
    }                                                                                    \
                                                                                         \
    /* A dynamically generated TLV parser function for this TLV use case. */             \
    /* */                                                                                \
    /* Parses a TLV payload using the tag and handlers of TAG_LIST */                    \
    /* */                                                                                \
    /* @param[in] payload the TLV payload to parse */                                    \
    /* @param[out] tlv_out The output data of this parser, written in by the handlers */ \
    /* @param[out] received_tags_flags The tag reception structure */                    \
    /* @return whether it was successful */                                              \
    static inline bool PARSE_FUNCTION_NAME(const buffer_t *payload,                      \
                                           void *tlv_out,                                \
                                           TLV_reception_t *received_tags_flags) {       \
        /* Create a local array of handlers to give to the generic parser */             \
        _internal_tlv_handler_t handlers[PARSE_FUNCTION_NAME##_TAG_COUNT] = {            \
            TAG_LIST(__X_DEFINE_TLV__TAG_CALLBACKS)                                      \
        };                                                                               \
        return _parse_tlv_internal(handlers,                                             \
                                   PARSE_FUNCTION_NAME##_TAG_COUNT,                      \
                                   (tlv_handler_cb_t*) COMMON_HANDLER,                   \
                                   PARSE_FUNCTION_NAME##_tag_to_flag,                    \
                                   payload,                                              \
                                   tlv_out,                                              \
                                   received_tags_flags);                                 \
    }
// clang-format on

/**
 * Get uint from tlv data
 *
 * This function extracts an unsigned N-bit integer from the TLV data.
 * The length of the data must not exceed the requested format.
 *
 * The data is padded with leading zeros if it is less than N-bits, and the resulting value is
 * converted to a N-bit unsigned integer in big-endian byte order.
 *
 * @param[in] data The TLV data containing the value to be extracted
 * @param[out] value Pointer to a uintN_t where the result will be stored
 * @return True if the extraction was successful, false otherwise (invalid length or data)
 */
bool get_uint64_t_from_tlv_data(const tlv_data_t *data, uint64_t *value);
bool get_uint32_t_from_tlv_data(const tlv_data_t *data, uint32_t *value);
bool get_uint16_t_from_tlv_data(const tlv_data_t *data, uint16_t *value);
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
 * Get a string from tlv data
 *
 * This function extracts a `string` from the TLV data, ensuring that the
 * extracted data's length is within the specified bounds (`min_size` and `max_size`).
 *
 * A 0 copy API would be inconvenient for strings because they are not '\0' terminated in the TLV
 * reception format.
 *
 * @param[in] data The TLV data containing the value to be extracted
 * @param[out] out The `string` where the extracted value will be copied
 * @param[in] min_length The minimum acceptable size for the extracted data
 * @param[in] out_size The maximum acceptable size for the extracted data including the '\0' byte
 * @return True if the extraction was successful, false otherwise (data length is outside the
 * allowed range)
 */
bool get_string_from_tlv_data(const tlv_data_t *data,
                              char *out,
                              uint16_t min_length,
                              uint16_t out_size);

/**
 * Checks if a given list of tags have been received by the parser-set tag reception tracker
 *
 * Please see CHECK_RECEIVED_TAGS below for a variadic (and more user friendly) variant
 *
 * @param[in] received The parser-set tag reception tracker
 * @param[in] tags The list of tags to check
 * @param[in] tag_count The number of tags in the tags list
 * @return True if all requested tags have been received
 *
 * Warning: do not mix and match tags of different TLV use cases. Undefined behavior.
 */
bool tlv_check_received_tags(TLV_reception_t received, const TLV_tag_t *tags, size_t tag_count);

/**
 * Macro wrapper of the above function to accept a list of tags as argument.
 */
#define TLV_CHECK_RECEIVED_TAGS(received, ...)          \
    tlv_check_received_tags(received,                   \
                            (TLV_tag_t[]){__VA_ARGS__}, \
                            sizeof((TLV_tag_t[]){__VA_ARGS__}) / sizeof(TLV_tag_t))

// ─────────────────────────────────────────────────────────────────────────────
// TLV internal data
// ─────────────────────────────────────────────────────────────────────────────

// Maps a tag to a handler function and some associated metadata
typedef struct {
    TLV_tag_t tag;
    // Handler to call when encountering this tag. Can be NULL.
    tlv_handler_cb_t *func;
    // If true the parser will check if this tag was already received before calling the handler
    bool is_unique;
} _internal_tlv_handler_t;

/**
 * Parses a TLV payload
 *
 * Please use the DEFINE_TLV_PARSER to define a wrapper of _parse_tlv_internal dedicated for your
 * use case.
 *
 * @param[in] handlers array of handlers to use to parse the TLV
 * @param[in] handlers_count the number handlers given
 * @param[in] common_handler an optional handler to call for all tags in addition to the specific
 * one
 * @param[in] the function to map tags to flags
 * @param[in] payload the raw TLV payload
 * @param[out] tlv_out the parsed TLV data
 * @param[out] received_tags_flags the flags of all received tags
 * @return whether it was successful
 */
bool _parse_tlv_internal(const _internal_tlv_handler_t *handlers,
                         uint8_t handlers_count,
                         tlv_handler_cb_t *common_handler,
                         tag_to_flag_function_t *tag_to_flag_function,
                         const buffer_t *payload,
                         void *tlv_out,
                         TLV_reception_t *received_tags_flags);
