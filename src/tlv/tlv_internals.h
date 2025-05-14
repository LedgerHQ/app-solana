#pragma once

#include <os.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

// ─────────────────────────────────────────────────────────────────────────────
// TLV X macros
// Not intended for library users
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Internal macro — assigns the tag's enum value.
 * @note Do not use directly.
 */
#define __X_DEFINE_TLV__TAG_ASSIGN(value, name, callback, unicity) name = value,

/**
 * @brief Internal macro — creates an index enum for mapping tags to their order in the list.
 * @note Do not use directly.
 */
#define __X_DEFINE_TLV__TAG_INDEX(value, name, callback, unicity) name##_INDEX,

/**
 * @brief Internal macro — creates a flag enum for mapping tags to their reception flag.
 * @note Do not use directly.
 */
#define __X_DEFINE_TLV__TAG_FLAG(value, name, callback, unicity) name##_FLAG = (1U << name##_INDEX),

/**
 * @brief Internal macro — expands to a switch case that maps a tag to its flag.
 * @note Do not use directly.
 */
#define __X_DEFINE_TLV__TAG_TO_FLAG_CASE(value, name, callback, unicity) \
    case name:                                                           \
        return name##_FLAG;

/**
 * @brief Internal macro — expands each tag into an _internal_tlv_handler_t array element
 * @note Do not use directly.
 */
#define __X_DEFINE_TLV__TAG_CALLBACKS(value, name, callback, unicity) \
    {.tag = name,                                                     \
     .func = (tlv_handler_cb_t *) callback,                           \
     .is_unique = (unicity == ENFORCE_UNIQUE_TAG)},

// The generated TLV library will give the user a tag_to_flag function of the following type for
// his TLV use case
typedef uint32_t TLV_tag_t;
typedef uint64_t TLV_flag_t;
typedef TLV_flag_t(tag_to_flag_function_t)(TLV_tag_t tag);

// This structure is returned to the TLV parser caller and can be used in conjunction with the
// associated helper functions to get the status of received tags.
typedef struct {
    TLV_flag_t flags;
    tag_to_flag_function_t *tag_to_flag_function;
} TLV_reception_internal_t;
