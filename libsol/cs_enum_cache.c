// Enum-variant cache for clear signing. See cs_enum_cache.h.
//
// Holds the signed ENUM_VARIANT descriptors provided during the descriptor
// preload so the IDL walker can resolve an IDL_KIND_ENUM discriminator to its
// variant name and payload shape at finalize time.

#include "cs_enum_cache.h"

#include <string.h>

#include "app_mem_utils.h"
#include "os_print.h"

// =============================================================================
// Module-global table
// =============================================================================

// Each variant descriptor is allocated on demand so the cache only consumes
// heap proportional to the number of variants actually provided, leaving room
// for the display renderer buffer at finalize time. The table itself is a tiny
// static array of pointers plus a count, so it needs no allocation of its own.
typedef struct cs_enum_cache_table_s {
    cs_enum_variant_t **variants;  // grown by one entry per add (APDU-paced)
    size_t count;
} cs_enum_cache_table_t;

static cs_enum_cache_table_t G_enum_cache;

// Release a variant and every buffer it owns, then null the slot pointer.
// Safe on a partially-built slot: unset owned buffers are NULL after calloc.
static void free_variant(cs_enum_variant_t **variant) {
    if (*variant == NULL) {
        return;
    }
    if ((*variant)->payload_kind == CS_VARIANT_PAYLOAD_INLINE) {
        APP_MEM_FREE_AND_NULL((void **) &(*variant)->payload.inline_descriptor.bytes);
    }
    APP_MEM_FREE_AND_NULL((void **) &(*variant)->variant_name);
    APP_MEM_FREE_AND_NULL((void **) &(*variant)->enum_id);
    APP_MEM_FREE_AND_NULL((void **) variant);
}

// True when `variant` carries the (program_id, enum_id, variant_index) key.
static bool key_matches(const cs_enum_variant_t *variant,
                        const uint8_t program_id[32],
                        const uint8_t *enum_id,
                        size_t enum_id_len,
                        uint16_t variant_index) {
    return (memcmp(variant->program_id, program_id, 32) == 0) &&
           (variant->enum_id_len == enum_id_len) &&
           (memcmp(variant->enum_id, enum_id, enum_id_len) == 0) &&
           (variant->variant_index == variant_index);
}

int cs_enum_cache_add(const uint8_t program_id[32],
                      const uint8_t *enum_id,
                      size_t enum_id_len,
                      uint16_t variant_index,
                      const char *variant_name,
                      size_t variant_name_len,
                      uint8_t payload_kind,
                      const uint8_t *payload,
                      size_t payload_size) {
    if (enum_id_len == 0) {
        PRINTF("cs_enum_cache_add: empty enum_id\n");
        return -1;
    }
    // The payload wire bytes must match the shape implied by payload_kind.
    switch (payload_kind) {
        case CS_VARIANT_PAYLOAD_EMPTY:
            if (payload_size != 0) {
                PRINTF("cs_enum_cache_add: EMPTY payload must be empty (got %d)\n", payload_size);
                return -1;
            }
            break;
        case CS_VARIANT_PAYLOAD_INLINE:
            if (payload_size == 0) {
                PRINTF("cs_enum_cache_add: INLINE payload must not be empty\n");
                return -1;
            }
            break;
        case CS_VARIANT_PAYLOAD_RAW_SIZE:
            if (payload_size != 2) {
                PRINTF(
                    "cs_enum_cache_add: RAW_SIZE payload must be 2 bytes (got "
                    "%d)\n",
                    payload_size);
                return -1;
            }
            break;
        default:
            PRINTF("cs_enum_cache_add: unknown payload_kind 0x%02x\n", payload_kind);
            return -1;
    }
    // The (program_id, enum_id, variant_index) key must be unique.
    if (cs_enum_cache_find(program_id, enum_id, enum_id_len, variant_index) != NULL) {
        PRINTF("cs_enum_cache_add: duplicate variant %d for enum\n", variant_index);
        return -1;
    }
    // Grow the pointer array to hold exactly one more variant.
    cs_enum_variant_t **grown = APP_MEM_REALLOC(G_enum_cache.variants,
                                                (G_enum_cache.count + 1) * sizeof(*grown));
    if (grown == NULL) {
        PRINTF("cs_enum_cache_add: table growth failed\n");
        return -1;
    }
    G_enum_cache.variants = grown;

    // One descriptor per variant, freed on reset. It owns its enum_id and
    // variant_name buffers, and (INLINE) a separate payload buffer; free_variant
    // releases all of them, so any allocation failure below unwinds cleanly.
    cs_enum_variant_t *slot = NULL;
    if (!APP_MEM_CALLOC((void **) &slot, sizeof(*slot))) {
        PRINTF("cs_enum_cache_add: variant allocation failed\n");
        return -1;
    }
    memcpy(slot->program_id, program_id, 32);
    slot->variant_index = variant_index;
    slot->payload_kind = (cs_variant_payload_kind_t) payload_kind;

    // enum_id: sized to its exact byte length, owned by the slot.
    if (!APP_MEM_CALLOC((void **) &slot->enum_id, enum_id_len)) {
        PRINTF("cs_enum_cache_add: enum_id allocation failed\n");
        free_variant(&slot);
        return -1;
    }
    memcpy(slot->enum_id, enum_id, enum_id_len);
    slot->enum_id_len = enum_id_len;

    // variant_name: sized to strlen+1 and NUL-terminated. An absent name stores
    // an empty string so consumers can always strlen/strcmp it.
    if (!APP_MEM_CALLOC((void **) &slot->variant_name, variant_name_len + 1)) {
        PRINTF("cs_enum_cache_add: variant_name allocation failed\n");
        free_variant(&slot);
        return -1;
    }
    if (variant_name != NULL && variant_name_len > 0) {
        memcpy(slot->variant_name, variant_name, variant_name_len);
    }

    // Store only the union member the kind selects (EMPTY uses none). RAW_SIZE
    // is decoded to a host uint16 here so the walker never re-parses wire
    // bytes.
    switch (payload_kind) {
        case CS_VARIANT_PAYLOAD_EMPTY:
            break;
        case CS_VARIANT_PAYLOAD_INLINE:
            // Size the inline buffer to the exact payload length.
            if (!APP_MEM_CALLOC((void **) &slot->payload.inline_descriptor.bytes, payload_size)) {
                PRINTF("cs_enum_cache_add: inline payload allocation failed\n");
                free_variant(&slot);
                return -1;
            }
            memcpy(slot->payload.inline_descriptor.bytes, payload, payload_size);
            slot->payload.inline_descriptor.size = (uint16_t) payload_size;
            break;
        case CS_VARIANT_PAYLOAD_RAW_SIZE:
            slot->payload.raw_size = ((uint16_t) payload[0] << 8) | (uint16_t) payload[1];
            break;
        default:
            // Unreachable: payload_kind validated above.
            break;
    }
    G_enum_cache.variants[G_enum_cache.count] = slot;
    G_enum_cache.count++;
    return 0;
}

const cs_enum_variant_t *cs_enum_cache_find(const uint8_t program_id[32],
                                            const uint8_t *enum_id,
                                            size_t enum_id_len,
                                            uint16_t variant_index) {
    for (size_t i = 0; i < G_enum_cache.count; i++) {
        if (key_matches(G_enum_cache.variants[i],
                        program_id,
                        enum_id,
                        enum_id_len,
                        variant_index)) {
            return G_enum_cache.variants[i];
        }
    }
    return NULL;
}

size_t cs_enum_cache_count(void) {
    return G_enum_cache.count;
}

void cs_enum_cache_reset(void) {
    // Release every per-variant descriptor; the static table stays but empties.
    // Each slot owns its enum_id, variant_name, and (INLINE) payload buffer,
    // all freed before the slot itself.
    for (size_t i = 0; i < G_enum_cache.count; i++) {
        free_variant(&G_enum_cache.variants[i]);
    }
    if (G_enum_cache.variants != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &G_enum_cache.variants);
    }
    G_enum_cache.count = 0;
}
