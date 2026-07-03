#pragma once

// Enum-variant cache for clear signing.
//
// Owns the signed ENUM_VARIANT descriptors streamed by PROVIDE ENUM VARIANT
// (0x26) during the Phase A descriptor preload and consumed by the IDL walker
// when it decodes an IDL_KIND_ENUM entry. Each descriptor is keyed by the
// (program_id, enum_id, variant_index) triple, mirroring the binding the HSM
// signature commits to.
//
// The cache lives on the heap (allocated on first add, released on reset) and
// is session-scoped, mirroring cs_transaction_t and the instruction template
// table.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// VariantPayloadKind enum (spec/device/tlv_structs.md ENUM_VARIANT).
// Selects how the walker advances past a variant's payload.
typedef enum cs_variant_payload_kind_e {
    CS_VARIANT_PAYLOAD_EMPTY = 0x00,
    CS_VARIANT_PAYLOAD_INLINE = 0x02,
    CS_VARIANT_PAYLOAD_RAW_SIZE = 0x03,
} cs_variant_payload_kind_t;

// Fixed capacities. Inputs exceeding these fail closed rather than truncate.
#define CS_MAX_ENUM_VARIANTS        8
#define CS_ENUM_ID_MAX_SIZE         64
#define CS_VARIANT_NAME_MAX_SIZE    64
#define CS_VARIANT_PAYLOAD_MAX_SIZE 128

// One cached enum variant descriptor. Only ever exposed once fully stored, so
// every field is valid. `payload_kind` tags the union: only the member matching
// the kind is valid (EMPTY leaves the union unused).
typedef struct cs_enum_variant_s {
    // Enum key
    uint8_t program_id[32];
    uint8_t enum_id[CS_ENUM_ID_MAX_SIZE];
    uint8_t enum_id_len;
    uint16_t variant_index;
    // Enum content
    char variant_name[CS_VARIANT_NAME_MAX_SIZE + 1];
    cs_variant_payload_kind_t payload_kind;
    union {
        // CS_VARIANT_PAYLOAD_INLINE: the self-contained inline type descriptor the walker decodes.
        struct {
            uint8_t bytes[CS_VARIANT_PAYLOAD_MAX_SIZE];
            uint16_t size;
        } inline_descriptor;
        // CS_VARIANT_PAYLOAD_RAW_SIZE: opaque payload byte count to skip.
        uint16_t raw_size;
        // CS_VARIANT_PAYLOAD_EMPTY: nothing.
        // empty
    } payload;
} cs_enum_variant_t;

// Store one variant descriptor keyed by (program_id, enum_id, variant_index).
// `variant_name` may be NULL or empty. `payload`/`payload_size` are the raw wire
// bytes interpreted per `payload_kind`: absent for EMPTY, the inline descriptor
// for INLINE, or the 2-byte big-endian count for RAW_SIZE.
// Returns 0 on success, -1 when the table cannot be allocated, is full, a field
// exceeds its capacity, the payload does not match the kind, or the key already
// exists (duplicate descriptor).
int cs_enum_cache_add(const uint8_t program_id[32],
                      const uint8_t *enum_id,
                      size_t enum_id_len,
                      uint16_t variant_index,
                      const char *variant_name,
                      uint8_t payload_kind,
                      const uint8_t *payload,
                      size_t payload_size);

// Find the cached variant matching the (program_id, enum_id, variant_index)
// triple. Returns NULL when no descriptor was provided for that variant.
const cs_enum_variant_t *cs_enum_cache_find(const uint8_t program_id[32],
                                            const uint8_t *enum_id,
                                            size_t enum_id_len,
                                            uint16_t variant_index);

// Number of cached variants.
uint8_t cs_enum_cache_count(void);

// Release the cache, returning to the empty state. Safe when none allocated.
void cs_enum_cache_reset(void);
