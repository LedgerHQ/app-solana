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

// One cached enum variant descriptor. Only ever exposed once fully stored, so
// every field is valid. `payload_kind` tags the union: only the member matching
// the kind is valid (EMPTY leaves the union unused). Every variable-length
// member (`enum_id`, `variant_name`, and the INLINE descriptor) is a separately
// heap-allocated buffer sized to its exact length and owned by this entry.
typedef struct cs_enum_variant_s {
    // Enum key
    uint8_t program_id[32];
    uint8_t *enum_id;
    size_t enum_id_len;
    uint16_t variant_index;
    // Enum content, NUL-terminated.
    char *variant_name;
    cs_variant_payload_kind_t payload_kind;
    union {
        // CS_VARIANT_PAYLOAD_INLINE: the self-contained inline type descriptor the
        // walker decodes. `bytes` is heap-allocated to `size`, owned by this entry.
        struct {
            uint8_t *bytes;
            uint16_t size;
        } inline_descriptor;
        // CS_VARIANT_PAYLOAD_RAW_SIZE: opaque payload byte count to skip.
        uint16_t raw_size;
        // CS_VARIANT_PAYLOAD_EMPTY: nothing.
    } payload;
} cs_enum_variant_t;

// Store one variant descriptor keyed by (program_id, enum_id, variant_index).
// `variant_name`/`variant_name_len` give the name bytes (NUL-terminated on
// store); `variant_name` may be NULL with a zero length for an absent name.
// `payload`/`payload_size` are the raw wire bytes interpreted per `payload_kind`:
// absent for EMPTY, the inline descriptor for INLINE, or the 2-byte big-endian
// count for RAW_SIZE. All input bytes are copied into owned heap buffers.
// Returns 0 on success, -1 when an allocation fails, the payload does not match
// the kind, or the key already exists (duplicate descriptor).
int cs_enum_cache_add(const uint8_t program_id[32],
                      const uint8_t *enum_id,
                      size_t enum_id_len,
                      uint16_t variant_index,
                      const char *variant_name,
                      size_t variant_name_len,
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
size_t cs_enum_cache_count(void);

// Release the cache, returning to the empty state. Safe when none allocated.
void cs_enum_cache_reset(void);
