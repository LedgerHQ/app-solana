// IDL type pool. See idl_pool.h for the contract.
//
// Parses the raw IDL_TYPE_POOL descriptor into a module-global array of
// structured entries and hands it back to the IDL walker through getters. The
// entry array is owned here (allocated at provide, freed at reset); the raw
// pool bytes the entries point into are borrowed and stay caller-owned.

#include <string.h>

#include "idl_pool.h"
#include "util.h"
#include "app_mem_utils.h"

// =============================================================================
// Module-global parsed pool
// =============================================================================

typedef struct idl_pool_s {
    idl_pool_entry_t *entries;
    uint8_t count;
    uint8_t root_index;  // index of the entry the walk starts from (the pool's root type)
    bool ready;          // true once a pool is parsed and loaded; getters refuse to read until then
} idl_pool_t;

static idl_pool_t G_idl_pool;

// =============================================================================
// Parsing
// =============================================================================

// Parse the entries of an IDL_TYPE_POOL payload into the pre-allocated, zeroed
// `entries` array. Multi-byte descriptor metadata is big-endian. Returns 0 on
// success, -1 on truncation, trailing bytes, an out-of-range ref, or an
// unknown kind.
static int parse_pool_entries(const uint8_t *buf,
                              size_t size,
                              idl_pool_entry_t *entries,
                              uint8_t count) {
    size_t offset = 1;
    PRINTF("idl_pool: parse_pool_entries count=%d size=%d\n", count, size);

    for (uint8_t i = 0; i < count; i++) {
        if (offset >= size) {
            PRINTF("idl_pool: pool truncated before entry %d\n", i);
            return -1;
        }
        uint8_t kind = buf[offset++];
        idl_pool_entry_t *entry = &entries[i];
        entry->kind = kind;
        PRINTF("idl_pool: parsing entry %d kind=0x%02x at offset=%d\n", i, kind, offset - 1);

        switch (kind) {
            case IDL_KIND_U8:
            case IDL_KIND_U16:
            case IDL_KIND_U32:
            case IDL_KIND_U64:
            case IDL_KIND_U128:
            case IDL_KIND_I8:
            case IDL_KIND_I16:
            case IDL_KIND_I32:
            case IDL_KIND_I64:
            case IDL_KIND_I128:
            case IDL_KIND_F32:
            case IDL_KIND_F64:
            case IDL_KIND_SHORT_U16:
            case IDL_KIND_BOOL_U8:
            case IDL_KIND_BOOL_U16:
            case IDL_KIND_BOOL_U32:
            case IDL_KIND_PUBKEY_32:
            case IDL_KIND_BYTES_REMAINDER:
                break;

            case IDL_KIND_BYTES_FIXED:
                if (offset + 2 > size) {
                    PRINTF("idl_pool: BYTES_FIXED entry %d truncated\n", i);
                    return -1;
                }
                entry->fixed_size = (uint16_t) ((buf[offset] << 8) | buf[offset + 1]);
                offset += 2;
                break;

            case IDL_KIND_STRING_FIXED:
                if (offset + 3 > size) {
                    PRINTF("idl_pool: STRING_FIXED entry %d truncated\n", i);
                    return -1;
                }
                entry->fixed_size = (uint16_t) ((buf[offset] << 8) | buf[offset + 1]);
                entry->encoding = buf[offset + 2];
                offset += 3;
                break;

            case IDL_KIND_STRING_PREFIXED:
                if (offset + 2 > size) {
                    PRINTF("idl_pool: STRING_PREFIXED entry %d truncated\n", i);
                    return -1;
                }
                entry->len_kind = buf[offset];
                entry->encoding = buf[offset + 1];
                offset += 2;
                break;

            case IDL_KIND_STRUCT:
            case IDL_KIND_TUPLE: {
                if (offset >= size) {
                    PRINTF("idl_pool: STRUCT/TUPLE entry %d truncated\n", i);
                    return -1;
                }
                uint8_t field_count = buf[offset++];
                if (offset + field_count > size) {
                    PRINTF("idl_pool: STRUCT/TUPLE entry %d refs truncated\n", i);
                    return -1;
                }
                entry->refs = &buf[offset];
                entry->ref_count = field_count;
                offset += field_count;
                break;
            }

            case IDL_KIND_OPTION_DYNAMIC:
            case IDL_KIND_OPTION_FIXED:
                if (offset + 2 > size) {
                    PRINTF("idl_pool: OPTION entry %d truncated\n", i);
                    return -1;
                }
                entry->flag_kind = buf[offset];
                entry->refs = &buf[offset + 1];
                entry->ref_count = 1;
                offset += 2;
                break;

            case IDL_KIND_OPTION_ZEROABLE: {
                if (offset + 2 > size) {
                    PRINTF("idl_pool: OPTION_ZEROABLE entry %d truncated\n", i);
                    return -1;
                }
                entry->refs = &buf[offset];
                entry->ref_count = 1;
                uint8_t sentinel_len = buf[offset + 1];
                offset += 2;
                if (offset + sentinel_len > size) {
                    PRINTF("idl_pool: OPTION_ZEROABLE entry %d sentinel truncated\n", i);
                    return -1;
                }
                entry->sentinel = &buf[offset];
                entry->sentinel_len = sentinel_len;
                offset += sentinel_len;
                break;
            }

            case IDL_KIND_ARRAY_FIXED:
                if (offset + 3 > size) {
                    PRINTF("idl_pool: ARRAY_FIXED entry %d truncated\n", i);
                    return -1;
                }
                entry->fixed_size = (uint16_t) ((buf[offset] << 8) | buf[offset + 1]);
                entry->refs = &buf[offset + 2];
                entry->ref_count = 1;
                offset += 3;
                break;

            case IDL_KIND_ARRAY_PREFIXED:
                if (offset + 2 > size) {
                    PRINTF("idl_pool: ARRAY_PREFIXED entry %d truncated\n", i);
                    return -1;
                }
                entry->len_kind = buf[offset];
                entry->refs = &buf[offset + 1];
                entry->ref_count = 1;
                offset += 2;
                break;

            case IDL_KIND_ARRAY_REMAINDER:
            case IDL_KIND_OPTION_REMAINDER:
                if (offset + 1 > size) {
                    PRINTF("idl_pool: REMAINDER entry %d truncated\n", i);
                    return -1;
                }
                entry->refs = &buf[offset];
                entry->ref_count = 1;
                offset += 1;
                break;

            case IDL_KIND_ENUM: {
                if (offset + 4 > size) {
                    PRINTF("idl_pool: ENUM entry %d truncated\n", i);
                    return -1;
                }
                entry->disc_kind = buf[offset];
                entry->total_variants = (uint16_t) ((buf[offset + 1] << 8) | buf[offset + 2]);
                uint8_t id_len = buf[offset + 3];
                offset += 4;
                if (offset + id_len > size) {
                    PRINTF("idl_pool: ENUM entry %d id truncated\n", i);
                    return -1;
                }
                entry->enum_id = &buf[offset];
                entry->enum_id_len = id_len;
                offset += id_len;
                break;
            }

            case IDL_KIND_HIDDEN_PREFIX:
            case IDL_KIND_HIDDEN_SUFFIX:
                if (offset + 2 > size) {
                    PRINTF("idl_pool: HIDDEN entry %d truncated\n", i);
                    return -1;
                }
                entry->refs = &buf[offset];  // [skip_ref, inner_ref]
                entry->ref_count = 2;
                offset += 2;
                break;

            default:
                PRINTF("idl_pool: unknown pool kind 0x%02x\n", kind);
                return -1;
        }
    }

    if (offset != size) {
        PRINTF("idl_pool: %d trailing byte(s) in pool\n", size - offset);
        return -1;
    }
    PRINTF("idl_pool: all %d entries parsed, validating refs\n", count);

    for (uint8_t i = 0; i < count; i++) {
        const idl_pool_entry_t *entry = &entries[i];
        for (uint8_t j = 0; j < entry->ref_count; j++) {
            if (entry->refs[j] >= count) {
                PRINTF("idl_pool: ref %d out of range (count=%d)\n", entry->refs[j], count);
                return -1;
            }
        }
    }
    PRINTF("idl_pool: pool refs validated OK\n");
    return 0;
}

// Parse the IDL_TYPE_POOL payload (`u8 count || entries`) into an owned array
// of idl_pool_entry_t. The owned array is allocated here and freed on parse
// failure, so parse_pool_entries can return -1 directly without leaking.
//
// Returns 0 on success (caller owns *out_entries), -1 on error.
static int parse_pool(const uint8_t *buf,
                      size_t size,
                      idl_pool_entry_t **out_entries,
                      uint8_t *out_count) {
    if (buf == NULL || size < 1) {
        PRINTF("idl_pool: empty pool buffer\n");
        return -1;
    }
    uint8_t count = buf[0];
    PRINTF("idl_pool: parse_pool size=%d declared count=%d\n", size, count);

    // malloc(0) is implementation-defined; allocate at least one slot.
    size_t alloc_count = (count == 0) ? 1 : count;
    idl_pool_entry_t *entries = APP_MEM_ALLOC(alloc_count * sizeof(idl_pool_entry_t));
    if (entries == NULL) {
        PRINTF("idl_pool: pool entry array allocation failed\n");
        return -1;
    }
    memset(entries, 0, alloc_count * sizeof(idl_pool_entry_t));

    if (parse_pool_entries(buf, size, entries, count) != 0) {
        PRINTF("idl_pool: parse_pool_entries failed, freeing entries\n");
        APP_MEM_FREE(entries);
        return -1;
    }

    *out_entries = entries;
    *out_count = count;
    PRINTF("idl_pool: parse_pool succeeded with %d entries\n", count);
    return 0;
}

// =============================================================================
// Public API
// =============================================================================

int idl_pool_provide(const uint8_t *pool, size_t pool_size, uint8_t root_index) {
    if (pool == NULL && pool_size > 0) {
        PRINTF("idl_pool_provide: NULL pool with non-zero size (pool_size=%d)\n", pool_size);
        return -1;
    }

    // Providing replaces any previously parsed pool.
    idl_pool_reset();

    idl_pool_entry_t *entries = NULL;
    uint8_t count = 0;
    if (parse_pool(pool, pool_size, &entries, &count) != 0) {
        PRINTF("idl_pool_provide: parse failed\n");
        return -1;
    }
    if (root_index >= count) {
        PRINTF("idl_pool_provide: root_index %d out of range (count=%d)\n", root_index, count);
        APP_MEM_FREE(entries);
        return -1;
    }

    G_idl_pool.entries = entries;
    G_idl_pool.count = count;
    G_idl_pool.root_index = root_index;
    G_idl_pool.ready = true;

    PRINTF("idl_pool_provide: parsed pool (entries=%d, root_index=%d)\n", count, root_index);
    return 0;
}

bool idl_pool_ready(void) {
    return G_idl_pool.ready;
}

uint8_t idl_pool_count(void) {
    return G_idl_pool.count;
}

uint8_t idl_pool_root_index(void) {
    return G_idl_pool.root_index;
}

const idl_pool_entry_t *idl_pool_entry(uint8_t index) {
    if (!G_idl_pool.ready) {
        PRINTF("idl_pool_entry: no pool loaded\n");
        return NULL;
    }
    if (index >= G_idl_pool.count) {
        PRINTF("idl_pool_entry: index %d out of range (count=%d)\n", index, G_idl_pool.count);
        return NULL;
    }
    return &G_idl_pool.entries[index];
}

void idl_pool_reset(void) {
    PRINTF("idl_pool_reset: freeing %d entries\n", G_idl_pool.count);
    APP_MEM_FREE(G_idl_pool.entries);
    G_idl_pool.entries = NULL;
    G_idl_pool.count = 0;
    G_idl_pool.root_index = 0;
    G_idl_pool.ready = false;
}
