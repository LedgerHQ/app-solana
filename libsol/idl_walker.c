// IDL walker. See idl_walker.h for the contract.
//
// The walker decodes the raw argument bytes of a Solana instruction against
// the trimmed, kind-driven IDL_TYPE_POOL descriptor and streams every decoded
// leaf to a caller-supplied callback.
//
// Inputs are borrowed, never copied: the caller keeps the pool and instruction
// data buffers alive until idl_walker_reset(). The walk itself allocates a
// parsed-pool view, a growable frame stack, an optional fixed-size table and a
// reusable scratch path; all are released before idl_walker_run() returns, so
// the only size-driven failure path is the allocator returning NULL.
//
// Descent is iterative over an explicit heap-allocated frame stack (no C
// recursion), so deeply nested descriptors cannot overflow the device stack.
//
// The walk fails closed (returns -1) on any descriptor/data inconsistency: a
// read past the end of the instruction data, a malformed pool, an unsupported
// kind (IDL_KIND_ENUM for now), or a final cursor that does not land exactly
// on the end of the instruction data.

#include <string.h>

#include "idl_walker.h"
#include "util.h"
#include "app_mem_utils.h"

// =============================================================================
// Parsed pool entry
// =============================================================================

// A single IDL_TYPE_POOL entry, parsed into a structured view. Every pointer
// field borrows into the caller's pool bytes (zero-copy); only the array of
// entry_t itself is owned (and freed by the walk).
typedef struct entry_s {
    uint8_t kind;             // IDL_KIND_*
    uint16_t fixed_size;      // BYTES_FIXED/STRING_FIXED byte size, ARRAY_FIXED count
    uint8_t encoding;         // STRING_FIXED/STRING_PREFIXED encoding (unused by the walk)
    uint8_t len_kind;         // STRING_PREFIXED/ARRAY_PREFIXED length kind
    uint8_t flag_kind;        // OPTION_DYNAMIC/OPTION_FIXED flag kind
    uint8_t disc_kind;        // ENUM discriminator kind
    uint16_t total_variants;  // ENUM total variant count
    const uint8_t *refs;      // pointer into pool bytes: ref_count contiguous u8 indices
    uint8_t ref_count;
    const uint8_t *sentinel;  // OPTION_ZEROABLE sentinel bytes
    uint8_t sentinel_len;
    const uint8_t *enum_id;   // ENUM identifier bytes
    uint8_t enum_id_len;
} entry_t;

// Fixed-size table sentinels (see compute_fixed_sizes).
#define FS_UNKNOWN  (SIZE_MAX)
#define FS_VARIABLE (SIZE_MAX - 1)

// =============================================================================
// Pool parsing
// =============================================================================

// Parse the IDL_TYPE_POOL payload (`u8 count || entries`) into an owned array
// of entry_t. Mirrors the on-wire layout from spec/device/idl_descriptor.md.
// Multi-byte descriptor metadata is big-endian. Fails closed on truncation,
// trailing bytes, an out-of-range ref index, or an unknown kind.
//
// Returns 0 on success (caller owns *out_entries), -1 on error.
static int parse_pool(const uint8_t *buf, size_t size, entry_t **out_entries, uint8_t *out_count) {
    if (buf == NULL || size < 1) {
        return -1;
    }
    uint8_t count = buf[0];
    size_t off = 1;

    // malloc(0) is implementation-defined; allocate at least one slot.
    size_t alloc_count = (count == 0) ? 1 : count;
    entry_t *entries = APP_MEM_ALLOC(alloc_count * sizeof(entry_t));
    if (entries == NULL) {
        PRINTF("idl_walker: pool entry array allocation failed\n");
        return -1;
    }
    memset(entries, 0, alloc_count * sizeof(entry_t));

    for (uint8_t i = 0; i < count; i++) {
        if (off >= size) {
            goto fail;
        }
        uint8_t kind = buf[off++];
        entry_t *e = &entries[i];
        e->kind = kind;

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
                // No inline arguments.
                break;

            case IDL_KIND_BYTES_FIXED:
                if (off + 2 > size) {
                    goto fail;
                }
                e->fixed_size = (uint16_t) ((buf[off] << 8) | buf[off + 1]);
                off += 2;
                break;

            case IDL_KIND_STRING_FIXED:
                if (off + 3 > size) {
                    goto fail;
                }
                e->fixed_size = (uint16_t) ((buf[off] << 8) | buf[off + 1]);
                e->encoding = buf[off + 2];
                off += 3;
                break;

            case IDL_KIND_STRING_PREFIXED:
                if (off + 2 > size) {
                    goto fail;
                }
                e->len_kind = buf[off];
                e->encoding = buf[off + 1];
                off += 2;
                break;

            case IDL_KIND_STRUCT:
            case IDL_KIND_TUPLE: {
                if (off >= size) {
                    goto fail;
                }
                uint8_t n = buf[off++];
                if (off + n > size) {
                    goto fail;
                }
                e->refs = &buf[off];
                e->ref_count = n;
                off += n;
                break;
            }

            case IDL_KIND_OPTION_DYNAMIC:
            case IDL_KIND_OPTION_FIXED:
                if (off + 2 > size) {
                    goto fail;
                }
                e->flag_kind = buf[off];
                e->refs = &buf[off + 1];
                e->ref_count = 1;
                off += 2;
                break;

            case IDL_KIND_OPTION_ZEROABLE: {
                if (off + 2 > size) {
                    goto fail;
                }
                e->refs = &buf[off];  // inner_ref
                e->ref_count = 1;
                uint8_t slen = buf[off + 1];
                off += 2;
                if (off + slen > size) {
                    goto fail;
                }
                e->sentinel = &buf[off];
                e->sentinel_len = slen;
                off += slen;
                break;
            }

            case IDL_KIND_ARRAY_FIXED:
                if (off + 3 > size) {
                    goto fail;
                }
                e->fixed_size = (uint16_t) ((buf[off] << 8) | buf[off + 1]);
                e->refs = &buf[off + 2];
                e->ref_count = 1;
                off += 3;
                break;

            case IDL_KIND_ARRAY_PREFIXED:
                if (off + 2 > size) {
                    goto fail;
                }
                e->len_kind = buf[off];
                e->refs = &buf[off + 1];
                e->ref_count = 1;
                off += 2;
                break;

            case IDL_KIND_ARRAY_REMAINDER:
            case IDL_KIND_OPTION_REMAINDER:
                if (off + 1 > size) {
                    goto fail;
                }
                e->refs = &buf[off];
                e->ref_count = 1;
                off += 1;
                break;

            case IDL_KIND_ENUM: {
                if (off + 4 > size) {
                    goto fail;
                }
                e->disc_kind = buf[off];
                e->total_variants = (uint16_t) ((buf[off + 1] << 8) | buf[off + 2]);
                uint8_t el = buf[off + 3];
                off += 4;
                if (off + el > size) {
                    goto fail;
                }
                e->enum_id = &buf[off];
                e->enum_id_len = el;
                off += el;
                break;
            }

            case IDL_KIND_HIDDEN_PREFIX:
            case IDL_KIND_HIDDEN_SUFFIX:
                if (off + 2 > size) {
                    goto fail;
                }
                e->refs = &buf[off];  // [skip_ref, inner_ref]
                e->ref_count = 2;
                off += 2;
                break;

            default:
                PRINTF("idl_walker: unknown pool kind 0x%02x\n", kind);
                goto fail;
        }
    }

    if (off != size) {
        PRINTF("idl_walker: %d trailing byte(s) in pool\n", size - off);
        goto fail;
    }

    // Every ref must point at a valid pool entry.
    for (uint8_t i = 0; i < count; i++) {
        const entry_t *e = &entries[i];
        for (uint8_t j = 0; j < e->ref_count; j++) {
            if (e->refs[j] >= count) {
                PRINTF("idl_walker: ref %d out of range (count=%d)\n", e->refs[j], count);
                goto fail;
            }
        }
    }

    *out_entries = entries;
    *out_count = count;
    return 0;

fail:
    APP_MEM_FREE(entries);
    return -1;
}

// =============================================================================
// Static-size table (OPTION_FIXED skip)
// =============================================================================

// Width in bytes of a fixed-width numeric/pubkey primitive, or 0 if `kind` is
// not such a primitive.
static size_t fixed_primitive_width(uint8_t kind) {
    switch (kind) {
        case IDL_KIND_U8:
        case IDL_KIND_I8:
        case IDL_KIND_BOOL_U8:
            return 1;
        case IDL_KIND_U16:
        case IDL_KIND_I16:
        case IDL_KIND_BOOL_U16:
            return 2;
        case IDL_KIND_U32:
        case IDL_KIND_I32:
        case IDL_KIND_BOOL_U32:
        case IDL_KIND_F32:
            return 4;
        case IDL_KIND_U64:
        case IDL_KIND_I64:
        case IDL_KIND_F64:
            return 8;
        case IDL_KIND_U128:
        case IDL_KIND_I128:
            return 16;
        case IDL_KIND_PUBKEY_32:
            return 32;
        default:
            return 0;
    }
}

// Try to determine the static serialized size of pool[idx] given the partially
// filled size table `fs`. Writes the result to *out and returns true when it
// can be decided now; returns false when a child size is still FS_UNKNOWN.
// The result may be FS_VARIABLE for inherently variable-size kinds.
static bool try_static_size(const entry_t *pool, uint8_t idx, const size_t *fs, size_t *out) {
    const entry_t *e = &pool[idx];
    uint8_t kind = e->kind;

    size_t prim = fixed_primitive_width(kind);
    if (prim != 0) {
        *out = prim;
        return true;
    }

    switch (kind) {
        case IDL_KIND_BYTES_FIXED:
        case IDL_KIND_STRING_FIXED:
            *out = e->fixed_size;
            return true;

        case IDL_KIND_SHORT_U16:
        case IDL_KIND_STRING_PREFIXED:
        case IDL_KIND_BYTES_REMAINDER:
        case IDL_KIND_ARRAY_PREFIXED:
        case IDL_KIND_ARRAY_REMAINDER:
        case IDL_KIND_OPTION_DYNAMIC:
        case IDL_KIND_OPTION_REMAINDER:
        case IDL_KIND_ENUM:
            *out = FS_VARIABLE;
            return true;

        case IDL_KIND_STRUCT:
        case IDL_KIND_TUPLE: {
            size_t total = 0;
            for (uint8_t j = 0; j < e->ref_count; j++) {
                size_t cs = fs[e->refs[j]];
                if (cs == FS_UNKNOWN) {
                    return false;
                }
                if (cs == FS_VARIABLE) {
                    *out = FS_VARIABLE;
                    return true;
                }
                total += cs;
            }
            *out = total;
            return true;
        }

        case IDL_KIND_ARRAY_FIXED: {
            size_t cs = fs[e->refs[0]];
            if (cs == FS_UNKNOWN) {
                return false;
            }
            if (cs == FS_VARIABLE) {
                *out = FS_VARIABLE;
                return true;
            }
            *out = (size_t) e->fixed_size * cs;
            return true;
        }

        case IDL_KIND_OPTION_FIXED: {
            size_t cs = fs[e->refs[0]];
            if (cs == FS_UNKNOWN) {
                return false;
            }
            if (cs == FS_VARIABLE) {
                *out = FS_VARIABLE;
                return true;
            }
            *out = fixed_primitive_width(e->flag_kind) + cs;
            return true;
        }

        case IDL_KIND_OPTION_ZEROABLE: {
            size_t cs = fs[e->refs[0]];
            if (cs == FS_UNKNOWN) {
                return false;
            }
            *out = cs;  // sentinel and inner occupy the same width
            return true;
        }

        case IDL_KIND_HIDDEN_PREFIX:
        case IDL_KIND_HIDDEN_SUFFIX: {
            size_t a = fs[e->refs[0]];
            size_t b = fs[e->refs[1]];
            if (a == FS_UNKNOWN || b == FS_UNKNOWN) {
                return false;
            }
            if (a == FS_VARIABLE || b == FS_VARIABLE) {
                *out = FS_VARIABLE;
                return true;
            }
            *out = a + b;
            return true;
        }

        default:
            *out = FS_VARIABLE;
            return true;
    }
}

// Compute the static-size table for every pool entry via a fixpoint pass (no
// recursion). Entries that cannot be resolved (e.g. reference cycles) are left
// FS_VARIABLE, which makes any OPTION_FIXED that depends on them fail closed.
//
// Returns 0 on success (caller owns *out_sizes), -1 on out-of-space.
static int compute_fixed_sizes(const entry_t *pool, uint8_t count, size_t **out_sizes) {
    size_t alloc_count = (count == 0) ? 1 : count;
    size_t *fs = APP_MEM_ALLOC(alloc_count * sizeof(size_t));
    if (fs == NULL) {
        PRINTF("idl_walker: fixed-size table allocation failed\n");
        return -1;
    }
    for (size_t i = 0; i < alloc_count; i++) {
        fs[i] = FS_UNKNOWN;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (uint8_t i = 0; i < count; i++) {
            if (fs[i] != FS_UNKNOWN) {
                continue;
            }
            size_t s;
            if (try_static_size(pool, i, fs, &s)) {
                fs[i] = s;
                changed = true;
            }
        }
    }

    // Anything still unknown is part of a cycle; treat as variable.
    for (uint8_t i = 0; i < count; i++) {
        if (fs[i] == FS_UNKNOWN) {
            fs[i] = FS_VARIABLE;
        }
    }

    *out_sizes = fs;
    return 0;
}

static bool pool_has_option_fixed(const entry_t *pool, uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        if (pool[i].kind == IDL_KIND_OPTION_FIXED) {
            return true;
        }
    }
    return false;
}

// =============================================================================
// Walk state
// =============================================================================

// One node on the descent stack. A frame is pushed when its parent steps into
// it and popped once its subtree is fully consumed.
typedef struct frame_s {
    uint8_t entry_idx;    // pool index of the entry this frame walks
    uint8_t kind;         // cached pool[entry_idx].kind
    bool entered;         // first-visit work (length/flag reads) already done
    size_t child_i;       // next child to descend into
    size_t child_count;   // total children to descend into
    size_t mark;          // cursor at last child push (ARRAY_REMAINDER progress guard)
    uint8_t parent_kind;  // kind of the parent that pushed this frame (0 = root)
    size_t step_value;    // step index this frame occupies within its parent
} frame_t;

typedef struct walk_ctx_s {
    const uint8_t *data;
    size_t data_size;
    size_t cursor;

    const entry_t *pool;
    uint8_t pool_count;
    const size_t *fixed_sizes;  // NULL unless the pool contains an OPTION_FIXED

    frame_t *stack;
    size_t stack_len;
    size_t stack_cap;

    uint8_t *path;     // reusable scratch path buffer
    size_t path_cap;

    idl_leaf_cb_t cb;
    void *cb_ctx;
} walk_ctx_t;

// Byte width of one argument-path step under a parent of `parent_kind`, or 0
// for a parent kind that contributes no step (only the synthetic root).
static size_t step_width(uint8_t parent_kind) {
    switch (parent_kind) {
        case IDL_KIND_ARRAY_FIXED:
        case IDL_KIND_ARRAY_PREFIXED:
        case IDL_KIND_ARRAY_REMAINDER:
            return 2;
        case IDL_KIND_STRUCT:
        case IDL_KIND_TUPLE:
        case IDL_KIND_OPTION_DYNAMIC:
        case IDL_KIND_OPTION_FIXED:
        case IDL_KIND_OPTION_ZEROABLE:
        case IDL_KIND_OPTION_REMAINDER:
        case IDL_KIND_HIDDEN_PREFIX:
        case IDL_KIND_HIDDEN_SUFFIX:
            return 1;
        default:
            return 0;
    }
}

// Select the (pool ref, step value) the current frame descends into for its
// `child_i`-th child, honoring the per-kind ordering rules from the spec.
static void select_child(const entry_t *e,
                         uint8_t kind,
                         size_t child_i,
                         uint8_t *ref_idx,
                         size_t *step_val) {
    switch (kind) {
        case IDL_KIND_STRUCT:
        case IDL_KIND_TUPLE:
            *ref_idx = e->refs[child_i];
            *step_val = child_i;
            break;
        case IDL_KIND_ARRAY_FIXED:
        case IDL_KIND_ARRAY_PREFIXED:
        case IDL_KIND_ARRAY_REMAINDER:
            *ref_idx = e->refs[0];
            *step_val = child_i;
            break;
        case IDL_KIND_OPTION_DYNAMIC:
        case IDL_KIND_OPTION_FIXED:
        case IDL_KIND_OPTION_ZEROABLE:
        case IDL_KIND_OPTION_REMAINDER:
            *ref_idx = e->refs[0];
            *step_val = 0;
            break;
        case IDL_KIND_HIDDEN_PREFIX:
            // skip side first (step 1, never displayed), then inner (step 0).
            if (child_i == 0) {
                *ref_idx = e->refs[0];
                *step_val = 1;
            } else {
                *ref_idx = e->refs[1];
                *step_val = 0;
            }
            break;
        case IDL_KIND_HIDDEN_SUFFIX:
            // inner side first (step 0), then skip (step 1, never displayed).
            if (child_i == 0) {
                *ref_idx = e->refs[1];
                *step_val = 0;
            } else {
                *ref_idx = e->refs[0];
                *step_val = 1;
            }
            break;
        default:
            *ref_idx = 0;
            *step_val = 0;
            break;
    }
}

// Read a Solana ShortU16 varint (1-3 bytes) from the cursor, advancing it.
// Returns false on a read past the end of the data.
static bool read_short_u16(walk_ctx_t *c, uint64_t *out) {
    uint64_t val = 0;
    for (int i = 0; i < 3; i++) {
        if (c->cursor >= c->data_size) {
            return false;
        }
        uint8_t byte = c->data[c->cursor++];
        val |= (uint64_t) (byte & 0x7F) << (7 * i);
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    *out = val;
    return true;
}

// Read a little-endian unsigned integer of the given primitive `kind` (or a
// SHORT_U16 varint) from the cursor, advancing it. Returns false on a read
// past the end of the data or an unsupported kind.
static bool read_uint_le(walk_ctx_t *c, uint8_t kind, uint64_t *out) {
    if (kind == IDL_KIND_SHORT_U16) {
        return read_short_u16(c, out);
    }
    size_t w = fixed_primitive_width(kind);
    if (w == 0 || w > 8) {
        return false;
    }
    if (c->cursor + w > c->data_size) {
        return false;
    }
    uint64_t val = 0;
    for (size_t i = 0; i < w; i++) {
        val |= (uint64_t) c->data[c->cursor + i] << (8 * i);
    }
    c->cursor += w;
    *out = val;
    return true;
}

// Build the packed argument path for the current leaf (the top frame) into the
// reusable scratch buffer. Returns 0 on success, 1 when the path cannot be
// represented (too many steps, or a step value too wide — the leaf is then
// silently skipped, not an error), and -1 on out-of-space.
static int build_path(walk_ctx_t *c, size_t *out_len) {
    size_t steps = c->stack_len - 1;  // every frame but the root contributes one step
    if (steps > 0xFF) {
        return 1;
    }

    size_t total = 1;  // leading step_count byte
    for (size_t i = 1; i < c->stack_len; i++) {
        size_t w = step_width(c->stack[i].parent_kind);
        if (w == 0) {
            return 1;
        }
        total += w;
    }

    if (c->path_cap < total) {
        uint8_t *np = APP_MEM_REALLOC(c->path, total);
        if (np == NULL) {
            PRINTF("idl_walker: scratch path allocation failed\n");
            return -1;
        }
        c->path = np;
        c->path_cap = total;
    }

    c->path[0] = (uint8_t) steps;
    size_t off = 1;
    for (size_t i = 1; i < c->stack_len; i++) {
        size_t w = step_width(c->stack[i].parent_kind);
        size_t val = c->stack[i].step_value;
        if (w < sizeof(size_t) && (val >> (w * 8)) != 0) {
            return 1;  // step value does not fit its width
        }
        for (size_t b = 0; b < w; b++) {
            c->path[off + b] = (uint8_t) (val >> (8 * (w - 1 - b)));  // big-endian
        }
        off += w;
    }

    *out_len = total;
    return 0;
}

// Hand one decoded leaf to the callback. Returns 0 on success (including a
// silently skipped unrepresentable path), -1 on out-of-space.
static int emit_leaf(walk_ctx_t *c, uint8_t kind, const uint8_t *value, size_t value_size) {
    if (c->cb == NULL) {
        return 0;
    }
    size_t path_len;
    int r = build_path(c, &path_len);
    if (r < 0) {
        return -1;
    }
    if (r > 0) {
        return 0;  // unrepresentable path — skip emission, keep walking
    }
    idl_leaf_t leaf = {
        .path = c->path,
        .path_size = path_len,
        .kind = kind,
        .value = value,
        .value_size = value_size,
    };
    c->cb(&leaf, c->cb_ctx);
    return 0;
}

static int push_frame(walk_ctx_t *c, uint8_t entry_idx, uint8_t parent_kind, size_t step_value) {
    if (entry_idx >= c->pool_count) {
        return -1;
    }
    if (c->stack_len == c->stack_cap) {
        size_t ncap = c->stack_cap * 2;
        frame_t *ns = APP_MEM_REALLOC(c->stack, ncap * sizeof(frame_t));
        if (ns == NULL) {
            PRINTF("idl_walker: frame stack growth failed\n");
            return -1;
        }
        c->stack = ns;
        c->stack_cap = ncap;
    }
    frame_t *f = &c->stack[c->stack_len++];
    f->entry_idx = entry_idx;
    f->kind = c->pool[entry_idx].kind;
    f->entered = false;
    f->child_i = 0;
    f->child_count = 0;
    f->mark = 0;
    f->parent_kind = parent_kind;
    f->step_value = step_value;
    return 0;
}

// Descend into the current frame's next child, or pop the frame when its
// children are exhausted. Used by every aggregate/option/hidden kind whose
// child count is fixed once `entered`.
static int step_children(walk_ctx_t *c, frame_t *f, const entry_t *e) {
    if (f->child_i < f->child_count) {
        uint8_t ref_idx;
        size_t step_val;
        select_child(e, f->kind, f->child_i, &ref_idx, &step_val);
        uint8_t parent_kind = f->kind;
        f->child_i++;
        // push_frame may reallocate the stack: do not touch `f` afterwards.
        return push_frame(c, ref_idx, parent_kind, step_val);
    }
    c->stack_len--;  // pop
    return 0;
}

// Process one unit of work on the top frame: emit a leaf and pop, descend into
// a child, or pop. Returns 0 on progress, -1 on a fatal error.
static int walk_top(walk_ctx_t *c) {
    frame_t *f = &c->stack[c->stack_len - 1];
    const entry_t *e = &c->pool[f->entry_idx];

    switch (f->kind) {
        // ---- fixed-width primitive / pubkey leaves --------------------------
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
        case IDL_KIND_BOOL_U8:
        case IDL_KIND_BOOL_U16:
        case IDL_KIND_BOOL_U32:
        case IDL_KIND_PUBKEY_32: {
            size_t w = fixed_primitive_width(f->kind);
            if (c->cursor + w > c->data_size) {
                return -1;
            }
            const uint8_t *val = c->data + c->cursor;
            if (emit_leaf(c, f->kind, val, w) != 0) {
                return -1;
            }
            c->cursor += w;
            c->stack_len--;
            return 0;
        }

        // ---- variable-width SHORT_U16 leaf ----------------------------------
        case IDL_KIND_SHORT_U16: {
            size_t start = c->cursor;
            uint64_t v;
            if (!read_short_u16(c, &v)) {
                return -1;
            }
            const uint8_t *val = c->data + start;
            if (emit_leaf(c, f->kind, val, c->cursor - start) != 0) {
                return -1;
            }
            c->stack_len--;
            return 0;
        }

        // ---- fixed byte/string leaves ---------------------------------------
        case IDL_KIND_BYTES_FIXED:
        case IDL_KIND_STRING_FIXED: {
            size_t w = e->fixed_size;
            if (c->cursor + w > c->data_size) {
                return -1;
            }
            const uint8_t *val = c->data + c->cursor;
            if (emit_leaf(c, f->kind, val, w) != 0) {
                return -1;
            }
            c->cursor += w;
            c->stack_len--;
            return 0;
        }

        // ---- length-prefixed string leaf ------------------------------------
        case IDL_KIND_STRING_PREFIXED: {
            uint64_t len;
            if (!read_uint_le(c, e->len_kind, &len)) {
                return -1;
            }
            if (c->cursor + len > c->data_size) {
                return -1;
            }
            const uint8_t *val = c->data + c->cursor;
            if (emit_leaf(c, f->kind, val, (size_t) len) != 0) {
                return -1;
            }
            c->cursor += len;
            c->stack_len--;
            return 0;
        }

        // ---- tail-of-buffer raw bytes leaf ----------------------------------
        case IDL_KIND_BYTES_REMAINDER: {
            const uint8_t *val = c->data + c->cursor;
            size_t w = c->data_size - c->cursor;
            if (emit_leaf(c, f->kind, val, w) != 0) {
                return -1;
            }
            c->cursor = c->data_size;
            c->stack_len--;
            return 0;
        }

        // ---- aggregates with a fixed child count ----------------------------
        case IDL_KIND_STRUCT:
        case IDL_KIND_TUPLE:
            if (!f->entered) {
                f->child_count = e->ref_count;
                f->child_i = 0;
                f->entered = true;
            }
            return step_children(c, f, e);

        case IDL_KIND_ARRAY_FIXED:
            if (!f->entered) {
                f->child_count = e->fixed_size;
                f->child_i = 0;
                f->entered = true;
            }
            return step_children(c, f, e);

        case IDL_KIND_ARRAY_PREFIXED:
            if (!f->entered) {
                uint64_t len;
                if (!read_uint_le(c, e->len_kind, &len)) {
                    return -1;
                }
                f->child_count = (size_t) len;
                f->child_i = 0;
                f->entered = true;
            }
            return step_children(c, f, e);

        // ---- remainder array: iterate until the buffer is consumed ----------
        case IDL_KIND_ARRAY_REMAINDER: {
            if (f->entered && c->cursor == f->mark) {
                // The previous element consumed no bytes — would loop forever.
                PRINTF("idl_walker: ARRAY_REMAINDER element consumed no bytes\n");
                return -1;
            }
            if (c->cursor < c->data_size) {
                uint8_t ref_idx;
                size_t step_val;
                select_child(e, f->kind, f->child_i, &ref_idx, &step_val);
                uint8_t parent_kind = f->kind;
                f->entered = true;
                f->mark = c->cursor;
                f->child_i++;
                return push_frame(c, ref_idx, parent_kind, step_val);
            }
            c->stack_len--;
            return 0;
        }

        // ---- options --------------------------------------------------------
        case IDL_KIND_OPTION_DYNAMIC:
            if (!f->entered) {
                uint64_t flag;
                if (!read_uint_le(c, e->flag_kind, &flag)) {
                    return -1;
                }
                f->child_count = (flag != 0) ? 1 : 0;
                f->child_i = 0;
                f->entered = true;
            }
            return step_children(c, f, e);

        case IDL_KIND_OPTION_FIXED:
            if (!f->entered) {
                uint64_t flag;
                if (!read_uint_le(c, e->flag_kind, &flag)) {
                    return -1;
                }
                if (flag != 0) {
                    f->child_count = 1;
                } else {
                    size_t inner = c->fixed_sizes[e->refs[0]];
                    if (inner == FS_VARIABLE) {
                        PRINTF("idl_walker: OPTION_FIXED with variable-size inner\n");
                        return -1;
                    }
                    if (c->cursor + inner > c->data_size) {
                        return -1;
                    }
                    c->cursor += inner;
                    f->child_count = 0;
                }
                f->child_i = 0;
                f->entered = true;
            }
            return step_children(c, f, e);

        case IDL_KIND_OPTION_ZEROABLE:
            if (!f->entered) {
                size_t slen = e->sentinel_len;
                bool match;
                if (slen == 0) {
                    match = true;
                } else if (c->cursor + slen > c->data_size) {
                    match = false;
                } else {
                    match = (memcmp(c->data + c->cursor, e->sentinel, slen) == 0);
                }
                if (match) {
                    c->cursor += slen;
                    f->child_count = 0;
                } else {
                    f->child_count = 1;
                }
                f->child_i = 0;
                f->entered = true;
            }
            return step_children(c, f, e);

        case IDL_KIND_OPTION_REMAINDER:
            if (!f->entered) {
                f->child_count = (c->cursor < c->data_size) ? 1 : 0;
                f->child_i = 0;
                f->entered = true;
            }
            return step_children(c, f, e);

        // ---- hidden wrappers ------------------------------------------------
        case IDL_KIND_HIDDEN_PREFIX:
        case IDL_KIND_HIDDEN_SUFFIX:
            if (!f->entered) {
                f->child_count = 2;
                f->child_i = 0;
                f->entered = true;
            }
            return step_children(c, f, e);

        // ---- deferred / unsupported -----------------------------------------
        case IDL_KIND_ENUM:
            PRINTF("idl_walker: ENUM not supported yet (enum_id=%.*s)\n",
                   e->enum_id_len,
                   e->enum_id);
            return -1;

        default:
            PRINTF("idl_walker: unhandled kind 0x%02x\n", f->kind);
            return -1;
    }
}

// =============================================================================
// Public API
// =============================================================================

void idl_walker_init(idl_walker_t *walker) {
    if (walker == NULL) {
        return;
    }
    memset(walker, 0, sizeof(*walker));
}

int idl_walker_provide_pool(idl_walker_t *walker,
                            const uint8_t *pool,
                            size_t pool_size,
                            uint8_t root_index) {
    if (walker == NULL) {
        return -1;
    }
    if (pool == NULL && pool_size > 0) {
        PRINTF("idl_walker_provide_pool: NULL pool with non-zero size\n");
        return -1;
    }

    // Borrow the caller's buffer; it must outlive the walk (until reset).
    walker->pool = pool;
    walker->pool_size = pool_size;
    walker->root_index = root_index;
    walker->pool_ready = true;

    PRINTF("idl_walker: received IDL type pool (size=%d, root_index=%d)\n",
           walker->pool_size,
           walker->root_index);
    return 0;
}

int idl_walker_provide_instruction_data(idl_walker_t *walker,
                                        const uint8_t *data,
                                        size_t data_size) {
    if (walker == NULL) {
        return -1;
    }
    if (data == NULL && data_size > 0) {
        PRINTF("idl_walker_provide_instruction_data: NULL data with non-zero size\n");
        return -1;
    }

    // Borrow the caller's buffer; it must outlive the walk (until reset).
    walker->data = data;
    walker->data_size = data_size;
    walker->data_ready = true;

    PRINTF("idl_walker: received instruction data (size=%d)\n", walker->data_size);
    return 0;
}

int idl_walker_run(idl_walker_t *walker, idl_leaf_cb_t cb, void *ctx) {
    if (walker == NULL) {
        return -1;
    }
    if (!walker->pool_ready || !walker->data_ready) {
        PRINTF("idl_walker_run: missing inputs (pool_ready=%d, data_ready=%d)\n",
               walker->pool_ready,
               walker->data_ready);
        return -1;
    }

    entry_t *entries = NULL;
    uint8_t count = 0;
    if (parse_pool(walker->pool, walker->pool_size, &entries, &count) != 0) {
        return -1;
    }
    if (walker->root_index >= count) {
        PRINTF("idl_walker: root_index %d out of range (count=%d)\n", walker->root_index, count);
        APP_MEM_FREE(entries);
        return -1;
    }

    size_t *fixed_sizes = NULL;
    if (pool_has_option_fixed(entries, count)) {
        if (compute_fixed_sizes(entries, count, &fixed_sizes) != 0) {
            APP_MEM_FREE(entries);
            return -1;
        }
    }

    walk_ctx_t c = {0};
    c.data = walker->data;
    c.data_size = walker->data_size;
    c.cursor = 0;
    c.pool = entries;
    c.pool_count = count;
    c.fixed_sizes = fixed_sizes;
    c.cb = cb;
    c.cb_ctx = ctx;
    c.stack_cap = 8;
    c.stack = APP_MEM_ALLOC(c.stack_cap * sizeof(frame_t));

    int rc = 0;
    if (c.stack == NULL) {
        PRINTF("idl_walker: frame stack allocation failed\n");
        rc = -1;
    } else {
        rc = push_frame(&c, walker->root_index, 0, 0);
        while (rc == 0 && c.stack_len > 0) {
            rc = walk_top(&c);
        }
        // The walk must land exactly on the end of the instruction data.
        if (rc == 0 && c.cursor != c.data_size) {
            PRINTF("idl_walker: cursor %d != data_size %d (fail closed)\n",
                   c.cursor,
                   c.data_size);
            rc = -1;
        }
    }

    APP_MEM_FREE(c.path);
    APP_MEM_FREE(c.stack);
    APP_MEM_FREE(fixed_sizes);
    APP_MEM_FREE(entries);
    return rc;
}

void idl_walker_reset(idl_walker_t *walker) {
    if (walker == NULL) {
        return;
    }
    // pool and data are borrowed; just drop the references, never free them.
    walker->pool = NULL;
    walker->pool_size = 0;
    walker->root_index = 0;
    walker->pool_ready = false;

    walker->data = NULL;
    walker->data_size = 0;
    walker->data_ready = false;
}
