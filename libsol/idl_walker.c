// IDL walker. See idl_walker.h for the contract.
//
// Decodes the raw argument bytes of a Solana instruction against the
// kind-driven IDL_TYPE_POOL descriptor and streams every decoded leaf to a
// caller-supplied callback. The pool descriptor is owned by the idl_pool
// module and read here through its getters; the data bytes are borrowed,
// never copied. The walk's own scratch (frame stack, path, fixed-size table)
// is released before idl_walker_run() returns.
//
// Descent is iterative over an explicit heap frame stack (no C recursion), so
// deeply nested descriptors cannot overflow the device stack. The walk fails
// closed (returns -1) on any descriptor/data inconsistency.

#include <string.h>

#include "idl_walker.h"
#include "idl_pool.h"
#include "util.h"
#include "app_mem_utils.h"

// =============================================================================
// Static-size table (OPTION_FIXED skip)
// =============================================================================

// Fixed-size table sentinels (see compute_fixed_sizes).
#define FS_UNKNOWN  (SIZE_MAX)
#define FS_VARIABLE (SIZE_MAX - 1)

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

// Try to determine the static serialized size of pool entry `idx` from the
// partially filled size table `sizes`. Writes the result to *out and returns
// true when it can be decided now; returns false when a child size is still
// FS_UNKNOWN.
static bool try_static_size(uint8_t idx, const size_t *sizes, size_t *out) {
    const idl_pool_entry_t *entry = idl_pool_entry(idx);
    uint8_t kind = entry->kind;

    size_t primitive_width = fixed_primitive_width(kind);
    if (primitive_width != 0) {
        *out = primitive_width;
        return true;
    }

    switch (kind) {
        case IDL_KIND_BYTES_FIXED:
        case IDL_KIND_STRING_FIXED:
            *out = entry->fixed_size;
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
            for (uint8_t j = 0; j < entry->ref_count; j++) {
                size_t child_size = sizes[entry->refs[j]];
                if (child_size == FS_UNKNOWN) {
                    return false;
                }
                if (child_size == FS_VARIABLE) {
                    *out = FS_VARIABLE;
                    return true;
                }
                total += child_size;
            }
            *out = total;
            return true;
        }

        case IDL_KIND_ARRAY_FIXED: {
            size_t child_size = sizes[entry->refs[0]];
            if (child_size == FS_UNKNOWN) {
                return false;
            }
            if (child_size == FS_VARIABLE) {
                *out = FS_VARIABLE;
                return true;
            }
            *out = (size_t) entry->fixed_size * child_size;
            return true;
        }

        case IDL_KIND_OPTION_FIXED: {
            size_t child_size = sizes[entry->refs[0]];
            if (child_size == FS_UNKNOWN) {
                return false;
            }
            if (child_size == FS_VARIABLE) {
                *out = FS_VARIABLE;
                return true;
            }
            *out = fixed_primitive_width(entry->flag_kind) + child_size;
            return true;
        }

        case IDL_KIND_OPTION_ZEROABLE: {
            size_t child_size = sizes[entry->refs[0]];
            if (child_size == FS_UNKNOWN) {
                return false;
            }
            *out = child_size;  // sentinel and inner occupy the same width
            return true;
        }

        case IDL_KIND_HIDDEN_PREFIX:
        case IDL_KIND_HIDDEN_SUFFIX: {
            size_t skip_size = sizes[entry->refs[0]];
            size_t inner_size = sizes[entry->refs[1]];
            if (skip_size == FS_UNKNOWN || inner_size == FS_UNKNOWN) {
                return false;
            }
            if (skip_size == FS_VARIABLE || inner_size == FS_VARIABLE) {
                *out = FS_VARIABLE;
                return true;
            }
            *out = skip_size + inner_size;
            return true;
        }

        default:
            *out = FS_VARIABLE;
            return true;
    }
}

// Compute the static-size table for every pool entry via a fixpoint pass (no
// recursion). Entries that cannot be resolved (e.g. reference cycles) are left
// FS_VARIABLE, so any OPTION_FIXED that depends on them is rejected at walk.
//
// Returns 0 on success (caller owns *out_sizes), -1 on out-of-space.
static int compute_fixed_sizes(uint8_t count, size_t **out_sizes) {
    size_t alloc_count = (count == 0) ? 1 : count;
    size_t *sizes = APP_MEM_ALLOC(alloc_count * sizeof(size_t));
    if (sizes == NULL) {
        PRINTF("idl_walker: fixed-size table allocation failed\n");
        return -1;
    }
    for (size_t i = 0; i < alloc_count; i++) {
        sizes[i] = FS_UNKNOWN;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (uint8_t i = 0; i < count; i++) {
            if (sizes[i] != FS_UNKNOWN) {
                continue;
            }
            size_t size;
            if (try_static_size(i, sizes, &size)) {
                sizes[i] = size;
                changed = true;
            }
        }
    }

    // Anything still unknown is part of a cycle; treat as variable.
    for (uint8_t i = 0; i < count; i++) {
        if (sizes[i] == FS_UNKNOWN) {
            PRINTF("idl_walker: entry %d size unresolved (cycle), marking variable\n", i);
            sizes[i] = FS_VARIABLE;
        }
        PRINTF("idl_walker: fixed_size[%d]=%d\n", i, sizes[i]);
    }

    *out_sizes = sizes;
    return 0;
}

static bool pool_has_option_fixed(void) {
    uint8_t count = idl_pool_count();
    for (uint8_t i = 0; i < count; i++) {
        if (idl_pool_entry(i)->kind == IDL_KIND_OPTION_FIXED) {
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

    const size_t *fixed_sizes;  // NULL unless the pool contains an OPTION_FIXED

    frame_t *stack;
    size_t stack_len;
    size_t stack_cap;

    uint8_t *path;     // reusable scratch path buffer
    size_t path_cap;

    idl_leaf_cb_t leaf_callback;
    void *callback_context;
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
static void select_child(const idl_pool_entry_t *entry,
                         uint8_t kind,
                         size_t child_i,
                         uint8_t *ref_idx,
                         size_t *step_val) {
    switch (kind) {
        case IDL_KIND_STRUCT:
        case IDL_KIND_TUPLE:
            *ref_idx = entry->refs[child_i];
            *step_val = child_i;
            break;
        case IDL_KIND_ARRAY_FIXED:
        case IDL_KIND_ARRAY_PREFIXED:
        case IDL_KIND_ARRAY_REMAINDER:
            *ref_idx = entry->refs[0];
            *step_val = child_i;
            break;
        case IDL_KIND_OPTION_DYNAMIC:
        case IDL_KIND_OPTION_FIXED:
        case IDL_KIND_OPTION_ZEROABLE:
        case IDL_KIND_OPTION_REMAINDER:
            *ref_idx = entry->refs[0];
            *step_val = 0;
            break;
        case IDL_KIND_HIDDEN_PREFIX:
            // skip side first (step 1, never displayed), then inner (step 0).
            if (child_i == 0) {
                *ref_idx = entry->refs[0];
                *step_val = 1;
            } else {
                *ref_idx = entry->refs[1];
                *step_val = 0;
            }
            break;
        case IDL_KIND_HIDDEN_SUFFIX:
            // inner side first (step 0), then skip (step 1, never displayed).
            if (child_i == 0) {
                *ref_idx = entry->refs[1];
                *step_val = 0;
            } else {
                *ref_idx = entry->refs[0];
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
static bool read_short_u16(walk_ctx_t *walk, uint64_t *out) {
    uint64_t value = 0;
    for (int i = 0; i < 3; i++) {
        if (walk->cursor >= walk->data_size) {
            PRINTF("idl_walker: SHORT_U16 read past end of data\n");
            return false;
        }
        uint8_t byte = walk->data[walk->cursor++];
        value |= (uint64_t) (byte & 0x7F) << (7 * i);
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    *out = value;
    PRINTF("idl_walker: read SHORT_U16 value=%d cursor=%d\n", value, walk->cursor);
    return true;
}
// Read a little-endian unsigned integer of the given primitive `kind` (or a
// SHORT_U16 varint) from the cursor, advancing it. Returns false on a read
// past the end of the data or an unsupported kind.
static bool read_uint_le(walk_ctx_t *walk, uint8_t kind, uint64_t *out) {
    if (kind == IDL_KIND_SHORT_U16) {
        return read_short_u16(walk, out);
    }
    size_t width = fixed_primitive_width(kind);
    if (width == 0 || width > 8) {
        PRINTF("idl_walker: kind 0x%02x is not a readable integer length\n", kind);
        return false;
    }
    if (walk->cursor + width > walk->data_size) {
        PRINTF("idl_walker: integer read past end of data\n");
        return false;
    }
    uint64_t value = 0;
    for (size_t i = 0; i < width; i++) {
        value |= (uint64_t) walk->data[walk->cursor + i] << (8 * i);
    }
    walk->cursor += width;
    *out = value;
    PRINTF("idl_walker: read uint kind=0x%02x width=%d value=%d cursor=%d\n",
           kind,
           width,
           value,
           walk->cursor);
    return true;
}

// Build the packed argument path for the current leaf (the top frame) into the
// reusable scratch buffer. Returns 0 on success, 1 when the path cannot be
// represented (the leaf is then silently skipped, not an error), -1 on
// out-of-space.
static int build_path(walk_ctx_t *walk, size_t *out_len) {
    size_t steps = walk->stack_len - 1;  // every frame but the root contributes one step
    if (steps > 0xFF) {
        return 1;
    }

    size_t total = 1;  // leading step_count byte
    for (size_t i = 1; i < walk->stack_len; i++) {
        size_t width = step_width(walk->stack[i].parent_kind);
        if (width == 0) {
            return 1;
        }
        total += width;
    }

    if (walk->path_cap < total) {
        uint8_t *new_path = APP_MEM_REALLOC(walk->path, total);
        if (new_path == NULL) {
            PRINTF("idl_walker: scratch path allocation failed\n");
            return -1;
        }
        walk->path = new_path;
        walk->path_cap = total;
    }

    walk->path[0] = (uint8_t) steps;
    size_t offset = 1;
    for (size_t i = 1; i < walk->stack_len; i++) {
        size_t width = step_width(walk->stack[i].parent_kind);
        size_t value = walk->stack[i].step_value;
        if (width < sizeof(size_t) && (value >> (width * 8)) != 0) {
            return 1;  // step value does not fit its width
        }
        for (size_t byte_i = 0; byte_i < width; byte_i++) {
            walk->path[offset + byte_i] = (uint8_t) (value >> (8 * (width - 1 - byte_i)));
        }
        offset += width;
    }

    *out_len = total;
    return 0;
}

// Hand one decoded leaf to the callback. Returns 0 on success (including a
// silently skipped unrepresentable path), -1 on out-of-space.
static int emit_leaf(walk_ctx_t *walk, uint8_t kind, const uint8_t *value, size_t value_size) {
    if (walk->leaf_callback == NULL) {
        PRINTF("idl_walker: no callback, skipping leaf kind=0x%02x\n", kind);
        return 0;
    }
    size_t path_len;
    int build_result = build_path(walk, &path_len);
    if (build_result < 0) {
        PRINTF("idl_walker: build_path failed for leaf kind=0x%02x\n", kind);
        return -1;
    }
    if (build_result > 0) {
        PRINTF("idl_walker: unrepresentable path for leaf kind=0x%02x, skipping\n", kind);
        return 0;  // unrepresentable path — skip emission, keep walking
    }
    idl_leaf_t leaf = {
        .path = walk->path,
        .path_size = path_len,
        .kind = kind,
        .value = value,
        .value_size = value_size,
    };
    PRINTF("idl_walker: emit leaf kind=0x%02x value_size=%d path_size=%d\n",
           kind,
           value_size,
           path_len);
    walk->leaf_callback(&leaf, walk->callback_context);
    return 0;
}

static int push_frame(walk_ctx_t *walk, uint8_t entry_idx, uint8_t parent_kind, size_t step_value) {
    const idl_pool_entry_t *entry = idl_pool_entry(entry_idx);
    if (entry == NULL) {
        PRINTF("idl_walker: push_frame ref %d out of range\n", entry_idx);
        return -1;
    }
    if (walk->stack_len == walk->stack_cap) {
        size_t new_cap = walk->stack_cap * 2;
        frame_t *new_stack = APP_MEM_REALLOC(walk->stack, new_cap * sizeof(frame_t));
        if (new_stack == NULL) {
            PRINTF("idl_walker: frame stack growth failed\n");
            return -1;
        }
        walk->stack = new_stack;
        walk->stack_cap = new_cap;
    }
    frame_t *frame = &walk->stack[walk->stack_len++];
    frame->entry_idx = entry_idx;
    frame->kind = entry->kind;
    frame->entered = false;
    frame->child_i = 0;
    frame->child_count = 0;
    frame->mark = 0;
    frame->parent_kind = parent_kind;
    frame->step_value = step_value;
    PRINTF("idl_walker: push_frame entry_idx=%d kind=0x%02x parent_kind=0x%02x step_value=%d depth=%d\n",
           entry_idx,
           frame->kind,
           parent_kind,
           step_value,
           walk->stack_len);
    return 0;
}

// Descend into the current frame's next child, or pop the frame when its
// children are exhausted. Used by every aggregate/option/hidden kind whose
// child count is fixed once `entered`.
static int step_children(walk_ctx_t *walk, frame_t *frame, const idl_pool_entry_t *entry) {
    if (frame->child_i < frame->child_count) {
        uint8_t ref_idx;
        size_t step_val;
        select_child(entry, frame->kind, frame->child_i, &ref_idx, &step_val);
        uint8_t parent_kind = frame->kind;
        frame->child_i++;
        // push_frame may reallocate the stack: do not touch `frame` afterwards.
        return push_frame(walk, ref_idx, parent_kind, step_val);
    }
    walk->stack_len--;  // pop
    return 0;
}

// Process one unit of work on the top frame: emit a leaf and pop, descend into
// a child, or pop. Returns 0 on progress, -1 on a fatal error.
static int walk_top(walk_ctx_t *walk) {
    frame_t *frame = &walk->stack[walk->stack_len - 1];
    const idl_pool_entry_t *entry = idl_pool_entry(frame->entry_idx);
    PRINTF("idl_walker: walk_top entry_idx=%d kind=0x%02x cursor=%d depth=%d\n",
           frame->entry_idx,
           frame->kind,
           walk->cursor,
           walk->stack_len);

    switch (frame->kind) {
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
            size_t width = fixed_primitive_width(frame->kind);
            if (walk->cursor + width > walk->data_size) {
                PRINTF("idl_walker: primitive kind 0x%02x read past end of data\n", frame->kind);
                return -1;
            }
            const uint8_t *value = walk->data + walk->cursor;
            PRINTF("idl_walker: primitive leaf kind=0x%02x width=%d value=%.*H\n",
                   frame->kind,
                   width,
                   width,
                   value);
            if (emit_leaf(walk, frame->kind, value, width) != 0) {
                return -1;
            }
            walk->cursor += width;
            walk->stack_len--;
            return 0;
        }

        // ---- variable-width SHORT_U16 leaf ----------------------------------
        case IDL_KIND_SHORT_U16: {
            size_t start = walk->cursor;
            uint64_t value;
            if (!read_short_u16(walk, &value)) {
                return -1;
            }
            if (emit_leaf(walk, frame->kind, walk->data + start, walk->cursor - start) != 0) {
                return -1;
            }
            walk->stack_len--;
            return 0;
        }

        // ---- fixed byte/string leaves ---------------------------------------
        case IDL_KIND_BYTES_FIXED:
        case IDL_KIND_STRING_FIXED: {
            size_t width = entry->fixed_size;
            if (walk->cursor + width > walk->data_size) {
                PRINTF("idl_walker: fixed bytes/string read past end of data\n");
                return -1;
            }
            const uint8_t *value = walk->data + walk->cursor;
            PRINTF("idl_walker: fixed bytes/string leaf kind=0x%02x width=%d\n", frame->kind, width);
            if (emit_leaf(walk, frame->kind, value, width) != 0) {
                return -1;
            }
            walk->cursor += width;
            walk->stack_len--;
            return 0;
        }

        // ---- length-prefixed string leaf ------------------------------------
        case IDL_KIND_STRING_PREFIXED: {
            uint64_t len;
            if (!read_uint_le(walk, entry->len_kind, &len)) {
                return -1;
            }
            if (walk->cursor + len > walk->data_size) {
                PRINTF("idl_walker: prefixed string body read past end of data\n");
                return -1;
            }
            const uint8_t *value = walk->data + walk->cursor;
            PRINTF("idl_walker: prefixed string leaf len=%d\n", len);
            if (emit_leaf(walk, frame->kind, value, (size_t) len) != 0) {
                return -1;
            }
            walk->cursor += len;
            walk->stack_len--;
            return 0;
        }

        // ---- tail-of-buffer raw bytes leaf ----------------------------------
        case IDL_KIND_BYTES_REMAINDER: {
            const uint8_t *value = walk->data + walk->cursor;
            size_t width = walk->data_size - walk->cursor;
            PRINTF("idl_walker: bytes remainder leaf width=%d\n", width);
            if (emit_leaf(walk, frame->kind, value, width) != 0) {
                return -1;
            }
            walk->cursor = walk->data_size;
            walk->stack_len--;
            return 0;
        }

        // ---- aggregates with a fixed child count ----------------------------
        case IDL_KIND_STRUCT:
        case IDL_KIND_TUPLE:
            if (!frame->entered) {
                frame->child_count = entry->ref_count;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry);

        case IDL_KIND_ARRAY_FIXED:
            if (!frame->entered) {
                frame->child_count = entry->fixed_size;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry);

        case IDL_KIND_ARRAY_PREFIXED:
            if (!frame->entered) {
                uint64_t len;
                if (!read_uint_le(walk, entry->len_kind, &len)) {
                    return -1;
                }
                PRINTF("idl_walker: ARRAY_PREFIXED element count=%d\n", len);
                frame->child_count = (size_t) len;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry);

        // ---- remainder array: iterate until the buffer is consumed ----------
        case IDL_KIND_ARRAY_REMAINDER: {
            if (frame->entered && walk->cursor == frame->mark) {
                // The previous element consumed no bytes — would loop forever.
                PRINTF("idl_walker: ARRAY_REMAINDER element consumed no bytes\n");
                return -1;
            }
            if (walk->cursor < walk->data_size) {
                uint8_t ref_idx;
                size_t step_val;
                select_child(entry, frame->kind, frame->child_i, &ref_idx, &step_val);
                uint8_t parent_kind = frame->kind;
                frame->entered = true;
                frame->mark = walk->cursor;
                frame->child_i++;
                return push_frame(walk, ref_idx, parent_kind, step_val);
            }
            walk->stack_len--;
            return 0;
        }

        // ---- options --------------------------------------------------------
        case IDL_KIND_OPTION_DYNAMIC:
            if (!frame->entered) {
                uint64_t flag;
                if (!read_uint_le(walk, entry->flag_kind, &flag)) {
                    return -1;
                }
                PRINTF("idl_walker: OPTION_DYNAMIC flag=%d (%s)\n",
                       flag,
                       (flag != 0) ? "present" : "absent");
                frame->child_count = (flag != 0) ? 1 : 0;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry);

        case IDL_KIND_OPTION_FIXED:
            if (!frame->entered) {
                uint64_t flag;
                if (!read_uint_le(walk, entry->flag_kind, &flag)) {
                    return -1;
                }
                if (flag != 0) {
                    PRINTF("idl_walker: OPTION_FIXED flag=%d present, descending\n", flag);
                    frame->child_count = 1;
                } else {
                    size_t inner_size = walk->fixed_sizes[entry->refs[0]];
                    PRINTF("idl_walker: OPTION_FIXED flag=0 absent, skipping inner_size=%d\n",
                           inner_size);
                    if (inner_size == FS_VARIABLE) {
                        PRINTF("idl_walker: OPTION_FIXED with variable-size inner\n");
                        return -1;
                    }
                    if (walk->cursor + inner_size > walk->data_size) {
                        PRINTF("idl_walker: OPTION_FIXED skip past end of data\n");
                        return -1;
                    }
                    walk->cursor += inner_size;
                    frame->child_count = 0;
                }
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry);

        case IDL_KIND_OPTION_ZEROABLE:
            if (!frame->entered) {
                size_t sentinel_len = entry->sentinel_len;
                bool match;
                if (sentinel_len == 0) {
                    match = true;
                } else if (walk->cursor + sentinel_len > walk->data_size) {
                    match = false;
                } else {
                    match = (memcmp(walk->data + walk->cursor, entry->sentinel, sentinel_len) == 0);
                }
                if (match) {
                    PRINTF("idl_walker: OPTION_ZEROABLE sentinel matched (len=%d), absent\n",
                           sentinel_len);
                    walk->cursor += sentinel_len;
                    frame->child_count = 0;
                } else {
                    PRINTF("idl_walker: OPTION_ZEROABLE sentinel mismatch, present\n");
                    frame->child_count = 1;
                }
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry);

        case IDL_KIND_OPTION_REMAINDER:
            if (!frame->entered) {
                frame->child_count = (walk->cursor < walk->data_size) ? 1 : 0;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry);

        // ---- hidden wrappers ------------------------------------------------
        case IDL_KIND_HIDDEN_PREFIX:
        case IDL_KIND_HIDDEN_SUFFIX:
            if (!frame->entered) {
                frame->child_count = 2;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry);

        // ---- deferred / unsupported -----------------------------------------
        case IDL_KIND_ENUM:
            PRINTF("idl_walker: ENUM not supported yet (enum_id=%.*s)\n",
                   entry->enum_id_len,
                   entry->enum_id);
            return -1;

        default:
            PRINTF("idl_walker: unhandled kind 0x%02x\n", frame->kind);
            return -1;
    }
}

// =============================================================================
// Public API
// =============================================================================

int idl_walker_run(const uint8_t *data,
                   size_t data_size,
                   idl_leaf_cb_t leaf_callback,
                   void *callback_context) {
    if (!idl_pool_ready()) {
        PRINTF("idl_walker_run: no pool provided\n");
        return -1;
    }
    if (data == NULL && data_size > 0) {
        PRINTF("idl_walker_run: NULL data with non-zero size (data_size=%d)\n", data_size);
        return -1;
    }

    uint8_t entry_count = idl_pool_count();
    uint8_t root_index = idl_pool_root_index();
    PRINTF("idl_walker_run: starting (entry_count=%d, root_index=%d, data_size=%d)\n",
           entry_count,
           root_index,
           data_size);

    size_t *fixed_sizes = NULL;
    if (pool_has_option_fixed()) {
        PRINTF("idl_walker_run: pool has OPTION_FIXED, building fixed-size table\n");
        if (compute_fixed_sizes(entry_count, &fixed_sizes) != 0) {
            PRINTF("idl_walker_run: fixed-size table build failed\n");
            return -1;
        }
    }

    walk_ctx_t walk = {0};
    walk.data = data;
    walk.data_size = data_size;
    walk.cursor = 0;
    walk.fixed_sizes = fixed_sizes;
    walk.leaf_callback = leaf_callback;
    walk.callback_context = callback_context;
    walk.stack_cap = 8;
    walk.stack = APP_MEM_ALLOC(walk.stack_cap * sizeof(frame_t));

    int walk_result = 0;
    if (walk.stack == NULL) {
        PRINTF("idl_walker: frame stack allocation failed\n");
        walk_result = -1;
    } else {
        walk_result = push_frame(&walk, root_index, 0, 0);
        while (walk_result == 0 && walk.stack_len > 0) {
            walk_result = walk_top(&walk);
        }
        // The walk must land exactly on the end of the instruction data.
        if (walk_result == 0 && walk.cursor != walk.data_size) {
            PRINTF("idl_walker: cursor %d != data_size %d, refusing\n",
                   walk.cursor,
                   walk.data_size);
            walk_result = -1;
        }
    }

    APP_MEM_FREE(walk.path);
    APP_MEM_FREE(walk.stack);
    APP_MEM_FREE(fixed_sizes);
    PRINTF("idl_walker_run: finished with result=%d (cursor=%d, data_size=%d)\n",
           walk_result,
           walk.cursor,
           walk.data_size);
    return walk_result;
}

