// IDL walker. See idl_walker.h for the contract.
//
// Decodes the raw argument bytes of a Solana instruction against the
// kind-driven IDL_TYPE_POOL descriptor and delivers matched leaves to the
// collector. The pool descriptor is owned by the idl_pool module and read here
// through its getters; the data bytes are borrowed, never copied. The walk's
// own scratch (frame stack, path, fixed-size table) is released before
// idl_walker_run() returns.
//
// Descent is iterative over an explicit heap frame stack (no C recursion), so
// deeply nested descriptors cannot overflow the device stack. The walk fails
// closed (returns -1) on any descriptor/data inconsistency.

#include <string.h>

#include "idl_walker.h"
#include "idl_pool.h"
#include "cs_enum_cache.h"
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
//
// A frame walks either a shared pool entry (is_inline == false, addressed by
// `entry_idx`) or a self-contained inline type descriptor (is_inline == true,
// addressed by `inline_ptr`/`inline_end`). Inline descriptors carry their
// children embedded sequentially instead of as pool ref indices; they back an
// enum variant's INLINE payload.
typedef struct frame_s {
    uint8_t kind;         // cached entry kind (pool or inline header)
    bool entered;         // first-visit work (length/flag reads) already done
    size_t child_i;       // next child to descend into
    size_t child_count;   // total children to descend into
    size_t mark;          // cursor at last child push (ARRAY_REMAINDER progress guard)
    uint8_t parent_kind;  // kind of the parent that pushed this frame (0 = root)
    size_t step_value;    // step index this frame occupies within its parent
    size_t step_bytes;    // byte width of this frame's step in its parent's path

    bool is_inline;  // tags which arm of `source` addresses this frame's node
    union {
        uint8_t entry_idx;  // is_inline == false: pool index of the walked entry
        struct {
            const uint8_t *ptr;  // is_inline == true: inline descriptor start
            const uint8_t *end;  // inline payload buffer end bound
        } inline_descriptor;
    } source;

    // ENUM frames with an INLINE payload stash the descent target here on the
    // first visit so the discriminator is read exactly once. Independent of
    // `is_inline`: an ENUM node may itself be a pool or an inline frame.
    const uint8_t *enum_payload;
    size_t enum_payload_size;
    size_t enum_variant_index;
} frame_t;

// One node on the inline-span work stack (see inline_span). `children_left`
// counts embedded child descriptors still to consume; `is_zeroable` flags an
// OPTION_ZEROABLE whose trailing sentinel is consumed after its child.
typedef struct span_frame_s {
    uint16_t children_left;
    bool is_zeroable;
} span_frame_t;

// One node on the inline data-size work stack (see inline_static_data_size).
// Accumulates the static serialized DATA size of an inline subtree. `kind` is 0
// for the virtual root; `multiplier` scales an ARRAY_FIXED child; `own` holds a
// node's fixed self-contribution (an OPTION_FIXED flag byte width).
typedef struct size_frame_s {
    uint8_t kind;
    uint16_t children_left;
    bool is_zeroable;
    size_t multiplier;
    size_t own;
    size_t acc;
} size_frame_t;

// Growth step for the walk scratch stacks (also their initial capacity). Fixed
// increment rather than doubling: the walk is bounded and shallow, so a small
// linear step keeps the reserved capacity close to the real depth.
#define IDL_WALK_STACK_STEP 8

typedef struct walk_ctx_s {
    // Instruction argument bytes under decode, and the current read offset.
    const uint8_t *data;
    size_t data_size;
    size_t cursor;

    const uint8_t *program_id;  // 32 bytes, enum-variant cache lookup key

    const size_t *fixed_sizes;  // NULL unless the pool contains an OPTION_FIXED

    // Explicit descent stack replacing C recursion; grows on demand.
    frame_t *stack;
    size_t stack_len;
    size_t stack_cap;

    span_frame_t *span_stack;  // reusable scratch for inline_span (grows on demand)
    size_t span_cap;

    size_frame_t *size_stack;  // reusable scratch for inline_static_data_size (grows on demand)
    size_t size_cap;

    uint8_t *path;  // reusable scratch for the current leaf's packed path
    size_t path_cap;

    // Collector I/O: paths to match, the slots filled on a match, and the
    // running count of matched leaves.
    const idl_match_path_t *match_paths;
    size_t match_count;
    idl_resolved_leaf_t *resolved;
    size_t *resolved_count;
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

// =============================================================================
// Inline type descriptors (enum variant INLINE payloads)
// =============================================================================
//
// An INLINE variant payload is a self-contained, kind-prefixed type descriptor
// with the same per-kind header bytes as an IDL_TYPE_POOL entry, except that
// child types are embedded sequentially in place of the pool's u8 ref indices.
// The functions below let the walker descend such a descriptor without a pool.

// Decode just the metadata header of the inline node at `ptr`, reporting its
// kind, the header byte count (excluding embedded children and any trailing
// sentinel), the number of embedded child descriptors, and whether it is an
// OPTION_ZEROABLE (whose sentinel trails its child). Returns 0 on success, -1
// on a truncated or unknown header.
static int inline_header_len(const uint8_t *ptr,
                             const uint8_t *end,
                             uint8_t *out_kind,
                             size_t *out_header_len,
                             uint8_t *out_child_count,
                             bool *out_is_zeroable) {
    if (ptr >= end) {
        PRINTF("idl_walker: inline header read past end\n");
        return -1;
    }
    uint8_t kind = ptr[0];
    size_t header_len;
    uint8_t child_count = 0;
    bool is_zeroable = false;

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
            header_len = 1;
            break;
        case IDL_KIND_BYTES_FIXED:
            header_len = 3;
            break;
        case IDL_KIND_STRING_FIXED:
            header_len = 4;
            break;
        case IDL_KIND_STRING_PREFIXED:
            header_len = 3;
            break;
        case IDL_KIND_STRUCT:
        case IDL_KIND_TUPLE:
            if (ptr + 2 > end) {
                PRINTF("idl_walker: inline struct/tuple header truncated\n");
                return -1;
            }
            child_count = ptr[1];
            header_len = 2;
            break;
        case IDL_KIND_OPTION_DYNAMIC:
        case IDL_KIND_OPTION_FIXED:
            child_count = 1;
            header_len = 2;
            break;
        case IDL_KIND_OPTION_ZEROABLE:
            child_count = 1;
            is_zeroable = true;
            header_len = 1;
            break;
        case IDL_KIND_ARRAY_FIXED:
            child_count = 1;
            header_len = 3;
            break;
        case IDL_KIND_ARRAY_PREFIXED:
            child_count = 1;
            header_len = 2;
            break;
        case IDL_KIND_ARRAY_REMAINDER:
        case IDL_KIND_OPTION_REMAINDER:
            child_count = 1;
            header_len = 1;
            break;
        case IDL_KIND_ENUM:
            if (ptr + 5 > end) {
                PRINTF("idl_walker: inline enum header truncated\n");
                return -1;
            }
            header_len = 5 + (size_t) ptr[4];
            break;
        case IDL_KIND_HIDDEN_PREFIX:
        case IDL_KIND_HIDDEN_SUFFIX:
            child_count = 2;
            header_len = 1;
            break;
        default:
            PRINTF("idl_walker: inline unknown kind 0x%02x\n", kind);
            return -1;
    }

    if (ptr + header_len > end) {
        PRINTF("idl_walker: inline header of kind 0x%02x truncated\n", kind);
        return -1;
    }

    *out_kind = kind;
    *out_header_len = header_len;
    *out_child_count = child_count;
    *out_is_zeroable = is_zeroable;
    return 0;
}

// Compute the byte length of the single inline type subtree rooted at `ptr`
// (its header, all embedded children, and any trailing sentinel). Iterative,
// backed by the reusable per-walk span stack. Returns 0 on success and writes
// *out_span, or -1 on a truncated/unknown descriptor or allocator failure.
static int inline_span(walk_ctx_t *walk, const uint8_t *ptr, const uint8_t *end, size_t *out_span) {
    const uint8_t *cur = ptr;
    size_t depth = 0;

    // Seed with a virtual parent that expects exactly one subtree (the root).
    if (walk->span_cap == 0) {
        walk->span_stack = APP_MEM_ALLOC(8 * sizeof(span_frame_t));
        if (walk->span_stack == NULL) {
            PRINTF("idl_walker: span stack allocation failed\n");
            return -1;
        }
        walk->span_cap = 8;
    }
    walk->span_stack[depth].children_left = 1;
    walk->span_stack[depth].is_zeroable = false;
    depth++;

    while (depth > 0) {
        span_frame_t *top = &walk->span_stack[depth - 1];
        if (top->children_left == 0) {
            if (top->is_zeroable) {
                if (cur >= end) {
                    PRINTF("idl_walker: inline zeroable sentinel length past end\n");
                    return -1;
                }
                uint8_t sentinel_len = *cur;
                cur++;
                if (cur + sentinel_len > end) {
                    PRINTF("idl_walker: inline zeroable sentinel past end\n");
                    return -1;
                }
                cur += sentinel_len;
            }
            depth--;
            if (depth > 0) {
                walk->span_stack[depth - 1].children_left--;
            }
            continue;
        }

        uint8_t kind;
        size_t header_len;
        uint8_t child_count;
        bool is_zeroable;
        if (inline_header_len(cur, end, &kind, &header_len, &child_count, &is_zeroable) != 0) {
            return -1;
        }
        cur += header_len;

        if (depth == walk->span_cap) {
            size_t new_cap = walk->span_cap + IDL_WALK_STACK_STEP;
            span_frame_t *grown = APP_MEM_REALLOC(walk->span_stack, new_cap * sizeof(span_frame_t));
            if (grown == NULL) {
                PRINTF("idl_walker: span stack growth failed\n");
                return -1;
            }
            walk->span_stack = grown;
            walk->span_cap = new_cap;
        }
        walk->span_stack[depth].children_left = child_count;
        walk->span_stack[depth].is_zeroable = is_zeroable;
        depth++;
    }

    *out_span = (size_t) (cur - ptr);
    return 0;
}

// Parse the inline node at `ptr` into `out` (mirroring the pool entry fields
// the walker reads) and report its header byte count in *header_len. Embedded
// children start at `ptr + *header_len`; they are NOT referenced through
// `out->refs`. Returns 0 on success, -1 on a truncated/unknown descriptor.
static int parse_inline_header(walk_ctx_t *walk,
                               const uint8_t *ptr,
                               const uint8_t *end,
                               idl_pool_entry_t *out,
                               size_t *header_len) {
    uint8_t kind;
    uint8_t child_count;
    bool is_zeroable;
    if (inline_header_len(ptr, end, &kind, header_len, &child_count, &is_zeroable) != 0) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->kind = kind;
    out->ref_count = child_count;

    switch (kind) {
        case IDL_KIND_BYTES_FIXED:
            out->fixed_size = ((uint16_t) ptr[1] << 8) | (uint16_t) ptr[2];
            break;
        case IDL_KIND_STRING_FIXED:
            out->fixed_size = ((uint16_t) ptr[1] << 8) | (uint16_t) ptr[2];
            out->encoding = ptr[3];
            break;
        case IDL_KIND_STRING_PREFIXED:
            out->len_kind = ptr[1];
            out->encoding = ptr[2];
            break;
        case IDL_KIND_OPTION_DYNAMIC:
        case IDL_KIND_OPTION_FIXED:
            out->flag_kind = ptr[1];
            break;
        case IDL_KIND_ARRAY_FIXED:
            out->fixed_size = ((uint16_t) ptr[1] << 8) | (uint16_t) ptr[2];
            break;
        case IDL_KIND_ARRAY_PREFIXED:
            out->len_kind = ptr[1];
            break;
        case IDL_KIND_ENUM:
            out->disc_kind = ptr[1];
            out->total_variants = ((uint16_t) ptr[2] << 8) | (uint16_t) ptr[3];
            out->enum_id_len = ptr[4];
            out->enum_id = ptr + 5;
            break;
        case IDL_KIND_OPTION_ZEROABLE: {
            // The sentinel trails the (single) inner subtree; skip the inner
            // descriptor to locate it.
            size_t inner_span;
            if (inline_span(walk, ptr + 1, end, &inner_span) != 0) {
                return -1;
            }
            const uint8_t *sentinel_len_ptr = ptr + 1 + inner_span;
            if (sentinel_len_ptr >= end) {
                PRINTF("idl_walker: inline zeroable sentinel length past end\n");
                return -1;
            }
            out->sentinel_len = *sentinel_len_ptr;
            out->sentinel = sentinel_len_ptr + 1;
            if (out->sentinel + out->sentinel_len > end) {
                PRINTF("idl_walker: inline zeroable sentinel past end\n");
                return -1;
            }
            break;
        }
        default:
            // Primitives, PUBKEY, BYTES_REMAINDER, STRUCT/TUPLE, remainder
            // arrays/options, and hidden wrappers carry no extra metadata the
            // walker needs beyond kind and child count.
            break;
    }
    return 0;
}

// Locate the `dci`-th embedded child descriptor within an inline aggregate
// whose children begin at `children_base`, by skipping the spans of the
// preceding children. Returns 0 and writes *out on success, -1 on error.
static int inline_child_ptr(walk_ctx_t *walk,
                            const uint8_t *children_base,
                            const uint8_t *end,
                            size_t dci,
                            const uint8_t **out) {
    const uint8_t *cur = children_base;
    for (size_t k = 0; k < dci; k++) {
        size_t span;
        if (inline_span(walk, cur, end, &span) != 0) {
            return -1;
        }
        cur += span;
    }
    if (cur >= end) {
        PRINTF("idl_walker: inline child %d past end of payload\n", dci);
        return -1;
    }
    *out = cur;
    return 0;
}

// Static serialized DATA size of the inline type subtree rooted at `ptr`
// (bounded by `end`): the number of instruction-data bytes it occupies once
// encoded. Writes a concrete size, or FS_VARIABLE when any part is
// variable-width, to *out. Iterative post-order over the reusable size stack
// (no recursion), mirroring try_static_size over inline descriptors instead of
// pool refs. Returns 0 on success, -1 on a truncated/unknown descriptor,
// allocator failure, or size overflow.
static int inline_static_data_size(walk_ctx_t *walk,
                                   const uint8_t *ptr,
                                   const uint8_t *end,
                                   size_t *out) {
    if (walk->size_cap == 0) {
        walk->size_stack = APP_MEM_ALLOC(8 * sizeof(size_frame_t));
        if (walk->size_stack == NULL) {
            PRINTF("idl_walker: size stack allocation failed\n");
            return -1;
        }
        walk->size_cap = 8;
    }

    const uint8_t *cur = ptr;
    // Virtual parent expecting exactly one subtree (the inner root).
    walk->size_stack[0].kind = 0;
    walk->size_stack[0].children_left = 1;
    walk->size_stack[0].is_zeroable = false;
    walk->size_stack[0].multiplier = 1;
    walk->size_stack[0].own = 0;
    walk->size_stack[0].acc = 0;
    size_t depth = 1;

    while (depth > 0) {
        size_frame_t *top = &walk->size_stack[depth - 1];
        if (top->children_left == 0) {
            // OPTION_ZEROABLE trails a sentinel in the descriptor (no data cost).
            if (top->is_zeroable) {
                if (cur >= end) {
                    PRINTF("idl_walker: inline size zeroable sentinel length past end\n");
                    return -1;
                }
                uint8_t sentinel_len = *cur;
                cur++;
                if (cur + sentinel_len > end) {
                    PRINTF("idl_walker: inline size zeroable sentinel past end\n");
                    return -1;
                }
                cur += sentinel_len;
            }
            size_t node_size;
            if (top->kind == IDL_KIND_ARRAY_FIXED) {
                if (top->acc != 0 && top->multiplier > SIZE_MAX / top->acc) {
                    PRINTF("idl_walker: inline ARRAY_FIXED size overflow\n");
                    return -1;
                }
                node_size = top->multiplier * top->acc;
            } else if (top->kind == IDL_KIND_OPTION_FIXED) {
                node_size = top->own + top->acc;
            } else {
                // virtual root, STRUCT, TUPLE, OPTION_ZEROABLE, HIDDEN_*
                node_size = top->acc;
            }
            depth--;
            if (depth == 0) {
                *out = node_size;
                return 0;
            }
            walk->size_stack[depth - 1].acc += node_size;
            walk->size_stack[depth - 1].children_left--;
            continue;
        }

        uint8_t kind;
        size_t header_len;
        uint8_t child_count;
        bool is_zeroable;
        if (inline_header_len(cur, end, &kind, &header_len, &child_count, &is_zeroable) != 0) {
            return -1;
        }
        const uint8_t *header_start = cur;
        cur += header_len;

        // Any variable-width construct makes the whole subtree variable, which
        // an OPTION_FIXED inner must never be (that is OPTION_DYNAMIC's role).
        size_t primitive_width = fixed_primitive_width(kind);
        if (primitive_width == 0) {
            switch (kind) {
                case IDL_KIND_BYTES_FIXED:
                case IDL_KIND_STRING_FIXED:
                case IDL_KIND_STRUCT:
                case IDL_KIND_TUPLE:
                case IDL_KIND_ARRAY_FIXED:
                case IDL_KIND_OPTION_FIXED:
                case IDL_KIND_OPTION_ZEROABLE:
                case IDL_KIND_HIDDEN_PREFIX:
                case IDL_KIND_HIDDEN_SUFFIX:
                    break;
                default:
                    PRINTF("idl_walker: inline OPTION_FIXED inner has variable kind 0x%02x\n",
                           kind);
                    *out = FS_VARIABLE;
                    return 0;
            }
        }

        // True leaves fold their size in immediately. Aggregates are pushed,
        // including an empty STRUCT/TUPLE (child_count 0), whose data footprint
        // is zero and must not be read as a fixed-size header field.
        if (primitive_width != 0) {
            top->acc += primitive_width;
            top->children_left--;
            continue;
        }
        if (kind == IDL_KIND_BYTES_FIXED || kind == IDL_KIND_STRING_FIXED) {
            top->acc += ((size_t) header_start[1] << 8) | (size_t) header_start[2];
            top->children_left--;
            continue;
        }

        if (depth == walk->size_cap) {
            size_t new_cap = walk->size_cap + IDL_WALK_STACK_STEP;
            size_frame_t *grown = APP_MEM_REALLOC(walk->size_stack, new_cap * sizeof(size_frame_t));
            if (grown == NULL) {
                PRINTF("idl_walker: size stack growth failed\n");
                return -1;
            }
            walk->size_stack = grown;
            walk->size_cap = new_cap;
        }
        walk->size_stack[depth].kind = kind;
        walk->size_stack[depth].children_left = child_count;
        walk->size_stack[depth].is_zeroable = is_zeroable;
        walk->size_stack[depth].multiplier = 1;
        walk->size_stack[depth].own = 0;
        walk->size_stack[depth].acc = 0;
        if (kind == IDL_KIND_ARRAY_FIXED) {
            walk->size_stack[depth].multiplier = ((size_t) header_start[1] << 8) |
                                                 (size_t) header_start[2];
        } else if (kind == IDL_KIND_OPTION_FIXED) {
            size_t flag_width = fixed_primitive_width(header_start[1]);
            if (flag_width == 0) {
                PRINTF("idl_walker: inline OPTION_FIXED invalid flag kind 0x%02x\n",
                       header_start[1]);
                return -1;
            }
            walk->size_stack[depth].own = flag_width;
        }
        depth++;
    }

    PRINTF("idl_walker: inline size stack drained unexpectedly\n");
    return -1;
}

// Inline counterpart of select_child: reports the embedded child index `dci`
// (position among the node's inline children) and the argument-path step value
// for the current frame's `child_i`-th child.
static void select_child_inline(uint8_t kind, size_t child_i, size_t *dci, size_t *step_val) {
    switch (kind) {
        case IDL_KIND_STRUCT:
        case IDL_KIND_TUPLE:
            *dci = child_i;
            *step_val = child_i;
            break;
        case IDL_KIND_ARRAY_FIXED:
        case IDL_KIND_ARRAY_PREFIXED:
        case IDL_KIND_ARRAY_REMAINDER:
            *dci = 0;
            *step_val = child_i;
            break;
        case IDL_KIND_OPTION_DYNAMIC:
        case IDL_KIND_OPTION_FIXED:
        case IDL_KIND_OPTION_ZEROABLE:
        case IDL_KIND_OPTION_REMAINDER:
            *dci = 0;
            *step_val = 0;
            break;
        case IDL_KIND_HIDDEN_PREFIX:
            // skip side first (descriptor child 0, step 1), then inner (child 1, step 0).
            if (child_i == 0) {
                *dci = 0;
                *step_val = 1;
            } else {
                *dci = 1;
                *step_val = 0;
            }
            break;
        case IDL_KIND_HIDDEN_SUFFIX:
            // inner first (descriptor child 1, step 0), then skip (child 0, step 1).
            if (child_i == 0) {
                *dci = 1;
                *step_val = 0;
            } else {
                *dci = 0;
                *step_val = 1;
            }
            break;
        default:
            *dci = 0;
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
// reusable scratch buffer. Returns 0 on success, -1 on error.
static int build_path(walk_ctx_t *walk, size_t *out_len) {
    size_t steps = walk->stack_len - 1;
    if (steps > 0xFF) {
        PRINTF("idl_walker: path depth %d exceeds u8 limit\n", steps);
        return -1;
    }

    size_t total = 1;
    for (size_t i = 1; i < walk->stack_len; i++) {
        size_t width = walk->stack[i].step_bytes;
        if (width == 0) {
            PRINTF("idl_walker: frame at depth %d has no step width\n", i);
            return -1;
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
        size_t width = walk->stack[i].step_bytes;
        size_t value = walk->stack[i].step_value;
        if (width < sizeof(size_t) && (value >> (width * 8)) != 0) {
            PRINTF("idl_walker: step value %d overflows width %d\n", value, width);
            return -1;
        }
        for (size_t byte_i = 0; byte_i < width; byte_i++) {
            walk->path[offset + byte_i] = (uint8_t) (value >> (8 * (width - 1 - byte_i)));
        }
        offset += width;
    }

    *out_len = total;
    return 0;
}

// Hand one decoded leaf to the collector. Matches the built path against the
// collector's pre-loaded match_paths; on match, stores kind/value/size into the
// corresponding resolved slot. Unmatched leaves are silently discarded.
// Returns 0 on success, -1 on error.
static int emit_leaf(walk_ctx_t *walk, uint8_t kind, const uint8_t *value, size_t value_size) {
    size_t path_len;
    if (build_path(walk, &path_len) != 0) {
        PRINTF("idl_walker: build_path failed for leaf kind=0x%02x\n", kind);
        return -1;
    }

    PRINTF("idl_walker: emit leaf kind=0x%02x value_size=%d path_size=%d\n",
           kind,
           value_size,
           path_len);

    for (size_t i = 0; i < walk->match_count; i++) {
        if (walk->match_paths[i].path_size != path_len) {
            continue;
        }
        if (memcmp(walk->match_paths[i].path, walk->path, path_len) == 0) {
            PRINTF("idl_walker: leaf matched slot %d\n", (int) i);
            walk->resolved[i].kind = kind;
            walk->resolved[i].value = value;
            walk->resolved[i].value_size = value_size;
            (*walk->resolved_count)++;
            return 0;
        }
    }
    PRINTF("idl_walker: leaf did not match any slot, discarding\n");
    return 0;
}

static int ensure_frame_capacity(walk_ctx_t *walk) {
    if (walk->stack_len == walk->stack_cap) {
        size_t new_cap = walk->stack_cap + IDL_WALK_STACK_STEP;
        frame_t *new_stack = APP_MEM_REALLOC(walk->stack, new_cap * sizeof(frame_t));
        if (new_stack == NULL) {
            PRINTF("idl_walker: frame stack growth failed\n");
            return -1;
        }
        walk->stack = new_stack;
        walk->stack_cap = new_cap;
    }
    return 0;
}

static int push_frame(walk_ctx_t *walk,
                      uint8_t entry_idx,
                      uint8_t parent_kind,
                      size_t step_value,
                      size_t step_bytes) {
    const idl_pool_entry_t *entry = idl_pool_entry(entry_idx);
    if (entry == NULL) {
        PRINTF("idl_walker: push_frame ref %d out of range\n", entry_idx);
        return -1;
    }
    if (ensure_frame_capacity(walk) != 0) {
        return -1;
    }
    frame_t *frame = &walk->stack[walk->stack_len++];
    frame->kind = entry->kind;
    frame->entered = false;
    frame->child_i = 0;
    frame->child_count = 0;
    frame->mark = 0;
    frame->parent_kind = parent_kind;
    frame->step_value = step_value;
    frame->step_bytes = step_bytes;
    frame->is_inline = false;
    frame->source.entry_idx = entry_idx;
    frame->enum_payload = NULL;
    frame->enum_payload_size = 0;
    frame->enum_variant_index = 0;
    PRINTF(
        "idl_walker: push_frame entry_idx=%d kind=0x%02x parent_kind=0x%02x step_value=%d "
        "depth=%d\n",
        entry_idx,
        frame->kind,
        parent_kind,
        step_value,
        walk->stack_len);
    return 0;
}

// Push a frame that walks the inline descriptor at `ptr` (bounded by `end`).
// The node's kind is decoded from its header. Returns 0 on success, -1 on a
// malformed header or allocator failure.
static int push_inline_frame(walk_ctx_t *walk,
                             const uint8_t *ptr,
                             const uint8_t *end,
                             uint8_t parent_kind,
                             size_t step_value,
                             size_t step_bytes) {
    idl_pool_entry_t header;
    size_t header_len;
    if (parse_inline_header(walk, ptr, end, &header, &header_len) != 0) {
        PRINTF("idl_walker: push_inline_frame header parse failed\n");
        return -1;
    }
    if (ensure_frame_capacity(walk) != 0) {
        return -1;
    }
    frame_t *frame = &walk->stack[walk->stack_len++];
    frame->kind = header.kind;
    frame->entered = false;
    frame->child_i = 0;
    frame->child_count = 0;
    frame->mark = 0;
    frame->parent_kind = parent_kind;
    frame->step_value = step_value;
    frame->step_bytes = step_bytes;
    frame->is_inline = true;
    frame->source.inline_descriptor.ptr = ptr;
    frame->source.inline_descriptor.end = end;
    frame->enum_payload = NULL;
    frame->enum_payload_size = 0;
    frame->enum_variant_index = 0;
    PRINTF("idl_walker: push_inline_frame kind=0x%02x parent_kind=0x%02x step_value=%d depth=%d\n",
           frame->kind,
           parent_kind,
           step_value,
           walk->stack_len);
    return 0;
}

// Descend into the current frame's next child, or pop the frame when its
// children are exhausted. Used by every aggregate/option/hidden kind whose
// child count is fixed once `entered`. `children_base` locates the first
// embedded child of an inline frame (NULL/unused for pool frames).
static int step_children(walk_ctx_t *walk,
                         frame_t *frame,
                         const idl_pool_entry_t *entry,
                         const uint8_t *children_base) {
    if (frame->child_i < frame->child_count) {
        uint8_t parent_kind = frame->kind;
        size_t step_bytes = step_width(parent_kind);
        if (frame->is_inline) {
            size_t dci;
            size_t step_val;
            select_child_inline(frame->kind, frame->child_i, &dci, &step_val);
            const uint8_t *inline_end = frame->source.inline_descriptor.end;
            const uint8_t *child_ptr;
            if (inline_child_ptr(walk, children_base, inline_end, dci, &child_ptr) != 0) {
                return -1;
            }
            frame->child_i++;
            // push_inline_frame may reallocate the stack: do not touch `frame`.
            return push_inline_frame(walk,
                                     child_ptr,
                                     inline_end,
                                     parent_kind,
                                     step_val,
                                     step_bytes);
        } else {
            uint8_t ref_idx;
            size_t step_val;
            select_child(entry, frame->kind, frame->child_i, &ref_idx, &step_val);
            frame->child_i++;
            // push_frame may reallocate the stack: do not touch `frame` afterwards.
            return push_frame(walk, ref_idx, parent_kind, step_val, step_bytes);
        }
    }
    walk->stack_len--;  // pop
    return 0;
}

// Process one unit of work on the top frame: emit a leaf and pop, descend into
// a child, or pop. Returns 0 on progress, -1 on a fatal error.
static int walk_top(walk_ctx_t *walk) {
    frame_t *frame = &walk->stack[walk->stack_len - 1];
    const idl_pool_entry_t *entry;
    idl_pool_entry_t inline_entry;
    const uint8_t *children_base = NULL;
    if (frame->is_inline) {
        size_t header_len;
        if (parse_inline_header(walk,
                                frame->source.inline_descriptor.ptr,
                                frame->source.inline_descriptor.end,
                                &inline_entry,
                                &header_len) != 0) {
            return -1;
        }
        entry = &inline_entry;
        children_base = frame->source.inline_descriptor.ptr + header_len;
    } else {
        entry = idl_pool_entry(frame->source.entry_idx);
    }
    PRINTF("idl_walker: walk_top kind=0x%02x cursor=%d depth=%d inline=%d\n",
           frame->kind,
           walk->cursor,
           walk->stack_len,
           frame->is_inline);

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
            PRINTF("idl_walker: fixed bytes/string leaf kind=0x%02x width=%d\n",
                   frame->kind,
                   width);
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
            return step_children(walk, frame, entry, children_base);

        case IDL_KIND_ARRAY_FIXED:
            if (!frame->entered) {
                frame->child_count = entry->fixed_size;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry, children_base);

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
            return step_children(walk, frame, entry, children_base);

        // ---- remainder array: iterate until the buffer is consumed ----------
        case IDL_KIND_ARRAY_REMAINDER: {
            if (frame->entered && walk->cursor == frame->mark) {
                // The previous element consumed no bytes — would loop forever.
                PRINTF("idl_walker: ARRAY_REMAINDER element consumed no bytes\n");
                return -1;
            }
            if (walk->cursor < walk->data_size) {
                uint8_t parent_kind = frame->kind;
                size_t step_bytes = step_width(parent_kind);
                size_t step_val;
                frame->entered = true;
                frame->mark = walk->cursor;
                if (frame->is_inline) {
                    size_t dci;
                    select_child_inline(frame->kind, frame->child_i, &dci, &step_val);
                    const uint8_t *inline_end = frame->source.inline_descriptor.end;
                    const uint8_t *child_ptr;
                    if (inline_child_ptr(walk, children_base, inline_end, dci, &child_ptr) != 0) {
                        return -1;
                    }
                    frame->child_i++;
                    return push_inline_frame(walk,
                                             child_ptr,
                                             inline_end,
                                             parent_kind,
                                             step_val,
                                             step_bytes);
                } else {
                    uint8_t ref_idx;
                    select_child(entry, frame->kind, frame->child_i, &ref_idx, &step_val);
                    frame->child_i++;
                    return push_frame(walk, ref_idx, parent_kind, step_val, step_bytes);
                }
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
            return step_children(walk, frame, entry, children_base);

        case IDL_KIND_OPTION_FIXED:
            if (!frame->entered) {
                uint64_t flag;
                if (!read_uint_le(walk, entry->flag_kind, &flag)) {
                    return -1;
                }
                if (flag != 0) {
                    PRINTF("idl_walker: OPTION_FIXED flag=%d present, descending\n", flag);
                    frame->child_count = 1;
                } else if (frame->is_inline) {
                    // Absent inline OPTION_FIXED: the inner bytes are still
                    // present as padding, so advance by the inner's static data
                    // size computed straight from the inline descriptor (the
                    // pool-wide size table does not index inline subtrees).
                    size_t inner_size;
                    if (inline_static_data_size(walk,
                                                children_base,
                                                frame->source.inline_descriptor.end,
                                                &inner_size) != 0) {
                        return -1;
                    }
                    if (inner_size == FS_VARIABLE) {
                        PRINTF("idl_walker: inline OPTION_FIXED with variable-size inner\n");
                        return -1;
                    }
                    if (walk->cursor + inner_size > walk->data_size) {
                        PRINTF("idl_walker: inline OPTION_FIXED skip past end of data\n");
                        return -1;
                    }
                    PRINTF(
                        "idl_walker: inline OPTION_FIXED flag=0 absent, skipping inner_size=%d\n",
                        inner_size);
                    walk->cursor += inner_size;
                    frame->child_count = 0;
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
            return step_children(walk, frame, entry, children_base);

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
            return step_children(walk, frame, entry, children_base);

        case IDL_KIND_OPTION_REMAINDER:
            if (!frame->entered) {
                frame->child_count = (walk->cursor < walk->data_size) ? 1 : 0;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry, children_base);

        // ---- hidden wrappers ------------------------------------------------
        case IDL_KIND_HIDDEN_PREFIX:
        case IDL_KIND_HIDDEN_SUFFIX:
            if (!frame->entered) {
                frame->child_count = 2;
                frame->child_i = 0;
                frame->entered = true;
            }
            return step_children(walk, frame, entry, children_base);

        // ---- enum: discriminator + variant payload --------------------------
        case IDL_KIND_ENUM: {
            if (!frame->entered) {
                uint64_t disc;
                if (!read_uint_le(walk, entry->disc_kind, &disc)) {
                    return -1;
                }
                if (disc >= entry->total_variants) {
                    PRINTF("idl_walker: ENUM discriminator %d >= total_variants %d\n",
                           disc,
                           entry->total_variants);
                    return -1;
                }
                const cs_enum_variant_t *variant = cs_enum_cache_find(walk->program_id,
                                                                      entry->enum_id,
                                                                      entry->enum_id_len,
                                                                      (uint16_t) disc);
                if (variant == NULL) {
                    PRINTF("idl_walker: no cached variant %d for enum_id=%.*s\n",
                           disc,
                           entry->enum_id_len,
                           entry->enum_id);
                    return -1;
                }
                // The variant name is the enum node's own displayable leaf value.
                if (emit_leaf(walk,
                              IDL_KIND_ENUM,
                              (const uint8_t *) variant->variant_name,
                              strlen(variant->variant_name)) != 0) {
                    return -1;
                }
                frame->child_i = 0;
                if (variant->payload_kind == CS_VARIANT_PAYLOAD_EMPTY) {
                    frame->child_count = 0;
                } else if (variant->payload_kind == CS_VARIANT_PAYLOAD_RAW_SIZE) {
                    uint16_t raw_size = variant->payload.raw_size;
                    if (walk->cursor + raw_size > walk->data_size) {
                        PRINTF("idl_walker: ENUM RAW_SIZE payload %d read past end of data\n",
                               raw_size);
                        return -1;
                    }
                    walk->cursor += raw_size;
                    frame->child_count = 0;
                } else if (variant->payload_kind == CS_VARIANT_PAYLOAD_INLINE) {
                    frame->enum_payload = variant->payload.inline_descriptor.bytes;
                    frame->enum_payload_size = variant->payload.inline_descriptor.size;
                    frame->enum_variant_index = (uint16_t) disc;
                    frame->child_count = 1;
                } else {
                    PRINTF("idl_walker: ENUM unknown payload_kind 0x%02x\n", variant->payload_kind);
                    return -1;
                }
                frame->entered = true;
            }
            if (frame->child_i < frame->child_count) {
                // INLINE payload: descend into its self-contained descriptor
                // root exactly once. The path step under an enum is the variant
                // index at the discriminator's byte width (big-endian per spec).
                size_t disc_width = fixed_primitive_width(entry->disc_kind);
                if (disc_width == 0) {
                    PRINTF("idl_walker: ENUM disc_kind 0x%02x has no fixed step width\n",
                           entry->disc_kind);
                    return -1;
                }
                const uint8_t *payload = frame->enum_payload;
                const uint8_t *payload_end = frame->enum_payload + frame->enum_payload_size;
                size_t variant_index = frame->enum_variant_index;
                frame->child_i++;
                return push_inline_frame(walk,
                                         payload,
                                         payload_end,
                                         IDL_KIND_ENUM,
                                         variant_index,
                                         disc_width);
            }
            walk->stack_len--;  // pop
            return 0;
        }

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
                   const uint8_t program_id[32],
                   const idl_match_path_t *match_paths,
                   size_t match_count,
                   idl_resolved_leaf_t *resolved,
                   size_t *resolved_count) {
    if (!idl_pool_ready()) {
        PRINTF("idl_walker_run: no pool provided\n");
        return -1;
    }
    if (data == NULL && data_size > 0) {
        PRINTF("idl_walker_run: NULL data with non-zero size (data_size=%d)\n", data_size);
        return -1;
    }
    if (program_id == NULL) {
        PRINTF("idl_walker_run: NULL program_id\n");
        return -1;
    }

    uint8_t entry_count = idl_pool_count();
    uint8_t root_index = idl_pool_root_index();
    PRINTF(
        "idl_walker_run: starting (entry_count=%d, root_index=%d, data_size=%d, match_count=%d)\n",
        entry_count,
        root_index,
        (int) data_size,
        (int) match_count);

    size_t *fixed_sizes = NULL;
    if (pool_has_option_fixed()) {
        PRINTF("idl_walker_run: pool has OPTION_FIXED, building fixed-size table\n");
        if (compute_fixed_sizes(entry_count, &fixed_sizes) != 0) {
            PRINTF("idl_walker_run: fixed-size table build failed\n");
            return -1;
        }
    }

    *resolved_count = 0;
    if (match_count > 0) {
        memset(resolved, 0, match_count * sizeof(idl_resolved_leaf_t));
    }

    walk_ctx_t walk = {0};
    walk.data = data;
    walk.data_size = data_size;
    walk.cursor = 0;
    walk.program_id = program_id;
    walk.fixed_sizes = fixed_sizes;
    walk.match_paths = match_paths;
    walk.match_count = match_count;
    walk.resolved = resolved;
    walk.resolved_count = resolved_count;
    walk.stack_cap = 8;
    walk.stack = APP_MEM_ALLOC(walk.stack_cap * sizeof(frame_t));

    int walk_result = 0;
    if (walk.stack == NULL) {
        PRINTF("idl_walker: frame stack allocation failed\n");
        walk_result = -1;
    } else {
        walk_result = push_frame(&walk, root_index, 0, 0, 0);
        while (walk_result == 0 && walk.stack_len > 0) {
            walk_result = walk_top(&walk);
        }
        if (walk_result == 0 && walk.cursor != walk.data_size) {
            PRINTF("idl_walker: cursor %d != data_size %d, refusing\n",
                   walk.cursor,
                   walk.data_size);
            walk_result = -1;
        }
    }

    APP_MEM_FREE(walk.path);
    APP_MEM_FREE(walk.stack);
    APP_MEM_FREE(walk.span_stack);
    APP_MEM_FREE(walk.size_stack);
    APP_MEM_FREE(fixed_sizes);
    PRINTF("idl_walker_run: finished with result=%d (cursor=%d, data_size=%d)\n",
           walk_result,
           walk.cursor,
           walk.data_size);
    return walk_result;
}
