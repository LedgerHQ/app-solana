#include "idl_kinds.h"
#include "os_print.h"

// The IDL kinds an amount may be read from, and the byte width of each.
//
// Amounts are unsigned and at most 64 bits: anything signed or wider is a number the
// decoders cannot produce. Both directions are answered from this one table, so a decoder,
// a descriptor validator and a width inference cannot come to disagree about which kinds
// qualify.
static const struct {
    uint8_t kind;
    uint8_t width;
} G_idl_unsigned_kinds[] = {
    {IDL_KIND_U8, 1},
    {IDL_KIND_U16, 2},
    {IDL_KIND_U32, 4},
    {IDL_KIND_U64, 8},
};

int idl_unsigned_kind_width(uint8_t kind, size_t *out_width) {
    // Answers two questions at once: a kind absent from the table is one no amount may use,
    // which is why callers validating a leaf can ignore the width they get back.
    for (size_t i = 0; i < sizeof(G_idl_unsigned_kinds) / sizeof(*G_idl_unsigned_kinds); i++) {
        if (G_idl_unsigned_kinds[i].kind == kind) {
            *out_width = G_idl_unsigned_kinds[i].width;
            PRINTF("idl_unsigned_kind_width: kind=%d width=%d\n",
                   kind,
                   G_idl_unsigned_kinds[i].width);
            return 0;
        }
    }
    PRINTF("idl_unsigned_kind_width: kind %d is not an unsigned integer\n", kind);
    return -1;
}

int idl_unsigned_kind_for_width(size_t width, uint8_t *out_kind) {
    // The reverse lookup, for a number embedded in a descriptor with no kind of its own,
    // where the byte count is the only thing that says how wide it is.
    for (size_t i = 0; i < sizeof(G_idl_unsigned_kinds) / sizeof(*G_idl_unsigned_kinds); i++) {
        if (G_idl_unsigned_kinds[i].width == width) {
            *out_kind = G_idl_unsigned_kinds[i].kind;
            PRINTF("idl_unsigned_kind_for_width: width=%d kind=%d\n",
                   (int) width,
                   G_idl_unsigned_kinds[i].kind);
            return 0;
        }
    }
    PRINTF("idl_unsigned_kind_for_width: %d bytes is not an integer width\n", (int) width);
    return -1;
}
