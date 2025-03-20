#include "common_byte_strings.h"
#include "instruction.h"
#include "onchain_spending_delegate.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "util.h"

typedef struct DelegateRegistryEntry {
    const Pubkey program_id;
    const char *name;
} DelegateRegistryEntry;

const DelegateRegistryEntry DELEGATE_REGISTRY[] = {
    // TODO: replace with actual baanx program ID
    // "BaanxDe1egate111111111111111111111111111111"
    {{{0x02, 0xb5, 0xc7, 0xb3, 0xbe, 0x32, 0x1d, 0x21, 0x2b, 0x61, 0x61,
       0x58, 0xa4, 0xec, 0xe6, 0x6f, 0x25, 0x19, 0x0c, 0xa0, 0xff, 0x48,
       0x22, 0xa2, 0xea, 0x07, 0x20, 0x61, 0xc0, 0x00, 0x00, 0x00}},
     "Baanx"},
};

const char *get_onchain_spending_delegate_name(const Pubkey *program_id) {
    for (size_t i = 0; i < ARRAY_LEN(DELEGATE_REGISTRY); i++) {
        if (memcmp(program_id, &DELEGATE_REGISTRY[i].program_id, PUBKEY_SIZE) == 0) {
            return DELEGATE_REGISTRY[i].name;
        }
    }

    return "Goose";
}
