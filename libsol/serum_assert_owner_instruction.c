#include "common_byte_strings.h"
#include "instruction.h"
#include "serum_assert_owner_instruction.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "util.h"

bool is_serum_assert_owner_program_id(const Pubkey *program_id) {
    static const Pubkey program_ids[] = {
        {{PROGRAM_ID_SERUM_ASSERT_OWNER_PHANTOM}},
        {{PROGRAM_ID_SERUM_ASSERT_OWNER}},
    };
    for (size_t i = 0; i < ARRAY_LEN(program_ids); i++) {
        if (pubkeys_equal(program_id, &program_ids[i])) {
            return true;
        }
    }
    return false;
}
