#include "common_byte_strings.h"
#include "instruction.h"
#include "baanx_assert_delegate_program_id.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"
#include "util.h"

bool is_baanx_assert_delegate_program_id(const Pubkey *program_id) {
    static const Pubkey baanx_delegate_program_id = {{PROGRAM_ID_BAANX_DELEGATE}};
    return pubkeys_equal(program_id, &baanx_delegate_program_id);
}
