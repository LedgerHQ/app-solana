#include "baanx_assert_delegate_program_id.c"
#include "common_byte_strings.h"
#include "system_instruction.h"
#include <assert.h>
#include <stdio.h>

void test_is_baanx_assert_delegate_program_id() {
    const Pubkey baanx_delegate_program_id = {{PROGRAM_ID_BAANX_DELEGATE}};

    assert(is_serum_assert_owner_program_id(&baanx_delegate_program_id));
    assert(!is_serum_assert_owner_program_id(&system_program_id));
}

int main() {
    test_is_serum_assert_owner_program_id();

    printf("passed\n");
    return 0;
}
