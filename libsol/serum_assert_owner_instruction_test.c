#include "serum_assert_owner_instruction.c"
#include "common_byte_strings.h"
#include "system_instruction.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>

void test_is_serum_assert_owner_program_id() {
    const Pubkey serum_deployment = {{PROGRAM_ID_SERUM_ASSERT_OWNER}};
    const Pubkey phantom_deployment = {{PROGRAM_ID_SERUM_ASSERT_OWNER_PHANTOM}};

    assert(is_serum_assert_owner_program_id(&serum_deployment));
    assert(is_serum_assert_owner_program_id(&phantom_deployment));
    assert(!is_serum_assert_owner_program_id(&system_program_id));
}

int main() {
    RUN_TEST(test_is_serum_assert_owner_program_id);

    printf("passed\n");
    return 0;
}
