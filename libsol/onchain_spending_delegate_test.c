#include "onchain_spending_delegate.c"
#include "common_byte_strings.h"
#include "system_instruction.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_onchain_spending_delegate_name_matches() {
    int res = strcmp(
        get_onchain_spending_delegate_name(&DELEGATE_REGISTRY[0].program_id),
        DELEGATE_REGISTRY[0].name,
    );
    assert(res == 0);

    assert(!get_onchain_spending_delegate_name(&system_program_id));
}

int main() {
    test_onchain_spending_delegate_name_matches();

    printf("passed\n");
    return 0;
}
