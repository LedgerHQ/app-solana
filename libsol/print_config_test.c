#include "common_byte_strings.h"
#include "print_config.c"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>

void test_print_config_show_authority() {
    Pubkey signer = {{BYTES32_BS58_1}};
    Pubkey not_signer = {{BYTES32_BS58_2}};
    PrintConfig print_config = {.expert_mode = false, .signer_pubkey = &signer};

    assert(!print_config_show_authority(&print_config, &signer));
    assert(print_config_show_authority(&print_config, &not_signer));
    print_config.expert_mode = true;
    assert(print_config_show_authority(&print_config, &signer));
    assert(print_config_show_authority(&print_config, &not_signer));
}

int main() {
    RUN_TEST(test_print_config_show_authority);

    printf("passed\n");
    return 0;
}
