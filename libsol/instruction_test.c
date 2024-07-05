#include "common_byte_strings.h"
#include "instruction.h"
#include "sol/parser.h"
#include "spl_memo_instruction.h"
#include "compute_budget_instruction.h"
#include "stake_instruction.h"
#include "system_instruction.h"
#include "util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_instruction_program_id_compute_budget() {
    Pubkey program_id;
    memcpy(&program_id, &compute_budget_program_id, PUBKEY_SIZE);
    Instruction instruction = {0, NULL, 0, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdComputeBudget);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdComputeBudget);
    }
}

void test_instruction_program_id_spl_memo() {
    Pubkey program_id;
    memcpy(&program_id, &spl_memo_program_id, PUBKEY_SIZE);
    Instruction instruction = {0, NULL, 0, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdSplMemo);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdSplMemo);
    }
}

void test_instruction_program_id_system() {
    Pubkey program_id;
    memcpy(&program_id, &system_program_id, PUBKEY_SIZE);
    Instruction instruction = {0, NULL, 0, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdSystem);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdSystem);
    }
}

void test_instruction_program_id_stake() {
    Pubkey program_id;
    memcpy(&program_id, &stake_program_id, PUBKEY_SIZE);
    Instruction instruction = {0, NULL, 0, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdStake);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdStake);
    }
}

void test_instruction_program_id_unknown() {
    Pubkey program_id = {{BYTES32_BS58_2}};
    Instruction instruction = {0, NULL, 0, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdUnknown);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 1}, &program_id, NULL, 1};
        assert(instruction_program_id(&instruction, &header) == ProgramIdUnknown);
    }
}

void test_instruction_validate_ok() {
    uint8_t accounts[] = {1, 2, 3};
    Instruction instruction = {0, accounts, 3, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 4}, NULL, NULL, 1};
        assert(instruction_validate(&instruction, &header) == 0);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 4}, NULL, NULL, 1};
        assert(instruction_validate(&instruction, &header) == 0);
    }
}

void test_instruction_validate_bad_program_id_index_fail() {
    uint8_t accounts[] = {1, 2, 3};
    Instruction instruction = {4, accounts, 3, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 4}, NULL, NULL, 1};
        assert(instruction_validate(&instruction, &header) == 1);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 4}, NULL, NULL, 1};
        assert(instruction_validate(&instruction, &header) == 1);
    }
}

void test_instruction_validate_bad_first_account_index_fail() {
    uint8_t accounts[] = {4, 2, 3};
    Instruction instruction = {0, accounts, 3, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 4}, NULL, NULL, 1};
        assert(instruction_validate(&instruction, &header) == 1);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 4}, NULL, NULL, 1};
        assert(instruction_validate(&instruction, &header) == 1);
    }
}

void test_instruction_validate_bad_last_account_index_fail() {
    uint8_t accounts[] = {1, 2, 4};
    Instruction instruction = {0, accounts, 3, NULL, 0};
    {
        MessageHeader header = {false, 0, {0, 0, 0, 4}, NULL, NULL, 1};
        assert(instruction_validate(&instruction, &header) == 1);
    }
    {
        MessageHeader header = {true, 0, {0, 0, 0, 4}, NULL, NULL, 1};
        assert(instruction_validate(&instruction, &header) == 1);
    }
}

void test_static_brief_initializer_macros() {
    InstructionBrief system_test = SYSTEM_IX_BRIEF(SystemTransfer);
    InstructionBrief system_expect = {ProgramIdSystem, .system = SystemTransfer};
    assert(memcmp(&system_test, &system_expect, sizeof(InstructionBrief)) == 0);
    InstructionBrief stake_test = STAKE_IX_BRIEF(StakeDelegate);
    InstructionBrief stake_expect = {ProgramIdStake, .stake = StakeDelegate};
    assert(memcmp(&stake_test, &stake_expect, sizeof(InstructionBrief)) == 0);
}

void test_instruction_info_matches_brief_constants() {
    {
        InstructionInfo info = {.kind = ProgramIdSerumAssertOwner};
        InstructionBrief brief_pass = {.program_id = ProgramIdSerumAssertOwner};
        assert(instruction_info_matches_brief(&info, &brief_pass));
    }

    {
        InstructionInfo info = {.kind = ProgramIdSplAssociatedTokenAccount};
        InstructionBrief brief_pass = {.program_id = ProgramIdSplAssociatedTokenAccount};
        assert(instruction_info_matches_brief(&info, &brief_pass));
    }

    {
        InstructionInfo info = {.kind = ProgramIdSplMemo};
        InstructionBrief brief_pass = {.program_id = ProgramIdSplMemo};
        assert(instruction_info_matches_brief(&info, &brief_pass));
    }
}

void test_instruction_compute_budget_matches_brief() {
    InstructionInfo info = {.kind = ProgramIdComputeBudget,
                            .compute_budget = {.kind = ComputeBudgetChangeUnitLimit,
                                               .change_unit_price = {.units = 0xAABBCCDD}}};

    {
        InstructionBrief brief_pass = {.program_id = ProgramIdComputeBudget,
                                       .compute_budget = ComputeBudgetChangeUnitLimit};
        assert(instruction_info_matches_brief(&info, &brief_pass));
    }

    {
        InstructionBrief brief_fail = {.program_id = ProgramIdComputeBudget,
                                       .compute_budget = ComputeBudgetRequestHeapFrame};
        assert(!instruction_info_matches_brief(&info, &brief_fail));
    }
}

void test_instruction_info_matches_brief() {
    InstructionInfo info = {
        .kind = ProgramIdSystem,
        .system =
            {
                .kind = SystemTransfer,
                .transfer = {NULL, NULL, 0},
            },
    };
    InstructionBrief brief_pass = SYSTEM_IX_BRIEF(SystemTransfer);
    assert(instruction_info_matches_brief(&info, &brief_pass));
    InstructionBrief brief_fail = SYSTEM_IX_BRIEF(SystemAdvanceNonceAccount);
    assert(!instruction_info_matches_brief(&info, &brief_fail));
}

void test_instruction_infos_match_briefs() {
    InstructionInfo infos[] = {{
                                   .kind = ProgramIdSystem,
                                   .system =
                                       {
                                           .kind = SystemTransfer,
                                           .transfer = {NULL, NULL, 0},
                                       },
                               },
                               {
                                   .kind = ProgramIdStake,
                                   .stake =
                                       {
                                           .kind = StakeDelegate,
                                           .delegate_stake = {NULL, NULL, NULL},
                                       },
                               }};
    InstructionBrief briefs[] = {
        SYSTEM_IX_BRIEF(SystemTransfer),
        STAKE_IX_BRIEF(StakeDelegate),
    };
    InstructionBrief bad_briefs[] = {
        SYSTEM_IX_BRIEF(SystemTransfer),
        STAKE_IX_BRIEF(StakeSplit),
    };
    InstructionInfo* display_infos[] = {&infos[0], &infos[1]};
    size_t infos_len = ARRAY_LEN(infos);
    assert(infos_len == ARRAY_LEN(display_infos));
    assert(infos_len == ARRAY_LEN(briefs));
    assert(infos_len == ARRAY_LEN(bad_briefs));
    assert(instruction_infos_match_briefs(display_infos, briefs, infos_len));
    assert(!instruction_infos_match_briefs(display_infos, bad_briefs, infos_len));
}

void test_instruction_accounts_iterator_next() {
    uint8_t instruction_accounts[] = {0, 1, 2};
    Instruction instruction = {
        2,
        instruction_accounts,
        ARRAY_LEN(instruction_accounts),
        NULL,
        0,
    };
    Pubkey header_pubkeys[] = {
        {{BYTES32_BS58_2}},
        {{BYTES32_BS58_3}},
        {{BYTES32_BS58_4}},
        {{BYTES32_BS58_5}},
    };
    MessageHeader header = {
        false,
        0,
        {0, 0, 0, ARRAY_LEN(header_pubkeys)},
        header_pubkeys,
        NULL,
        1,
    };
    InstructionAccountsIterator it;
    instruction_accounts_iterator_init(&it, &header, &instruction);
    size_t expected_remaining = ARRAY_LEN(instruction_accounts);
    assert(instruction_accounts_iterator_remaining(&it) == expected_remaining--);
    const Pubkey* pubkey;

    Pubkey expected1 = {{BYTES32_BS58_2}};
    assert(instruction_accounts_iterator_next(&it, &pubkey) == 0);
    assert(memcmp(pubkey, &expected1, PUBKEY_SIZE) == 0);
    assert(instruction_accounts_iterator_remaining(&it) == expected_remaining--);

    // Test skipping a pubkey
    assert(instruction_accounts_iterator_next(&it, NULL) == 0);
    assert(instruction_accounts_iterator_remaining(&it) == expected_remaining--);

    Pubkey expected3 = {{BYTES32_BS58_4}};
    assert(instruction_accounts_iterator_next(&it, &pubkey) == 0);
    assert(instruction_accounts_iterator_remaining(&it) == expected_remaining);
    assert(memcmp(pubkey, &expected3, PUBKEY_SIZE) == 0);

    assert(instruction_accounts_iterator_next(&it, &pubkey) == 1);
    assert(instruction_accounts_iterator_remaining(&it) == expected_remaining);
}

int main() {
    test_instruction_validate_ok();
    test_instruction_validate_bad_program_id_index_fail();
    test_instruction_validate_bad_first_account_index_fail();
    test_instruction_validate_bad_last_account_index_fail();
    test_instruction_program_id_unknown();
    test_instruction_program_id_stake();
    test_instruction_program_id_system();
    test_static_brief_initializer_macros();
    test_instruction_info_matches_brief();
    test_instruction_infos_match_briefs();
    test_instruction_accounts_iterator_next();
    test_instruction_program_id_spl_memo();
    test_instruction_program_id_compute_budget();
    test_instruction_info_matches_brief_constants();
    test_instruction_compute_budget_matches_brief();

    printf("passed\n");
    return 0;
}
