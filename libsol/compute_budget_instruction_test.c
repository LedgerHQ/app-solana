#include "compute_budget_instruction.c"
#include "sol/parser.h"
#include <assert.h>
#include <stdio.h>

void test_parse_compute_budget_instruction_kind() {
    uint8_t message[] = {1, 2, 3, 4};

    enum ComputeBudgetInstructionKind instruction_kind_target;

    Parser parser = {message, sizeof(message)};

    // ComputeBudgetRequestHeapFrame
    assert(parse_compute_budget_instruction_kind(&parser, &instruction_kind_target) == 0);
    assert(instruction_kind_target == ComputeBudgetRequestHeapFrame);

    // ComputeBudgetChangeUnitLimit
    assert(parse_compute_budget_instruction_kind(&parser, &instruction_kind_target) == 0);
    assert(instruction_kind_target == ComputeBudgetChangeUnitLimit);

    // ComputeBudgetChangeUnitPrice
    assert(parse_compute_budget_instruction_kind(&parser, &instruction_kind_target) == 0);
    assert(instruction_kind_target == ComputeBudgetChangeUnitPrice);

    // ComputeBudgetSetLoadedAccountsDataSizeLimit
    assert(parse_compute_budget_instruction_kind(&parser, &instruction_kind_target) == 0);
    assert(instruction_kind_target == ComputeBudgetSetLoadedAccountsDataSizeLimit);

    // Buffer empty, should fail
    // parse_u8 should return 1
    assert(parse_compute_budget_instruction_kind(&parser, &instruction_kind_target) == 1);
}

/**
 * Buffer with invalid data should return error and not modify passed *kind pointer
 */
void test_parse_compute_budget_instruction_kind_invalid() {
    uint8_t message[] = {0x21, 0x37};

    enum ComputeBudgetInstructionKind instruction_kind_target = 0;

    Parser parser = {message, sizeof(message)};

    // instruction kind not found with given value
    assert(parse_compute_budget_instruction_kind(&parser, &instruction_kind_target) == 1);
    assert(instruction_kind_target == 0);  // instruction_kind_target is not modified
}

/**
 * Test parsing instruction kind.
 * Code execution should not get to the switch statement
 */
void test_parse_compute_budget_instructions_invalid_kind() {
    uint8_t message[] = {5};

    Instruction instruction = {.data = message,
                               .data_length = sizeof(message),
                               .accounts_length = 0};

    MessageHeader *header = {0};

    ComputeBudgetInfo info;

    int result = parse_compute_budget_instructions(&instruction, header, &info);

    assert(result == 1);  // Invalid instruction kind for ComputeBudget program
}

// Verify fee calculation with typical values
void test_calculate_max_fee_normal() {
    ComputeBudgetChangeUnitPriceInfo price = {.units = 1000};
    ComputeBudgetChangeUnitLimitInfo limit = {.units = 200000};
    ComputeBudgetFeeInfo info = {
        .change_unit_price = &price,
        .change_unit_limit = &limit,
        .instructions_count = 1,
        .signatures_count = 1,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) == 0);
    assert(fee == 5200);
}

// Verify fee calculation is correct when result exceeds UINT32_MAX
void test_calculate_max_fee_no_truncation() {
    ComputeBudgetChangeUnitPriceInfo price = {.units = UINT64_C(4294967296)};
    ComputeBudgetChangeUnitLimitInfo limit = {.units = 1000000};
    ComputeBudgetFeeInfo info = {
        .change_unit_price = &price,
        .change_unit_limit = &limit,
        .instructions_count = 1,
        .signatures_count = 1,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) == 0);
    assert(fee == UINT64_C(4294972296));
}

// Verify no overflow in intermediate computations with large unit price
void test_calculate_max_fee_large_price() {
    ComputeBudgetChangeUnitPriceInfo price = {.units = UINT64_C(10000000000000)};
    ComputeBudgetChangeUnitLimitInfo limit = {.units = 1400000};
    ComputeBudgetFeeInfo info = {
        .change_unit_price = &price,
        .change_unit_limit = &limit,
        .instructions_count = 1,
        .signatures_count = 1,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) == 0);
    assert(fee == UINT64_C(14000000005000));
}

// Without unit price, fee is base fee only
void test_calculate_max_fee_base_only() {
    ComputeBudgetFeeInfo info = {
        .change_unit_price = NULL,
        .change_unit_limit = NULL,
        .instructions_count = 3,
        .signatures_count = 2,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) == 0);
    assert(fee == 10000);
}

// Without explicit unit limit, default max compute is used
void test_calculate_max_fee_default_compute_limit() {
    ComputeBudgetChangeUnitPriceInfo price = {.units = 2000000};
    ComputeBudgetFeeInfo info = {
        .change_unit_price = &price,
        .change_unit_limit = NULL,
        .instructions_count = 3,
        .signatures_count = 1,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) == 0);
    assert(fee == 1205000);
}

// Overflow in unit_price * max_compute must reject (return error)
void test_calculate_max_fee_overflow_rejects() {
    ComputeBudgetChangeUnitPriceInfo price = {.units = UINT64_MAX};
    ComputeBudgetChangeUnitLimitInfo limit = {.units = 2};
    ComputeBudgetFeeInfo info = {
        .change_unit_price = &price,
        .change_unit_limit = &limit,
        .instructions_count = 1,
        .signatures_count = 1,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) != 0);
}

// Another overflow case: large price with realistic limit must reject
void test_calculate_max_fee_overflow_large_price_rejects() {
    ComputeBudgetChangeUnitPriceInfo price = {.units = UINT64_C(18446744073709551615)};
    ComputeBudgetChangeUnitLimitInfo limit = {.units = 1400000};
    ComputeBudgetFeeInfo info = {
        .change_unit_price = &price,
        .change_unit_limit = &limit,
        .instructions_count = 1,
        .signatures_count = 1,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) != 0);
}

// Boundary: max_compute=1 should never overflow
void test_calculate_max_fee_no_overflow_unit_compute() {
    ComputeBudgetChangeUnitPriceInfo price = {.units = UINT64_MAX};
    ComputeBudgetChangeUnitLimitInfo limit = {.units = 1};
    ComputeBudgetFeeInfo info = {
        .change_unit_price = &price,
        .change_unit_limit = &limit,
        .instructions_count = 1,
        .signatures_count = 1,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) == 0);
    // UINT64_MAX / 1000000 + 5000
    assert(fee == UINT64_C(18446744073709551615) / 1000000 + 5000);
}

// Boundary: max_compute=0 should yield base fee only
void test_calculate_max_fee_zero_compute() {
    ComputeBudgetChangeUnitPriceInfo price = {.units = UINT64_MAX};
    ComputeBudgetChangeUnitLimitInfo limit = {.units = 0};
    ComputeBudgetFeeInfo info = {
        .change_unit_price = &price,
        .change_unit_limit = &limit,
        .instructions_count = 1,
        .signatures_count = 1,
    };
    uint64_t fee = 0;
    assert(calculate_max_fee(&info, &fee) == 0);
    assert(fee == 5000);
}

int main() {
    test_parse_compute_budget_instruction_kind();
    test_parse_compute_budget_instruction_kind_invalid();
    test_parse_compute_budget_instructions_invalid_kind();
    test_calculate_max_fee_normal();
    test_calculate_max_fee_no_truncation();
    test_calculate_max_fee_large_price();
    test_calculate_max_fee_base_only();
    test_calculate_max_fee_default_compute_limit();
    test_calculate_max_fee_overflow_rejects();
    test_calculate_max_fee_overflow_large_price_rejects();
    test_calculate_max_fee_no_overflow_unit_compute();
    test_calculate_max_fee_zero_compute();

    printf("passed\n");
    return 0;
}
