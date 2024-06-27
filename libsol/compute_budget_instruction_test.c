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
    ComputeBudgetInfo info;

    int result = parse_compute_budget_instructions(&instruction, &info);

    assert(result == 1);  // Invalid instruction kind for ComputeBudget program
}

int main() {
    test_parse_compute_budget_instruction_kind();
    test_parse_compute_budget_instruction_kind_invalid();
    test_parse_compute_budget_instructions_invalid_kind();

    printf("passed\n");
    return 0;
}