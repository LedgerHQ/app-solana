// Unit tests for cs_merge_engine.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_merge_engine.h"

static void test_all_survive_mvp(void) {
    printf("  test_all_survive_mvp\n");

    cs_instruction_result_t instrs[3];
    memset(instrs, 0, sizeof(instrs));
    bool survivors[3] = {false, false, false};

    assert(cs_merge_engine_run(instrs, 3, survivors) == 0);
    assert(survivors[0] == true);
    assert(survivors[1] == true);
    assert(survivors[2] == true);
}

static void test_zero_instructions(void) {
    printf("  test_zero_instructions\n");

    assert(cs_merge_engine_run(NULL, 0, NULL) == 0);
}

static void test_null_with_nonzero_count(void) {
    printf("  test_null_with_nonzero_count\n");

    bool survivors[1];
    assert(cs_merge_engine_run(NULL, 3, survivors) == -1);
}

static void test_null_survivors_with_nonzero_count(void) {
    printf("  test_null_survivors_with_nonzero_count\n");

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    assert(cs_merge_engine_run(&instr, 1, NULL) == -1);
}

static void test_single_instruction(void) {
    printf("  test_single_instruction\n");

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    bool survivor = false;

    assert(cs_merge_engine_run(&instr, 1, &survivor) == 0);
    assert(survivor == true);
}

int main(void) {
    printf("cs_merge_engine_test\n");
    test_all_survive_mvp();
    test_zero_instructions();
    test_null_with_nonzero_count();
    test_null_survivors_with_nonzero_count();
    test_single_instruction();
    printf("  All passed!\n");
    return 0;
}
