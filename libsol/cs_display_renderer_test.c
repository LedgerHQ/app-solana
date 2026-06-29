// Unit tests for cs_display_renderer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_display_renderer.h"
#include "idl_kinds.h"
#include "app_mem_utils.h"

static void test_initial_state(void) {
    printf("  test_initial_state\n");
    cs_display_renderer_reset();
    assert(cs_display_renderer_element_count() == 0);
    assert(cs_display_renderer_element(0) == NULL);
}

static void test_render_u64_leaf(void) {
    printf("  test_render_u64_leaf\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    // 1000000 in little-endian
    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_element_count() == 1);

    const cs_display_element_t *elem = cs_display_renderer_element(0);
    assert(elem != NULL);
    assert(strcmp(elem->value, "1000000") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_bool_leaf(void) {
    printf("  test_render_bool_leaf\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    uint8_t val_true = 1;
    uint8_t val_false = 0;

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    instr.resolved[0].kind = IDL_KIND_BOOL_U8;
    instr.resolved[0].value = &val_true;
    instr.resolved[0].value_size = 1;
    instr.resolved[1].kind = IDL_KIND_BOOL_U8;
    instr.resolved[1].value = &val_false;
    instr.resolved[1].value_size = 1;
    instr.resolved_count = 2;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_element_count() == 2);
    assert(strcmp(cs_display_renderer_element(0)->value, "True") == 0);
    assert(strcmp(cs_display_renderer_element(1)->value, "False") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_skips_null_value(void) {
    printf("  test_render_skips_null_value\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    instr.resolved[0].kind = IDL_KIND_U8;
    instr.resolved[0].value = NULL;
    instr.resolved[0].value_size = 0;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    assert(cs_display_renderer_element_count() == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_empty_input(void) {
    printf("  test_render_empty_input\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    assert(cs_display_renderer_run(NULL, 0, NULL) == 0);
    assert(cs_display_renderer_element_count() == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_alloc_failure(void) {
    printf("  test_alloc_failure\n");
    mock_mem_reset();
    cs_display_renderer_reset();

    mock_mem_fail_after(0);
    bool survivor = true;
    assert(cs_display_renderer_run(NULL, 0, &survivor) == -1);
    assert(cs_display_renderer_element_count() == 0);

    mock_mem_reset();
    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

int main(void) {
    printf("cs_display_renderer_test\n");
    test_initial_state();
    test_render_u64_leaf();
    test_render_bool_leaf();
    test_render_skips_null_value();
    test_render_empty_input();
    test_alloc_failure();
    printf("  All passed!\n");
    return 0;
}
