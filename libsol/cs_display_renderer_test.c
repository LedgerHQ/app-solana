// Unit tests for cs_display_renderer.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cs_display_renderer.h"
#include "idl_kinds.h"
#include "app_mem_utils.h"

// Dummy template used by tests that don't care about operation_type/names.
static cs_instruction_template_t G_dummy_template;

static void init_dummy_template(void) {
    memset(&G_dummy_template, 0, sizeof(G_dummy_template));
    strlcpy(G_dummy_template.operation_type, "Transfer", sizeof(G_dummy_template.operation_type));
    strlcpy(G_dummy_template.display_fields[0].name, "Amount", sizeof(G_dummy_template.display_fields[0].name));
    strlcpy(G_dummy_template.display_fields[1].name, "Recipient", sizeof(G_dummy_template.display_fields[1].name));
}

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
    init_dummy_template();

    // 1000000 in little-endian
    uint8_t value[] = {0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_U64;
    instr.resolved[0].value = value;
    instr.resolved[0].value_size = 8;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // 1 header + 1 field = 2 elements
    assert(cs_display_renderer_element_count() == 2);

    const cs_display_element_t *header = cs_display_renderer_element(0);
    assert(header != NULL);
    assert(strcmp(header->title, "[1/1] Transfer") == 0);

    const cs_display_element_t *elem = cs_display_renderer_element(1);
    assert(elem != NULL);
    assert(strcmp(elem->title, "Amount") == 0);
    assert(strcmp(elem->value, "1000000") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_bool_leaf(void) {
    printf("  test_render_bool_leaf\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    uint8_t val_true = 1;
    uint8_t val_false = 0;

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_BOOL_U8;
    instr.resolved[0].value = &val_true;
    instr.resolved[0].value_size = 1;
    instr.resolved[1].kind = IDL_KIND_BOOL_U8;
    instr.resolved[1].value = &val_false;
    instr.resolved[1].value_size = 1;
    instr.resolved_count = 2;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // 1 header + 2 fields = 3 elements
    assert(cs_display_renderer_element_count() == 3);
    assert(strcmp(cs_display_renderer_element(0)->title, "[1/1] Transfer") == 0);
    assert(strcmp(cs_display_renderer_element(1)->title, "Amount") == 0);
    assert(strcmp(cs_display_renderer_element(1)->value, "True") == 0);
    assert(strcmp(cs_display_renderer_element(2)->title, "Recipient") == 0);
    assert(strcmp(cs_display_renderer_element(2)->value, "False") == 0);

    cs_display_renderer_reset();
    assert(mock_mem_outstanding() == 0);
}

static void test_render_skips_null_value(void) {
    printf("  test_render_skips_null_value\n");
    mock_mem_reset();
    cs_display_renderer_reset();
    init_dummy_template();

    cs_instruction_result_t instr;
    memset(&instr, 0, sizeof(instr));
    instr.template = &G_dummy_template;
    instr.resolved[0].kind = IDL_KIND_U8;
    instr.resolved[0].value = NULL;
    instr.resolved[0].value_size = 0;
    instr.resolved_count = 1;

    bool survivor = true;
    assert(cs_display_renderer_run(&instr, 1, &survivor) == 0);
    // Header emitted, but the NULL-valued field is skipped
    assert(cs_display_renderer_element_count() == 1);
    assert(strcmp(cs_display_renderer_element(0)->title, "[1/1] Transfer") == 0);

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
