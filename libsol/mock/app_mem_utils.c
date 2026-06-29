// Host-side mock of the SDK dynamic allocator. See app_mem_utils.h for the
// rationale and the test-control API.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "app_mem_utils.h"

// Number of allocations still live (alloc - free). Lets tests assert that a
// reset/cleanup path freed everything it allocated.
static size_t g_outstanding = 0;

// Fault injection: when >= 0, counts down on each allocation and forces NULL
// once it reaches zero. When < 0, allocations behave normally.
static int g_fail_after = -1;

void mock_mem_reset(void) {
    g_outstanding = 0;
    g_fail_after = -1;
}

void mock_mem_fail_after(int n) {
    g_fail_after = n;
}

size_t mock_mem_outstanding(void) {
    return g_outstanding;
}

static bool should_fail(void) {
    if (g_fail_after < 0) {
        return false;
    }
    if (g_fail_after == 0) {
        return true;
    }
    g_fail_after -= 1;
    return false;
}

void *mock_mem_alloc(size_t size) {
    if (should_fail()) {
        return NULL;
    }
    void *ptr = malloc(size);
    if (ptr != NULL) {
        g_outstanding += 1;
    }
    return ptr;
}

void *mock_mem_realloc(void *ptr, size_t size) {
    if (should_fail()) {
        return NULL;
    }
    void *new_ptr = realloc(ptr, size);
    if (new_ptr != NULL && ptr == NULL) {
        g_outstanding += 1;
    }
    return new_ptr;
}

void mock_mem_free(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    free(ptr);
    if (g_outstanding > 0) {
        g_outstanding -= 1;
    }
}

void mock_mem_free_and_null(void **ptr) {
    if (ptr == NULL) {
        return;
    }
    mock_mem_free(*ptr);
    *ptr = NULL;
}

bool mock_mem_calloc(void **ptr, size_t size) {
    if (ptr == NULL) {
        return false;
    }
    // Free any previous allocation before allocating a new one
    if (*ptr != NULL) {
        mock_mem_free(*ptr);
        *ptr = NULL;
    }
    void *new_ptr = mock_mem_alloc(size);
    if (new_ptr == NULL) {
        return false;
    }
    memset(new_ptr, 0, size);
    *ptr = new_ptr;
    return true;
}
