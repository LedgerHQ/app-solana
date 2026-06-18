#pragma once

// Host-side mock of the SDK dynamic allocator (lib_alloc/app_mem_utils.h).
//
// On device, libsol is compiled with ENABLE_DYNAMIC_ALLOC=1 and resolves
// `app_mem_utils.h` to the real SDK header. In the libsol unit-test build the
// `-Imock` include path makes this stub take precedence instead, mapping the
// APP_MEM_* macros onto a malloc-backed allocator that supports out-of-space
// fault injection and outstanding-allocation accounting (for leak detection).

#include <stddef.h>

void *mock_mem_alloc(size_t size);
void *mock_mem_realloc(void *ptr, size_t size);
void mock_mem_free(void *ptr);
void mock_mem_free_and_null(void **ptr);

// Test controls (not part of the real SDK API).
//
// `mock_mem_reset()` clears every counter and disables fault injection.
// `mock_mem_fail_after(n)` lets the next `n` allocations succeed, then forces
// every subsequent allocation to return NULL (simulating an out-of-space
// allocator). A negative value disables fault injection.
// `mock_mem_outstanding()` returns the number of live allocations, so a test
// can assert that a reset path freed everything it took.
void mock_mem_reset(void);
void mock_mem_fail_after(int n);
size_t mock_mem_outstanding(void);

#define APP_MEM_ALLOC(size)        mock_mem_alloc(size)
#define APP_MEM_REALLOC(ptr, size) mock_mem_realloc(ptr, size)
#define APP_MEM_FREE(ptr)          mock_mem_free(ptr)
#define APP_MEM_FREE_AND_NULL(ptr) mock_mem_free_and_null(ptr)
