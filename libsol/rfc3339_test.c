#include "rfc3339.c"
#include "util.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>

void test_rfc3339_format() {
    char s[20];

    // Buffer too small fails
    assert(rfc3339_format(s, sizeof(s) - 1, 0) == 1);

    // seconds too large fails
    int64_t too_large = (3652060LL * 86400) - EPOCH;
    assert(rfc3339_format(s, sizeof(s), too_large) == 1);

    // seconds too small fails
    int64_t too_small = -EPOCH - 1;
    assert(rfc3339_format(s, sizeof(s), too_small) == 1);

    assert(rfc3339_format(s, sizeof(s), -EPOCH) == 0);
    assert_string_equal(s, "0000-12-31 00:00:00");
    assert(rfc3339_format(s, sizeof(s), 0) == 0);
    assert_string_equal(s, "1970-01-01 00:00:00");
    assert(rfc3339_format(s, sizeof(s), too_large - 1) == 0);
    assert_string_equal(s, "9999-12-31 23:59:59");
}

int main() {
    RUN_TEST(test_rfc3339_format);

    printf("passed\n");
    return 0;
}
