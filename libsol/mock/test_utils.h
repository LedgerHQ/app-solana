#pragma once

#define RUN_TEST(fn)                    \
    do {                                \
        printf("=> RUNNING " #fn "\n"); \
        fn();                           \
        printf("=> PASSED  " #fn "\n"); \
    } while (0)
