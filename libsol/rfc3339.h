#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool rfc3339_is_displayable(int64_t seconds);
int rfc3339_format(char *dst, size_t len, int64_t seconds);
