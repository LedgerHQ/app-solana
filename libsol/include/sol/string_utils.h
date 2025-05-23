#pragma once
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

bool is_data_utf8(const uint8_t *data, size_t length);
bool is_data_ascii(const uint8_t *data, size_t length);