#pragma once
#include <stdint.h>

void roll_challenge(void);
uint32_t get_challenge(void);
void handle_get_challenge(volatile unsigned int *tx);
