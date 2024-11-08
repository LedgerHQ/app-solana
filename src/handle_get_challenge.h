#ifndef TRUSTED_INFO_CHALLENGE_H_
#define TRUSTED_INFO_CHALLENGE_H_

#include <stdint.h>

void roll_challenge(void);
uint32_t get_challenge(void);
void handle_get_challenge(volatile unsigned int *tx);

#endif  // TRUSTED_INFO_CHALLENGE_H_