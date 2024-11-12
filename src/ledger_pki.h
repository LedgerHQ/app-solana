#pragma once
#include <stdint.h>

extern int check_signature_with_pubkey(const char *tag,
                                       uint8_t *buffer,
                                       const uint8_t bufLen,
                                       const uint8_t keyUsageExp,
                                       uint8_t *signature,
                                       const uint8_t sigLen);