#pragma once

#include <stdint.h>
#include <stdbool.h>

int store_preview_fingerprint(const uint8_t *message,
                              size_t message_length,
                              const uint32_t *derivation_path,
                              uint32_t derivation_path_length);
int store_cs_preview_fingerprint(void);
int handle_sign_message_delayed(void);
void clear_preview_state(void);
