#pragma once

#include "os.h"

void ui_idle(void);

void ui_get_public_key(void);

void start_sign_tx_ui(size_t num_summary_steps);

void start_sign_offchain_message_ui(bool is_ascii, size_t num_summary_steps);
