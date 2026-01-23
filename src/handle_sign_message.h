#pragma once

void handle_sign_message_parse_message(volatile unsigned int *flags, volatile unsigned int *tx);

void swap_finalize(bool is_valid);
