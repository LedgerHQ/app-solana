#pragma once

#include "parser.h"
#include "print_config.h"

int process_message_body(const uint8_t *message_body,
                         int message_body_length,
                         const PrintConfig *print_config);
