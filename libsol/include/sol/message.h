#pragma once

#include "parser.h"
#include "print_config.h"

int process_message_body(const uint8_t *message_body,
                         int message_body_length,
                         const PrintConfig *print_config);

int process_message_body_with_descriptor(const uint8_t *message_body,
                                         int message_body_length,
                                         const PrintConfig *print_config);

// Token2022 extensions the app cannot decode make the whole message suspect, so the warning
// applies whether or not the message could be clear signed. The blind signing path rebuilds
// the summary from scratch and has to add it back.
int message_print_extension_warning();
