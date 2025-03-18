#pragma once

#include "parser.h"
#include <stdbool.h>

typedef struct PrintConfig {
    MessageHeader header;
    bool expert_mode;
    const Pubkey *signer_pubkey;
} PrintConfig;

bool print_config_show_authority(const PrintConfig *print_config, const Pubkey *authority);
