#pragma once

#include "parser.h"
#include <stdbool.h>

typedef struct PrintConfig {
    MessageHeader header;
    bool expert_mode;
    bool force_full_print;
    bool user_input_is_ata_or_token_account;
    const Pubkey *signer_pubkey;
} PrintConfig;

bool print_config_show_authority(const PrintConfig *print_config, const Pubkey *authority);
