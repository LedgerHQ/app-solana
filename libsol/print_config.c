#include "sol/print_config.h"
#include "util.h"

bool print_config_show_authority(const PrintConfig *print_config, const Pubkey *authority) {
    return print_config->expert_mode || !pubkeys_equal(print_config->signer_pubkey, authority);
}
