#ifndef TRUSTED_INFO_H_
#define TRUSTED_INFO_H_

#include <stdint.h>
#include <stdbool.h>

#include "sol/parser.h"

#define MAX_ADDRESS_LENGTH 32

#define TYPE_ADDRESS 0x06
#define TYPE_DYN_RESOLVER 0x06

bool has_trusted_info(uint8_t types_count,
                      const uint64_t *chain_id,
                      const uint8_t *addr);
void handle_provide_trusted_info(void);

extern Pubkey g_trusted_token_account_owner_pubkey;

#endif  // TRUSTED_INFO_H_