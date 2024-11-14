#ifndef TRUSTED_INFO_H_
#define TRUSTED_INFO_H_

void handle_provide_trusted_info(void);

#define MAX_ADDRESS_LENGTH 44

extern uint8_t g_trusted_token_account_owner_pubkey[MAX_ADDRESS_LENGTH + 1];
extern bool g_trusted_token_account_owner_pubkey_set;

#endif  // TRUSTED_INFO_H_