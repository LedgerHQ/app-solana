#ifndef TRUSTED_INFO_H_
#define TRUSTED_INFO_H_

void handle_provide_trusted_info(void);

extern Pubkey g_trusted_token_account_owner_pubkey;
extern bool g_trusted_token_account_owner_pubkey_set;

#endif  // TRUSTED_INFO_H_