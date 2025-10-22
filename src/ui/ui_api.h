#pragma once

#include "os.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_HOME      C_home_solana_14px
#define ICON_SIGN_MENU C_home_solana_white_14px
#define ICON_WARNING   C_icon_warning
#define ICON_REVIEW    C_icon_certificate
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_HOME      C_home_solana_64px
#define ICON_SIGN_MENU C_home_solana_64px
#define ICON_WARNING   C_Warning_64px
#define ICON_REVIEW    C_Review_64px
#elif defined(TARGET_APEX_P)
#define ICON_HOME      C_home_solana_48px
#define ICON_SIGN_MENU C_home_solana_48px
#define ICON_WARNING   C_Warning_48px
#define ICON_REVIEW    C_Review_48px
#endif

void ui_idle(void);

void ui_settings(void);

void ui_get_public_key(void);

void start_blind_sign_error_ui(void);

void start_sign_tx_ui(size_t num_summary_steps);

void start_blind_sign_tx_ui(size_t num_summary_steps);

void start_sign_offchain_message_ui(bool is_ascii, size_t num_summary_steps);
