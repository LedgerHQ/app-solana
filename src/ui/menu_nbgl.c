
/*****************************************************************************
 *   Ledger App Solana
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "ui_api.h"
#include "utils.h"
#include "feature_transaction_check.h"
#ifdef HAVE_TRANSACTION_CHECKS
#include "transaction_check_ui.h"
#endif

static void quit_app_callback(void) {
    os_sched_exit(-1);
}

#define SETTING_INFO_NB 2
static const char *const info_types[SETTING_INFO_NB] = {"Version", "Developer"};
static const char *const info_contents[SETTING_INFO_NB] = {APPVERSION, "Ledger"};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = info_types,
    .infoContents = info_contents,
};

enum {
    BLIND_SIGNING_IDX = 0,
    PUBLIC_KEY_LENGTH_IDX,
    DISPLAY_MODE_IDX,
#ifdef HAVE_TRANSACTION_CHECKS
    TRANSACTION_CHECKS_IDX,
#endif
    NB_SETTINGS_SWITCHES,
};
static nbgl_layoutSwitch_t G_switches[NB_SETTINGS_SWITCHES];

enum {
    BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN,
    PUBLIC_KEY_LENGTH_TOKEN,
    DISPLAY_MODE_TOKEN,
#ifdef HAVE_TRANSACTION_CHECKS
    TRANSACTION_CHECKS_TOKEN,
#endif
};

static void settings_controls_callback(int token, uint8_t index, int page);

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = NB_SETTINGS_SWITCHES,
     .content.switchesList.switches = G_switches,
     .contentActionCallback = settings_controls_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};

static void settings_controls_callback(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);
    uint8_t new_setting;
    switch (token) {
        case BLIND_SIGNING_TOKEN:
            // Write in NVM the opposite of what the current toggle is
            new_setting = (G_switches[BLIND_SIGNING_IDX].initState != ON_STATE);
            G_switches[BLIND_SIGNING_IDX].initState = (nbgl_state_t) new_setting;
            nvm_write((void *) &N_storage.settings.allow_blind_sign,
                      &new_setting,
                      sizeof(new_setting));
            break;
        case PUBLIC_KEY_LENGTH_TOKEN:
            // Write in NVM the opposite of what the current toggle is
            new_setting = (G_switches[PUBLIC_KEY_LENGTH_IDX].initState != ON_STATE);
            G_switches[PUBLIC_KEY_LENGTH_IDX].initState = (nbgl_state_t) new_setting;
            nvm_write((void *) &N_storage.settings.pubkey_display,
                      &new_setting,
                      sizeof(new_setting));
            break;
        case DISPLAY_MODE_TOKEN:
            // Write in NVM the opposite of what the current toggle is
            new_setting = (G_switches[DISPLAY_MODE_IDX].initState != ON_STATE);
            G_switches[DISPLAY_MODE_IDX].initState = (nbgl_state_t) new_setting;
            nvm_write((void *) &N_storage.settings.display_mode, &new_setting, sizeof(new_setting));
            break;
#ifdef HAVE_TRANSACTION_CHECKS
        case TRANSACTION_CHECKS_TOKEN:
            if (!N_storage.settings.tx_check_opt_in) {
                PRINTF("First time enabling Transaction Checks, showing opt-in screen\n");
                // First time: show consent screen instead of direct toggle.
                // The opt-in UI will set both tx_check_opt_in and tx_check_enable.
                ui_transaction_check_opt_in(false);
            } else {
                new_setting = (G_switches[TRANSACTION_CHECKS_IDX].initState != ON_STATE);
                G_switches[TRANSACTION_CHECKS_IDX].initState = (nbgl_state_t) new_setting;
                nvm_write((void *) &N_storage.settings.tx_check_enable,
                          &new_setting,
                          sizeof(new_setting));
                PRINTF("No-screen toggling TX Checks to %d\n", N_storage.settings.tx_check_enable);
            }
            break;
#endif  // HAVE_TRANSACTION_CHECKS
        default:
            PRINTF("Unreachable\n");
            break;
    }
}

static void ui_main_menu(uint8_t page) {
    G_switches[BLIND_SIGNING_IDX].text = "Blind signing";
    G_switches[BLIND_SIGNING_IDX].subText = "Enable blind signing";
    G_switches[BLIND_SIGNING_IDX].token = BLIND_SIGNING_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    G_switches[BLIND_SIGNING_IDX].tuneId = TUNE_TAP_CASUAL;
#endif
    if (N_storage.settings.allow_blind_sign == BlindSignDisabled) {
        G_switches[BLIND_SIGNING_IDX].initState = OFF_STATE;
    } else {
        G_switches[BLIND_SIGNING_IDX].initState = ON_STATE;
    }

    G_switches[PUBLIC_KEY_LENGTH_IDX].text = "Public key length";
    G_switches[PUBLIC_KEY_LENGTH_IDX].subText = "Display short public keys";
    G_switches[PUBLIC_KEY_LENGTH_IDX].token = PUBLIC_KEY_LENGTH_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    G_switches[PUBLIC_KEY_LENGTH_IDX].tuneId = TUNE_TAP_CASUAL;
#endif
    if (N_storage.settings.pubkey_display == PubkeyDisplayLong) {
        G_switches[PUBLIC_KEY_LENGTH_IDX].initState = OFF_STATE;
    } else {
        G_switches[PUBLIC_KEY_LENGTH_IDX].initState = ON_STATE;
    }

    G_switches[DISPLAY_MODE_IDX].text = "Display mode";
    G_switches[DISPLAY_MODE_IDX].subText = "Use Expert display mode";
    G_switches[DISPLAY_MODE_IDX].token = DISPLAY_MODE_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    G_switches[DISPLAY_MODE_IDX].tuneId = TUNE_TAP_CASUAL;
#endif
    if (N_storage.settings.display_mode == DisplayModeUser) {
        G_switches[DISPLAY_MODE_IDX].initState = OFF_STATE;
    } else {
        G_switches[DISPLAY_MODE_IDX].initState = ON_STATE;
    }

#ifdef HAVE_TRANSACTION_CHECKS
    G_switches[TRANSACTION_CHECKS_IDX].text = "Transaction Check";
    G_switches[TRANSACTION_CHECKS_IDX].subText =
        "Get real-time warnings about risky transactions. Learn more: ledger.com/tx-check";
    G_switches[TRANSACTION_CHECKS_IDX].token = TRANSACTION_CHECKS_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    G_switches[TRANSACTION_CHECKS_IDX].tuneId = TUNE_TAP_CASUAL;
#endif
    G_switches[TRANSACTION_CHECKS_IDX].initState = N_storage.settings.tx_check_enable ? ON_STATE
                                                                                      : OFF_STATE;
#endif  // HAVE_TRANSACTION_CHECKS

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &ICON_HOME,
                                NULL,
                                page,
                                &settingContents,
                                &infoList,
                                NULL,
                                quit_app_callback);
}

void ui_idle(void) {
    ui_main_menu(INIT_HOME_PAGE);
}
/**
 * Go to settings screen
 */
void ui_settings(void) {
    ui_main_menu(0);
}
