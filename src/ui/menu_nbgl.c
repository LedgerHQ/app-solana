
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

#ifdef HAVE_NBGL

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "ui_api.h"
#include "utils.h"

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
    NB_SETTINGS_SWITCHES,
};
static nbgl_layoutSwitch_t G_switches[NB_SETTINGS_SWITCHES];

enum {
    BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN,
    PUBLIC_KEY_LENGTH_TOKEN,
    DISPLAY_MODE_TOKEN,
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
        default:
            PRINTF("Unreachable\n");
            break;
    }
}

void ui_idle(void) {
    G_switches[BLIND_SIGNING_IDX].text = "Blind signing";
    G_switches[BLIND_SIGNING_IDX].subText = "Enable blind signing";
    G_switches[BLIND_SIGNING_IDX].token = BLIND_SIGNING_TOKEN;
    G_switches[BLIND_SIGNING_IDX].tuneId = TUNE_TAP_CASUAL;
    if (N_storage.settings.allow_blind_sign == BlindSignDisabled) {
        G_switches[BLIND_SIGNING_IDX].initState = OFF_STATE;
    } else {
        G_switches[BLIND_SIGNING_IDX].initState = ON_STATE;
    }

    G_switches[PUBLIC_KEY_LENGTH_IDX].text = "Public key length";
    G_switches[PUBLIC_KEY_LENGTH_IDX].subText = "Display short public keys";
    G_switches[PUBLIC_KEY_LENGTH_IDX].token = PUBLIC_KEY_LENGTH_TOKEN;
    G_switches[PUBLIC_KEY_LENGTH_IDX].tuneId = TUNE_TAP_CASUAL;
    if (N_storage.settings.pubkey_display == PubkeyDisplayLong) {
        G_switches[PUBLIC_KEY_LENGTH_IDX].initState = OFF_STATE;
    } else {
        G_switches[PUBLIC_KEY_LENGTH_IDX].initState = ON_STATE;
    }

    G_switches[DISPLAY_MODE_IDX].text = "Display mode";
    G_switches[DISPLAY_MODE_IDX].subText = "Use Expert display mode";
    G_switches[DISPLAY_MODE_IDX].token = DISPLAY_MODE_TOKEN;
    G_switches[DISPLAY_MODE_IDX].tuneId = TUNE_TAP_CASUAL;
    if (N_storage.settings.display_mode == DisplayModeUser) {
        G_switches[DISPLAY_MODE_IDX].initState = OFF_STATE;
    } else {
        G_switches[DISPLAY_MODE_IDX].initState = ON_STATE;
    }

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &C_icon_solana_64x64,
                                NULL,
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                quit_app_callback);
}
#endif
