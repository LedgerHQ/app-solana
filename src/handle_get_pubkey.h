#pragma once

#include "os.h"
#include "cx.h"
#include "globals.h"
#include "sol/printer.h"

extern char G_publicKeyStr[BASE58_PUBKEY_LENGTH];

void reset_getpubkey_globals(void);

int handle_get_pubkey(void);

uint8_t set_result_get_pubkey(void);
