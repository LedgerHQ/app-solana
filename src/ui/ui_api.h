#pragma once

#include "os.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"

void ui_idle(void);

void ui_get_public_key(void);

void start_sign_tx_ui(size_t num_summary_steps);

#ifdef HAVE_NBGL
void start_sign_offchain_message_ui(bool is_ascii, size_t num_summary_steps);
#endif
#ifdef HAVE_BAGL
void start_sign_offchain_message_ui(size_t num_summary_steps,
                                    const enum SummaryItemKind *summary_step_kinds);
#endif