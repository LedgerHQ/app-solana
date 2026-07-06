#pragma once

#include "feature_transaction_check.h"

#ifdef HAVE_TRANSACTION_CHECKS

#include <stdbool.h>

// Show the Transaction Check opt-in consent screen.
// If response_expected is true, the APDU response will be sent after user choice.
// If false, the UI returns to settings after user choice.
void ui_transaction_check_opt_in(bool response_expected);

#endif  // HAVE_TRANSACTION_CHECKS
