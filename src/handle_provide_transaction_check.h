#pragma once

#include "feature_transaction_check.h"

#ifdef HAVE_TRANSACTION_CHECKS

#include "nbgl_use_case.h"
#include "tlv_use_case_transaction_check.h"

int handle_provide_transaction_check(void);
int handle_transaction_check_opt_in(void);
void apply_transaction_check_report(nbgl_warning_t *warning);
void clear_transaction_check(void);

#endif  // HAVE_TRANSACTION_CHECKS
