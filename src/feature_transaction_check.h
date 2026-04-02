// Transaction Check feature flag.
// Wallet-sized screens (Stax, Flex, Apex) support Transaction Checks.
// Nano devices do not.
#pragma once

#ifdef SCREEN_SIZE_WALLET
#define HAVE_TRANSACTION_CHECKS
#endif
