# Solana Ledger App - Development Guide

## Build & Compile

Use `qb` tool (auto-runs in Docker):

```bash
qb -e -f dbg_trusted_name_test    # FLEX with test flags
qb -a -f dbg_trusted_name_test    # STAX with test flags
qb -xpaen -f dbg_trusted_name_test # All devices
qb -cx                            # Clean rebuild for NANOX
```

**NANOS is DEPRECATED** - do not support it.

## Testing

Always run the tests in the python virtual environment, use the `venv` bash alias to enter it. DO NOT try to source an activate file, use the BASH ALIAS.

```bash
# Python UI tests (Speculos)
venv && pytest tests/python/ --device flex
venv && pytest tests/python/ --device stax --golden_run  # Regenerate snapshots, use conservatively

# Swap tests (Exchange + Ethereum apps)
venv && pytest tests/swap/ --device flex
venv && pytest tests/swap/ --device flex --golden_run  # Regenerate snapshots, use conservatively

# NEVER attempt to run both pytest instances, "pytest tests/python/ tests/swap/" it WILL NOT work.

# libsol unit tests
qb_run_in_docker make -C libsol
qb_run_in_docker COVERAGE=1 make -C libsol

# Memory leak tests (valground)
# Build with memory_profiling flag, run pytest with -s to capture allocator logs, pipe to valground.py
# Clean if previous compilation was with a different flag, e.g. from dbg_trusted_name_test to memory_profiling
qb -ce -f memory_profiling
venv && pytest tests/python/ --device flex -s 2>&1 | tools/valground.py -q
```

## Architecture

### APDU Flow
1. `io_exchange()` → `G_io_apdu_buffer`
2. `apdu_handle_message()` parses header
3. `src/handle_*.c` handlers process payload
4. Multi-APDU uses `P2_EXTEND` flag

**Instructions:** `0x04` config, `0x05` pubkey, `0x06` sign, `0x07` offchain, `0x08` preview, `0x09` delayed sign, `0x16-0x22` trusted name

### Transaction Parsing (libsol)
Portable C code, no SDK deps (except `libsol/mock/` for tests):
1. `message.c` → parse header/accounts
2. `instruction.c` → identify programs
3. Program parsers → `system_instruction.c`, `spl_token_instruction.c`, etc.
4. `transaction_summary.c` → build UI items

**Summary items** → NBGL screens (Amount, Pubkey, String types)

### Trusted Names
PKI-signed token metadata for display:
- `handle_provide_trusted_info.c` - TLV descriptors
- `handle_provide_dynamic_descriptor.c` - Token metadata
- `handle_get_challenge.c` - Replay protection
- Test mode: `TRUSTED_NAME_TEST_KEY=1` in `ledger_app.toml`

### Delayed Signing
Preview (INS 0x08) stores SHA-512 fingerprint of message with zeroed blockhash, then delayed sign (INS 0x09) verifies and signs instantly.
- Preview mode: `G_command.is_preview_mode = true`
- Verification checks: hash, length, derivation path
- Error codes: `0x6f10` (no preview), `0x6f11` (hash), `0x6f12` (length), `0x6f13` (derivation)
- State cleared after every delayed sign

## Code Patterns

### Logging

- Never assume code is correct on first try - add logs to verify execution flow
- Trace logs (no variables): Use `PRINTF("Function entered\n")` sparingly in key dispatch logic (e.g., APDU handlers, main switch cases)
- Variable logs: Use `PRINTF("variable_name=%d\n", var)` or `PRINTF("buffer=%.*H\n", len, buf)` liberally in calculations and new code
- Purpose: Help understand what actually runs vs what was expected to run

### Coding conventions

- bool return is used to indicate the result of a CHECK, NOT a success or failure.
- int return is used to report a success or failure of a function by using -1 or 0.
- Global or module variables are prefixed by `G_*`.

### Swap feature

- The SWAP flow is the flow started from the Exchange application instead of the dashboard. It enables some features and blocks others.
- The information coming from Exchange is TRUSTED.
- The application must return to Exchange after the handling of an apdu to sign, whether valid or not. Return is made through the send_swap_error_X() SDK functions in case of error, or through the SDK IO stack once G_swap_response_ready has been set. In both cases, cleaning non-sensitive data is completely useless (dynamic allocator free, apdu managers, etc).

## Critical Files

- `src/main_application.c` - APDU dispatch
- `src/apdu.c` - APDU parsing
- `src/handle_sign_message.c` - Transaction signing
- `src/handle_sign_message_preview.{c,h}` - Delayed signing
- `libsol/message.c` - Core parser
- `libsol/transaction_summary.c` - UI summary
- `doc/api.md` - APDU protocol spec

Makefile flags are handled through the `qb` tool via `ledger_app.toml`. dbg_trusted_name_test is the standard debug profile.

## Common Issues

1. **libsol is portable** - no SDK includes in `libsol/*.c` files
2. **Clean only when needed** - `qb -c` clears leftover .o files (not required for device switches)
4. **Swap context is different than normal Dashboard start and blocks features** - `G_called_from_swap` prevents other features like message preview or blind signing.
