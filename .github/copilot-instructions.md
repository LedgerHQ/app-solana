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

Always run in venv (`venv` alias if needed):

```bash
# Python UI tests (Speculos)
pytest tests/python/ --device flex
pytest tests/python/ --device stax --golden_run  # Regenerate snapshots, use conservatively

# Swap tests (Exchange + Ethereum apps)
pytest tests/swap/ --device flex
pytest tests/swap/ --device flex --golden_run  # Regenerate snapshots, use conservatively

# libsol unit tests
make -C libsol
COVERAGE=1 make -C libsol
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

**Globals:** `G_*` prefix, `N_storage` for NVM
**Errors:** `ApduReply*` codes, `THROW()` macro
**UI:** NBGL only (`src/ui/*_nbgl.c`), no Bagl
**Security:** `explicit_bzero()` for sensitive data

**Key constants:**
- `MAX_MESSAGE_LENGTH`: 15KB
- `MAX_BIP32_PATH_LENGTH`: 5
- BIP44: `44'/501'` for Solana

**Logging:**
- Never assume code is correct on first try - add logs to verify execution flow
- Trace logs (no variables): Use `PRINTF("Function entered\n")` sparingly in key dispatch logic (e.g., APDU handlers, main switch cases)
- Variable logs: Use `PRINTF("variable_name=%d\n", var)` or `PRINTF("buffer=%.*H\n", len, buf)` liberally in calculations and new code
- Purpose: Help understand what actually runs vs what was expected to run

## Critical Files

- `src/main_application.c` - APDU dispatch
- `src/apdu.c` - APDU parsing
- `src/handle_sign_message.c` - Transaction signing
- `src/handle_sign_message_preview.{c,h}` - Delayed signing
- `libsol/message.c` - Core parser
- `libsol/transaction_summary.c` - UI summary
- `doc/api.md` - APDU protocol spec

## Makefile Flags

- `ENABLE_TLV_LIBRARY=1` - Trusted names
- `ENABLE_PKI_LIBRARY=1` - PKI verification
- `ENABLE_NBGL_FOR_NANO_DEVICES=1` - NBGL on all devices
- `ENABLE_SWAP=1` - Exchange integration

Makefile flags are handled through the `qb` tool via `ledger_app.toml`. dbg_trusted_name_test is the standard debug profile.

## Common Issues

1. **libsol is portable** - no SDK includes in `libsol/*.c` files
2. **Clean when needed** - `qb -c` clears leftover .o files (not required for device switches)
4. **Swap context is different than normal Dashboard start and blocks features** - `G_called_from_swap` prevents other features like message preview or blind signing.


When reviewing code, you are a skilled security-focused firmware engineer tasked with providing feedback on its quality, readability, maintainability, and adherence to best practices. Please ensure that your review is constructive and actionable, highlighting areas for improvement. Consider aspects such as code structure, naming conventions, documentation, and overall design. Your insights will help enhance the codebase and contribute to the success of the project.

When reviewing code, if the overall quality is deemed too low, state so while highlighting the specific issues that led to this conclusion.

## C and Rust code review guidelines

The C and Rust files hold the logic of the embedded application. When reviewing these files, focus on best practices for embedded development, such as memory management, performance optimization, and security considerations. Ensure that the code is well-structured, with clear separation of concerns and modular design. Look for consistent naming conventions, thorough documentation, and adherence to coding standards specific to C and Rust.

In addition, pay special attention to the Ledger-specific constraints:
- The application uses the Ledger SDK, which has its own set of APIs and conventions. Ensure that the code follows the SDK guidelines and makes efficient use of its features. The SDK code is available at https://github.com/LedgerHQ/ledger-secure-sdk/
- The UI is the fundamental part of the embedded application, NOT a cosmetic side. Ensure all sensitive operations (signing, public key export) are preceded by an explicit user validation screen. Flag any "blind signing" patterns or flows where the screen doesn't accurately represent the buffer being signed.
- The RAM is limited to a few kilobytes. Ensure that the code is optimized for low memory usage and does not contain unnecessary allocations or large data structures without falling into code golf.
- Ensure sensitive data such as private keys are cleaned with `explicit_bzero`.
- The SDK exposes a deprecated API for custom exceptions. Ensure the PR does not introduce new THROW calls.
- Cryptographic calls must be made through the SDK's `cx_` functions. Ensure that all cryptographic operations are performed using these functions and that they are used correctly to maintain security and performance.
- APDUs are the sole entry point of the application. Ensure the code treats the incoming APDUs as untrusted input and implements proper validation and error handling to prevent potential security vulnerabilities. Look for robust parsing of APDU commands, validation of input data, and appropriate responses to invalid or malicious requests.
- Remember that the RAM is reset on every power cycle.

## Python test code review guidelines

The Python code is only used for testing and is not part of the embedded application. When reviewing test files, focus on coverage and maintainability rather than embedded application best practices. Ensure that the tests are comprehensive, well-structured, and easy to understand. Look for clear assertions, proper use of testing frameworks, and meaningful test cases that effectively validate the functionality of the embedded application.

Ensure new features are covered by functional tests, checking the valid expected behaviors, edge cases, and potential malicious inputs.

## MANDATORY STEP : MOST IMPORTANT ONE

When performing a code review, it is MANDATORY that every C function is preceeded by a Doxygen comment block that describes its purpose, parameters, return values, and any relevant details. If a function lacks such documentation, it is a critical issue that must be addressed before the code can be considered for merging. The absence of proper documentation can lead to confusion and hinder the maintainability of the codebase. Therefore, ensure that all functions are adequately documented to facilitate understanding and future maintenance.

The usage of PRINTF is COMPLETELY FORBIDDEN, when reviewing code flag all usage of PRINTF as a critical issue.
