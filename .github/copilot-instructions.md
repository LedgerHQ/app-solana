# Solana Ledger App - Development Guide

## Build & Compile

Never truncate, filter, or paginate the output of qb, qb_run_in_docker, or pytest. Run them raw and read the whole output. This bans appending | tail, | head, | less, | grep, | wc, and any 2>&1 | … filter to these commands. They are deliberately tuned to print only meaningful lines, so there is nothing to trim.

Use `qb` tool (auto-runs in Docker):

```bash
qb -e -f dbg_trusted_name_test    # FLEX with test flags
qb -a -f dbg_trusted_name_test    # STAX with test flags
qb -xpaen -f dbg_trusted_name_test # All devices
qb -cx                            # Clean rebuild for NANOX
```

**NANOS is DEPRECATED**

## Testing

Whenever possible, adopt a TDD approch when developing new features or fixing bugs.

### Running Tests

Always run the tests in the python virtual environment, use the `venv` bash alias to enter it. DO NOT try to source an activate file, use the BASH ALIAS.
NEVER use 'python3' in the venv, use 'python'
Run only one pytest per command line, do not chain them with `&&`

```bash
# Python UI tests (Speculos)
venv && pytest tests/python/ --device flex
venv && pytest tests/python/ --device stax --golden_run  # Regenerate snapshots, use conservatively

# Swap tests (Exchange + Ethereum apps)
venv && pytest tests/swap/ --device flex
venv && pytest tests/swap/ --device flex --golden_run  # Regenerate snapshots, use conservatively

# libsol unit tests
qb_run_in_docker make -C libsol QUIET=1
qb_run_in_docker make -C libsol QUIET=1 clean
qb_run_in_docker COVERAGE=1 make -C libsol QUIET=1

# Memory leak tests (valground)
# Build with memory_profiling flag, run pytest with -s to capture allocator logs, pipe to valground.py
# Clean if previous compilation was with a different flag, e.g. from dbg_trusted_name_test to memory_profiling
qb -ce -f memory_profiling
venv && pytest tests/python/ --device flex -s 2>&1 | tools/valground.py -q
```

### Test pitfals

- NEVER attempt to run both pytest instances, "pytest tests/python/ tests/swap/" it WILL NOT work as fixtures will fight each other.
- snapshot checking is performed before returning APDU response: a snapshot failure can mean the application refused to sign and is displaying an error screen.
- tests can timeout in case of errors, if that happens be smart when iterating to avoid wasting too much time.
- debuging a test is done by adding logs in the C code, rebuilding, and re-running the test with `-s` option so Speculos prints PRINTF in stdout.
- There is NO SUCH THING as a "pre-existing failure". All tests are presumed correct and failures are ALWAYS caused by latest changes. Suggesting otherwise is entirely FORBIDDEN. ALL TESTS SHALL ALWAYS PASS.

## Architecture

### APDU Flow
1. `io_exchange()` → `G_io_apdu_buffer`
2. `apdu_handle_message()` parses header
3. `src/handle_*.c` handlers process payload
4. Multi-APDU uses `P2_EXTEND` flag

**Instructions:** `0x04` config, `0x05` pubkey, `0x06` sign, `0x07` offchain, `0x08` preview, `0x09` delayed sign, `0x16-0x22` trusted name

### Pure Solana code (libsol)
The Libsol is independent of the SDK features (PKI, NBGL, etc) and contains code purely related to the Solana blockchain. (except `libsol/mock/` for tests).
PRINTF, dynamic allocation, and hashing are available in libsol by mock.

1. `message.c` → parse header/accounts
2. `instruction.c` → identify programs
3. Program parsers → `system_instruction.c`, `spl_token_instruction.c`, etc.
4. `transaction_summary.c` → build UI items

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

### Swap feature

- The SWAP flow is the flow started from the Exchange application instead of the dashboard. It enables some features and blocks others.
- The information coming from Exchange is TRUSTED.
- The application must return to Exchange after the handling of an apdu to sign, whether valid or not. Return is made through the send_swap_error_X() SDK functions in case of error, or through the SDK IO stack once G_swap_response_ready has been set. In both cases, cleaning non-sensitive data is completely useless (dynamic allocator free, apdu managers, etc).

### Dynamic allocation

- Dynamic allocation is allowed but must be used with great care, ensuring the data is always freed after use.
- Splitting a function in an internal one that performs the logic and an external one that calls the internal one and frees is a good pattern to ensure proper freeing of memory.
- The size of the allocated pool can be increased if needed.

### Test pem keys

- You do NOT have the possibility to regenerate the PKI certificates for new keys. As a result NEVER try to generate new .pem files. If a new use cases requires new keys, reuse the existing test keys and their corresponding .pem files for development purposes and flag so in the result summary.

## Code Patterns

Coding patterns described here are more important than uniformity cross applications.

### Logging

- Never assume code is correct on first try, writing logs is mandatory to verify execution flow, `PRINTF` are the only way to trace execution and are meant to be permanent
- Trace logs (no variables): Use `PRINTF("Function entered or choice taken\n")` in key dispatch logic (e.g., APDU handlers, main switch cases)
- Variable logs: Use `PRINTF("variable_name=%d\n", var)` or `PRINTF("buffer=%.*H\n", len, buf)` in calculations and new code
- Log ALL error returns. No `return -1` shall exist without an associated `PRINTF`

### Coding conventions

- bool return is used to indicate the result of a CHECK, NOT a success or failure.
- int return is used to report a success or failure of a function by using -1 or 0.
- Global or module variables are prefixed by `G_*`.
- Never use ternary conditional operator
- Comments are concise and straightforward
- No goto: if a function needs exit cleaning logic, split in inner / outer.
- Functions and variables should have clear explicit names without abbreviation. BAD: `idl_leaf_cb_t cb`, GOOD: `idl_leaf_cb_t leaf_callback`.
- Functions called in a wrong context shall return an error, not ignore or skip
- Do not use shortcut variables to avoid writing long access path.
- Never write functions in header files.
- Do not rely on C implicit struct copy, use a memcpy to highlight deep copy behavior.

### Chain of trust

- The payloads received signed from the CAL (descriptors, trusted names, etc) are trusted in content.

## Critical Files

- `src/main_application.c` - APDU dispatch
- `src/apdu.c` - APDU parsing
- `src/handle_sign_message.c` - Transaction signing
- `src/handle_sign_message_preview.{c,h}` - Delayed signing
- `libsol/message.c` - Core parser
- `libsol/transaction_summary.c` - UI summary
- `doc/api.md` - APDU protocol spec

## Common Issues

- **Clean only when needed** - `qb -c` clears leftover .o files (not required for device switches)
- **Swap context is different than normal Dashboard start and blocks features** - `G_called_from_swap` prevents other features like message preview or blind signing.
- Do not use /tmp as a storage for temporary files, if you want to create temporary files, create them in the project directory and remove them after.

## External projects

Other repositories that are relevant to the development of the Solana Ledger application are available as read-only in the directory ./other_projects
This includes but is not limited to:
- app-ethereum
- ledger-app-workflows
- ledger-secure-sdk
- ragger
