#include "apdu.h"
#include "mocks.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "lib_standard_app/crypto_helpers.h"
#include "cx.h"
#include "ledger_pki.h"

/* After cx.h: handle_sign_message_preview.h uses CX_SHA512_SIZE without
 * including what defines it. */
#include "app_mem_utils.h"
#include "handle_sign_message_preview.h"
#include "dynamic_token_info.h"

/* swap_copy_transaction_parameters() calls this explicitly when accepting a
 * cross-app Exchange swap.  Zeroing BSS in a fuzz build would wipe the
 * Absolution prefix and break state restoration, so it is a no-op here. */
void os_explicit_zero_BSS_segment(void) {
}

/* app_main() from src/main_application.c is excluded from the fuzz build so
 * the harness can drive APDU dispatch directly.  A weak stub keeps anything
 * that references it (e.g. swap_lib_calls.c) linkable. */
void app_main(void) {
}

/* ────────────────────────── UI entry-point stubs ─────────────────────────────
 * The real NBGL screens in src/ui/ are excluded from the fuzz build:
 *   1. Their callbacks exercise no exploitable logic (pure rendering).
 *   2. Static file-scope globals in those files are shrunk by clang's
 *      GlobalOpt pass (static uint32_t → uint8_t when only enum values are
 *      ever assigned), which collides with Absolution's AST-derived size
 *      and yields spurious ASan global-buffer-overflows in sample_invariant.
 * Replacing each UI entry with a no-op keeps the handler flow intact while
 * still letting the harness drive review_choice / reject logic through the
 * NBGL mocks installed by the SDK fuzzer skeleton.
 */
void ui_idle(void) {
}

void ui_settings(void) {
}

void ui_get_public_key(void) {
}

void start_blind_sign_error_ui(void) {
}

void start_sign_message_ui(size_t num_summary_steps) {
    (void) num_summary_steps;
}

void start_blind_sign_tx_ui(size_t num_summary_steps) {
    (void) num_summary_steps;
}

void start_sign_offchain_message_ui(bool is_ascii, size_t num_summary_steps) {
    (void) is_ascii;
    (void) num_summary_steps;
}

void ui_transaction_modal(bool is_success) {
    (void) is_success;
}

/* The opt-in branch replies asynchronously from the UI callback, so the handler
 * returns 0 either way; which branch runs is N_storage's, hence Absolution's. */
void ui_transaction_check_opt_in(bool response_expected) {
    (void) response_expected;
}

/* The real check compares a tail-derived pubkey against a prefix-restored one
 * through SHA-256 PDA derivation, which no mutation aligns. Returning true opens
 * the SPL transfer printing pipeline and the swap validation behind it; the
 * derivation itself is covered by unit tests. */
bool check_ata_against_trusted_info(const uint8_t src_account[32],
                                    const uint8_t mint_account[32],
                                    const uint8_t dest_account[32],
                                    bool is_token_2022) {
    (void) src_account;
    (void) mint_account;
    (void) dest_account;
    (void) is_token_2022;
    return true;
}

/* Bypasses the ATA derivation check only; the NULL and received guards match
 * src/trusted_info.c, since g_trusted_info is heap-allocated and freed on reset. */
#include "trusted_info.h"
int get_transfer_to_address(const char **to_address) {
    if (g_trusted_info == NULL || !g_trusted_info->received) {
        return -1;
    }
    *to_address = g_trusted_info->encoded_owner_address;
    return 0;
}

/* The SDK crypto mock pins the curve to CX_CURVE_256K1, so Solana's
 * CX_CURVE_Ed25519 is rejected with CX_INVALID_PARAMETER and every non-UI handler
 * returns before the parsers run. Overriding the one symbol get_public_key() calls
 * returns a deterministic key instead.
 *
 * utils.c reverses raw_pubkey[64..33], so the app sees 0xBB repeated 32 times, and
 * raw_pubkey[32] = 0xAA is even so no parity bit flips. Any seed generator matching
 * a signer must use that value, or scan_header_for_signer() finds none. */
WARN_UNUSED_RESULT cx_err_t bip32_derive_with_seed_get_pubkey_256(
    unsigned int    derivation_mode __attribute__((unused)),
    cx_curve_t      curve __attribute__((unused)),
    const uint32_t *path __attribute__((unused)),
    size_t          path_len __attribute__((unused)),
    uint8_t         raw_pubkey[static 65],
    uint8_t        *chain_code,
    cx_md_t         hashID __attribute__((unused)),
    unsigned char  *seed __attribute__((unused)),
    size_t          seed_len __attribute__((unused)))
{
    raw_pubkey[0] = 0x04;
    memset(&raw_pubkey[1], 0xAA, 32);
    memset(&raw_pubkey[33], 0xBB, 32);
    if (chain_code != NULL) {
        memset(chain_code, 0, 32);
    }
    return CX_OK;
}

/* Same curve mismatch on the Ed25519 signing path used by the swap flow. */
WARN_UNUSED_RESULT cx_err_t bip32_derive_with_seed_eddsa_sign_hash_256(
    unsigned int    derivation_mode __attribute__((unused)),
    cx_curve_t      curve __attribute__((unused)),
    const uint32_t *path __attribute__((unused)),
    size_t          path_len __attribute__((unused)),
    cx_md_t         hashID __attribute__((unused)),
    const uint8_t  *hash __attribute__((unused)),
    size_t          hash_len __attribute__((unused)),
    uint8_t        *sig,
    size_t         *sig_len,
    unsigned char  *seed __attribute__((unused)),
    size_t          seed_len __attribute__((unused)))
{
    if (sig_len == NULL) {
        return CX_INVALID_PARAMETER;
    }
    if (sig != NULL) {
        memset(sig, 0x5A, 64);
    }
    *sig_len = 64;
    return CX_OK;
}

/* apdu.c wipes apdu_command_t on every fresh command, discarding the state the
 * prefix just installed. Skipping that one object keeps the prefix driving
 * message[] and message_length, a state a host reaches by sending the same bytes
 * with P2_MORE. Scoped to &G_command: every other caller still gets the real
 * zeroing, whose volatile barrier keeps MSan from reporting cleared buffers. */
void *__wrap_explicit_bzero(void *dst, size_t len) {
    if (dst == (void *) &G_command) {
        return dst;
    }
    if (dst != NULL && len != 0) {
        for (size_t i = 0; i < len; i++) {
            ((volatile unsigned char *) dst)[i] = 0;
        }
    }
    __asm__ volatile("" ::: "memory");
    return dst;
}

/* g_trusted_info, g_dynamic_token_info and G_preview_state are heap pointers, so
 * Absolution restores the pointer and never the block behind it. These value
 * globals are restored instead, and the harness performs the allocation the app
 * performs and copies bytes it did not choose. Allocation uses the real pool so
 * APP_MEM_FREE_AND_NULL still works. fuzz_state_present is restored too, so
 * "nothing received yet" stays reachable. */
trusted_info_t       fuzz_backing_trusted_info;
dynamic_token_info_t fuzz_backing_dynamic_token;
preview_state_t      fuzz_backing_preview;
internalStorage_t    fuzz_backing_nvram;
uint8_t              fuzz_state_present;
fuzz_msg_t           fuzz_backing_msg;

void fuzz_install_restored_state(void) {
    if ((fuzz_state_present & 0x01) != 0) {
        if (APP_MEM_CALLOC((void **) &g_trusted_info, sizeof(trusted_info_t))) {
            memcpy(g_trusted_info, &fuzz_backing_trusted_info, sizeof(trusted_info_t));
        }
    }
    if ((fuzz_state_present & 0x02) != 0) {
        if (APP_MEM_CALLOC((void **) &g_dynamic_token_info, sizeof(dynamic_token_info_t))) {
            memcpy(g_dynamic_token_info, &fuzz_backing_dynamic_token, sizeof(dynamic_token_info_t));
        }
    }
    if ((fuzz_state_present & 0x04) != 0) {
        if (APP_MEM_CALLOC((void **) &G_preview_state, sizeof(preview_state_t))) {
            memcpy(G_preview_state, &fuzz_backing_preview, sizeof(preview_state_t));
        }
    }
    /* Settings live in NVRAM, which the app writes through nvm_write(). Absolution
     * skips N_storage_real because it is const, so the restored copy comes from
     * here instead. The harness pins the object to a writable section; without
     * that it lands in .rodata and this write faults. */
    memcpy((void *) &N_storage, &fuzz_backing_nvram, sizeof(internalStorage_t));

    /* The restored message. Copied whole; G_command.message_length is restored
     * separately and deliberately not derived from this size, so the app's view of
     * the length can be longer or shorter than what is actually here. */
    memcpy(G_command.message, &fuzz_backing_msg, sizeof(fuzz_msg_t));
}
