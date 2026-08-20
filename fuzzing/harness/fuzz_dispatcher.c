/* Solana fuzz harness: command table, TLV grammars, APDU serialiser, swap lane.
 * One APDU per iteration through apdu_handle_message(); app state comes from the
 * invariant. The swap library callbacks have no APDU route, so a lane gated on the
 * P1 control byte reaches them. */

#include "mocks.h"

#include "apdu.h"
#include "globals.h"
#include "utils.h"

#include "handle_get_pubkey.h"
#include "handle_sign_message.h"
#include "handle_sign_offchain_message.h"
#include "handle_sign_message_preview.h"
#include "handle_provide_instruction_descriptor.h"
#include "handle_get_challenge.h"
#include "handle_provide_trusted_info.h"
#include "handle_provide_dynamic_descriptor.h"
#include "trusted_info.h"
#include "dynamic_token_info.h"
#include "mem_utils.h"

#include "swap_common.h"
#include "swap_utils.h"
#include "swap_lib_calls.h"
#include "handle_swap_sign_transaction.h"
#include "handle_check_address.h"
#include "handle_get_printable_amount.h"

#include "parser.h"

#include <stdint.h>
#include <string.h>

apdu_command_t G_command;

/* globals.h declares this extern const, so the definition must stay const to
 * link, but both the settings handler (through nvm_write) and the restore path
 * write it. An uninitialized const lands in .rodata, where those writes fault,
 * so pin it to a writable section. */
const internalStorage_t N_storage_real __attribute__((section(".data"))) = {0};

static volatile uint8_t _swap_return_dummy;

/* Own mutator and entry point, so both defaults are opted out here. */
#define FUZZ_APP_CUSTOM_MUTATOR
#define FUZZ_APP_CUSTOM_ENTRY
#include "fuzz_mutator.h"
#include "tlv_mutator.h"

/* Tag grammars from each handler's X-macro list and the SDK lib_tlv use cases. */

/* handle_provide_instruction_descriptor.c */
static const tlv_tag_info_t TAGS_INSTRUCTION_DESCRIPTOR[] = {
    {0x01, 1,  1 },   /* STRUCTURE_TYPE          */
    {0x02, 1,  1 },   /* VERSION                 */
    {0x23, 1,  8 },   /* CHAIN_ID                */
    {0x90, 1,  8 },   /* TEMPLATE_ID             */
    {0x91, 32, 32},   /* PROGRAM_ID              */
    {0x92, 1,  32},   /* DISCRIMINATOR           */
    {0x93, 1,  1 },   /* AMOUNT_SIZE             */
    {0x94, 1,  4 },   /* AMOUNT_OFFSET           */
    {0x95, 1,  1 },   /* AMOUNT_RULES            */
    {0x96, 1,  2 },   /* ASSET_ACCOUNT_INDEX     */
    {0x97, 1,  2 },   /* ASSET_ATA_INDEX         */
    {0x98, 1,  2 },   /* RECIPIENT_ACCOUNT_INDEX */
    {0x99, 1,  2 },   /* RECIPIENT_ATA_INDEX     */
    {0x15, 70, 72},   /* DER_SIGNATURE           */
};

/* lib_tlv/use_cases/tlv_use_case_trusted_name.c */
static const tlv_tag_info_t TAGS_TRUSTED_NAME[] = {
    {0x01, 1,  1 },   /* STRUCTURE_TYPE      */
    {0x02, 1,  1 },   /* VERSION             */
    {0x70, 1,  1 },   /* TRUSTED_NAME_TYPE   */
    {0x71, 1,  1 },   /* TRUSTED_NAME_SOURCE */
    {0x20, 1, 45 },   /* TRUSTED_NAME (base58 pubkey) */
    {0x23, 1,  8 },   /* CHAIN_ID            */
    {0x22, 1, 45 },   /* ADDRESS             */
    {0x72, 1, 32 },   /* NFT_ID              */
    {0x73, 1, 45 },   /* SOURCE_CONTRACT     */
    {0x12, 1,  4 },   /* CHALLENGE           */
    {0x10, 3,  3 },   /* NOT_VALID_AFTER     */
    {0x13, 1,  2 },   /* SIGNER_KEY_ID       */
    {0x14, 1,  2 },   /* SIGNER_ALGORITHM    */
    {0x15, 70, 72},   /* DER_SIGNATURE       */
};

/* lib_tlv/use_cases/tlv_use_case_dynamic_descriptor.c + app TUID sub-TLV */
static const tlv_tag_info_t TAGS_DYNAMIC_DESCRIPTOR[] = {
    {0x01, 1,  1 },   /* STRUCTURE_TYPE    */
    {0x02, 1,  1 },   /* VERSION           */
    {0x03, 1,  4 },   /* COIN_TYPE         */
    {0x04, 1, 30 },   /* APPLICATION_NAME  */
    {0x05, 1, 12 },   /* TICKER            */
    {0x06, 1,  1 },   /* MAGNITUDE         */
    {0x07, 1, 64 },   /* TUID              */
    {0x08, 70, 72},   /* SIGNATURE         */
};

/* Indexed by position in fuzz_commands[]. TLV_CFG comes from tlv_mutator.h. */
static const tlv_fuzz_config_t tlv_configs[] = {
    [0]  = {0},                                  /* InsDeprecatedGetAppConfiguration */
    [1]  = {0},                                  /* InsDeprecatedGetPubkey           */
    [2]  = {0},                                  /* InsDeprecatedSignMessage         */
    [3]  = {0},                                  /* InsGetAppConfiguration           */
    [4]  = {0},                                  /* InsGetPubkey                     */
    [5]  = {0},                                  /* InsSignMessage                   */
    [6]  = {0},                                  /* InsSignOffchainMessage           */
    [7]  = {0},                                  /* InsSignMessagePreview            */
    [8]  = {0},                                  /* InsSignMessageDelayed            */
    [9]  = TLV_CFG(TAGS_INSTRUCTION_DESCRIPTOR), /* InsTrustedInfoProvideInstructionDescriptor */
    [10] = {0},                                  /* InsTrustedInfoGetChallenge       */
    [11] = TLV_CFG(TAGS_TRUSTED_NAME),           /* InsTrustedInfoProvideInfo        */
    [12] = TLV_CFG(TAGS_DYNAMIC_DESCRIPTOR),     /* InsTrustedInfoProvideDynamicDescriptor */
};

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                size_t max_size, unsigned int seed) {
    return fuzz_tlv_dispatch_mutate(data, size, max_size, seed,
                                    tlv_configs,
                                    sizeof(tlv_configs) / sizeof(tlv_configs[0]));
}

#include "fuzz_harness.h"

const fuzz_command_spec_t fuzz_commands[] = {
    {.cla = CLA, .ins = InsDeprecatedGetAppConfiguration},
    {.cla = CLA, .ins = InsDeprecatedGetPubkey, .p1_max = 1, .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA,
     .ins = InsDeprecatedSignMessage,
     .p1_max = 1,
     .p2_max = P2_EXTEND | P2_MORE | P2_IS_ATA_OR_TOKEN_ACCOUNT,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA, .ins = InsGetAppConfiguration},
    {.cla = CLA, .ins = InsGetPubkey, .p1_max = 1, .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA,
     .ins = InsSignMessage,
     .p1_max = 1,
     .p2_max = P2_EXTEND | P2_MORE | P2_IS_ATA_OR_TOKEN_ACCOUNT,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA,
     .ins = InsSignOffchainMessage,
     .p1_max = 1,
     .p2_max = P2_EXTEND | P2_MORE,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA,
     .ins = InsSignMessagePreview,
     .p1_max = 1,
     .p2_max = P2_EXTEND | P2_MORE,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA,
     .ins = InsSignMessageDelayed,
     .p1_max = 1,
     .p2_max = P2_EXTEND | P2_MORE,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA,
     .ins = InsTrustedInfoProvideInstructionDescriptor,
     .p1_max = 1,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA, .ins = InsTrustedInfoGetChallenge},
    {.cla = CLA,
     .ins = InsTrustedInfoProvideInfo,
     .p1_max = 1,
     .p2_max = P2_EXTEND | P2_MORE,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA,
     .ins = InsTrustedInfoProvideDynamicDescriptor,
     .p1_max = 1,
     .p2_max = P2_EXTEND | P2_MORE,
     .flags = FUZZ_CMD_HAS_DATA},
};

FUZZ_COMMAND_COUNT();

/* ── Per-iteration state reset ───────────────────────────────────────── */

/* Surgical reset following the Ethereum model: zero G_command so
 * apdu_handle_message repopulates it from the raw APDU bytes, but
 * preserve Absolution-restored state gates (preview, trusted info,
 * descriptors, swap flags, N_storage).  Fix up pointer fields that
 * Absolution would fill with garbage. */

void fuzz_app_reset(void) {
    G_swap_signing_return_value_address = &_swap_return_dummy;

    /* Absolution restores these as 8-byte pointers, which cannot name a heap block,
     * so start them from NULL rather than an arbitrary value: mem_free() reads a
     * pointer as a chunk header before it can reject it. */
    G_preview_state = NULL;
    g_trusted_info = NULL;
    g_dynamic_token_info = NULL;

    /* main_application.c owns this on device and is excluded from the fuzz build.
     * Without it every APP_MEM_CALLOC fails, so the handlers behind the
     * heap-allocated globals never run. Re-initialising per iteration also reclaims
     * the previous one's blocks, which the NULLs above have just orphaned. */
    app_mem_init();

    /* Now the pool exists, hand the heap-held state its restored contents. Must
     * follow app_mem_init(), which reclaims the previous iteration's blocks. */
    fuzz_install_restored_state();

    /* G_command is deliberately NOT cleared here. It is the APDU state machine, and
     * the prefix restores it so a command lands mid-flow -- clearing it would undo
     * exactly the state Absolution just installed. message_text_start, the one
     * pointer field, is pinned to NULL by invariants/domain-overrides.txt. */
}

/* ── Raw-APDU serialiser ─────────────────────────────────────────────── */

extern uint8_t G_io_apdu_buffer[];

static int serialise_apdu(const command_t *c, uint8_t *out, size_t *out_len) {
    bool deprecated = (c->ins == InsDeprecatedGetAppConfiguration ||
                       c->ins == InsDeprecatedGetPubkey ||
                       c->ins == InsDeprecatedSignMessage);
    size_t hdr = OFFSET_CDATA;
    if (deprecated) {
        hdr = DEPRECATED_OFFSET_CDATA;
    }

    size_t data_len = c->lc;
    if (!deprecated && data_len > 255) {
        data_len = 255;
    } else if (deprecated && data_len > (UINT16_MAX - hdr)) {
        data_len = UINT16_MAX - hdr;
    }

    if (hdr + data_len > IO_APDU_BUFFER_SIZE) {
        return -1;
    }

    out[OFFSET_CLA] = c->cla;
    out[OFFSET_INS] = c->ins;
    out[OFFSET_P1] = c->p1;
    out[OFFSET_P2] = c->p2;
    if (deprecated) {
        out[OFFSET_LC] = (uint8_t) (data_len >> 8);
        out[OFFSET_LC + 1] = (uint8_t) (data_len & 0xFF);
    } else {
        out[OFFSET_LC] = (uint8_t) data_len;
    }

    if (data_len > 0 && c->data != NULL) {
        memcpy(out + hdr, c->data, data_len);
    }

    *out_len = hdr + data_len;
    return 0;
}

/* ── Single-APDU dispatch ────────────────────────────────────────────── */

void fuzz_app_dispatch(void *cmd) {
    command_t *c = (command_t *) cmd;
    size_t apdu_len = 0;
    if (serialise_apdu(c, G_io_apdu_buffer, &apdu_len) != 0) {
        return;
    }

    const int ret = apdu_handle_message(G_io_apdu_buffer, apdu_len, &G_command);
    if (ret != 0) {
        memset(&G_command, 0, sizeof(G_command));
        return;
    }

    if (G_command.state == ApduStatePayloadInProgress) {
        return;
    }

    if (G_command.instruction != InsSignMessageDelayed) {
        clear_preview_state();
    }

    switch (G_command.instruction) {
        case InsDeprecatedGetAppConfiguration:
        case InsGetAppConfiguration:
            G_io_apdu_buffer[0] = N_storage.settings.allow_blind_sign;
            G_io_apdu_buffer[1] = N_storage.settings.pubkey_display;
            break;

        case InsDeprecatedGetPubkey:
        case InsGetPubkey:
            handle_get_pubkey();
            break;

        case InsDeprecatedSignMessage:
        case InsSignMessage:
            handle_sign_message_parse_message();
            break;

        case InsSignMessagePreview:
            if (!G_called_from_swap) {
                G_command.is_preview_mode = true;
                handle_sign_message_parse_message();
            }
            break;

        case InsSignMessageDelayed:
            handle_sign_message_delayed();
            break;

        case InsSignOffchainMessage:
            handle_sign_offchain_message();
            break;

        case InsTrustedInfoProvideInstructionDescriptor:
            handle_provide_instruction_descriptor();
            break;

        case InsTrustedInfoGetChallenge:
            handle_get_challenge();
            break;

        case InsTrustedInfoProvideInfo:
            handle_provide_trusted_info();
            break;

        case InsTrustedInfoProvideDynamicDescriptor:
            handle_provide_dynamic_descriptor();
            break;

        default:
            break;
    }
}

/* ── Swap library callback lane ──────────────────────────────────────── */

#define SWAP_MODE_THRESHOLD 224

#define SWAP_SCRATCH_ADDR_STR   BASE58_PUBKEY_LENGTH
/* destination_address_extra_id carries no length field: swap_copy_transaction_parameters()
 * reads type/template_id/tx_hash by fixed offset and documents the minimum Exchange
 * guarantees. Undersizing this buffer overflows the app's read, not the app's fault. */
#define SWAP_SCRATCH_EXTRA_ID   EXTRA_ID_SOLANA_TEMPLATE_MIN_SIZE
#define SWAP_SCRATCH_AMOUNT     16
#define SWAP_SCRATCH_COIN_CFG   256

/* Clamp a fuzzer-supplied length to a scratch buffer. */
static size_t min_size(size_t a, size_t b) {
    if (a < b) {
        return a;
    }
    return b;
}

/* Bytes left in the payload after offset, saturating at zero. */
static size_t bytes_after(size_t total, size_t offset) {
    if (total > offset) {
        return total - offset;
    }
    return 0;
}

static void fuzz_swap_callbacks(const uint8_t *tail, size_t tail_len) {
    if (tail_len < 2) {
        return;
    }

    uint8_t sub_mode = tail[0] % 3;
    const uint8_t *payload = tail + 1;
    size_t plen = tail_len - 1;

    switch (sub_mode) {
        case 0: {
            char address_to_check[SWAP_SCRATCH_ADDR_STR];
            memset(address_to_check, 0, sizeof(address_to_check));
            size_t copy = min_size(plen, sizeof(address_to_check) - 1);
            memcpy(address_to_check, payload, copy);

            uint8_t path_blob[1 + 4 * MAX_BIP32_PATH_LENGTH];
            memset(path_blob, 0, sizeof(path_blob));
            size_t path_copy = min_size(plen, sizeof(path_blob));
            memcpy(path_blob, payload, path_copy);

            char extra_id[SWAP_SCRATCH_EXTRA_ID];
            memset(extra_id, 0, sizeof(extra_id));

            check_address_parameters_t params;
            memset(&params, 0, sizeof(params));
            params.address_parameters = path_blob;
            params.address_parameters_length = (uint8_t) path_copy;
            params.address_to_check = address_to_check;
            params.extra_id_to_check = extra_id;
            swap_handle_check_address(&params);
            break;
        }
        case 1: {
            uint8_t amount[SWAP_SCRATCH_AMOUNT];
            memset(amount, 0, sizeof(amount));
            size_t copy = min_size(plen, sizeof(amount));
            memcpy(amount, payload, copy);

            get_printable_amount_parameters_t params;
            memset(&params, 0, sizeof(params));
            params.amount = amount;
            params.amount_length = (uint8_t) copy;
            params.is_fee = false;
            if (plen > sizeof(amount)) {
                params.is_fee = (payload[sizeof(amount)] & 1) != 0;
            }
            swap_handle_get_printable_amount(&params);
            break;
        }
        case 2: {
            char dest_addr[SWAP_SCRATCH_ADDR_STR];
            memset(dest_addr, 0, sizeof(dest_addr));
            size_t copy = min_size(plen, sizeof(dest_addr) - 1);
            memcpy(dest_addr, payload, copy);

            uint8_t amount_buf[SWAP_SCRATCH_AMOUNT];
            memset(amount_buf, 0, sizeof(amount_buf));
            size_t a_copy = min_size(plen, sizeof(amount_buf));
            memcpy(amount_buf, payload, a_copy);

            uint8_t fee_buf[SWAP_SCRATCH_AMOUNT];
            memset(fee_buf, 0, sizeof(fee_buf));
            size_t f_off = 16;
            size_t f_avail = bytes_after(plen, f_off);
            size_t f_copy = min_size(f_avail, sizeof(fee_buf));
            memcpy(fee_buf, payload + f_off, f_copy);

            uint8_t coin_cfg[SWAP_SCRATCH_COIN_CFG];
            memset(coin_cfg, 0, sizeof(coin_cfg));
            size_t c_off = 48;
            size_t c_avail = bytes_after(plen, c_off);
            size_t c_copy = min_size(c_avail, 255);
            memcpy(coin_cfg, payload + c_off, c_copy);

            char extra_id[SWAP_SCRATCH_EXTRA_ID];
            memset(extra_id, 0, sizeof(extra_id));
            size_t e_off = 64;
            size_t e_avail = bytes_after(plen, e_off);
            size_t e_copy = min_size(e_avail, sizeof(extra_id));
            memcpy(extra_id, payload + e_off, e_copy);

            create_transaction_parameters_t params;
            memset(&params, 0, sizeof(params));
            params.destination_address = dest_addr;
            params.amount = amount_buf;
            params.amount_length = (uint8_t) a_copy;
            params.fee_amount = fee_buf;
            params.fee_amount_length = (uint8_t) f_copy;
            params.coin_configuration = coin_cfg;
            params.coin_configuration_length = (uint8_t) c_copy;
            params.destination_address_extra_id = extra_id;
            swap_copy_transaction_parameters(&params);
            break;
        }
    }
}

/* ── Fuzz entry ──────────────────────────────────────────────────────── */

int fuzz_entry(const uint8_t *data, size_t size) {
    G_swap_signing_return_value_address = &_swap_return_dummy;

    if (size >= 4 && data[2] >= SWAP_MODE_THRESHOLD) {
        if (sigsetjmp(fuzz_exit_jump_ctx.jmp_buf, 1)) {
            return 0;
        }
        fuzz_swap_callbacks(data, size);
        return 0;
    }

    return fuzz_harness_entry(data, size);
}
