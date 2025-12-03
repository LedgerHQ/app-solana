#include <os.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "globals.h"
#include "utils.h"
#include "handle_get_challenge.h"
#include "base58.h"
#include "trusted_info.h"
#include "tlv_use_case_trusted_name.h"

#include "sol/printer.h"

#include "macros.h"
#include "io_utils.h"
#include "os_pki.h"
#include "ledger_pki.h"
#include "handle_swap_sign_transaction.h"
#include "dynamic_token_info.h"
#include "instruction.h"
#include "ed25519_helpers.h"

#include "handle_provide_instruction_descriptor.h"

#define LIFI_SOLANA_MAIN_NET 900
#define LIFI_SOLANA_TEST_NET 901

// https://ledgerhq.atlassian.net/wiki/spaces/TA/pages/5764022544/ARCH+Solana+LiFi+swap+support

#define MAX_DISCRIMINATOR_NUMBER 10

#define TYPE_SOLANA_SWAP_TEMPLATE     0x0a
#define AMOUNT_RULES_ENDIANESS_MASK   (1 << 0)
#define AMOUNT_RULES_OFFSET_TYPE_MASK (1 << 1)

typedef struct saved_descriptors_s {
    uint8_t saved_count;
    uint8_t read_count;
    bool is_main_net;
    uint64_t template_id;
    instruction_descriptor_t descriptors[MAX_DISCRIMINATOR_NUMBER];
} saved_descriptors_t;

static saved_descriptors_t G_saved_descriptors;

void reset_saved_descriptors(void) {
    explicit_bzero(&G_saved_descriptors, sizeof(G_saved_descriptors));
}

uint8_t get_descriptor_count(void) {
    return G_saved_descriptors.saved_count;
}

int get_next_descriptor(const instruction_descriptor_t **instruction_descriptor) {
    if (G_saved_descriptors.read_count >= G_saved_descriptors.saved_count) {
        return -1;
    }
    PRINTF("Reading descriptor n %d\n", G_saved_descriptors.read_count);

    *instruction_descriptor = &G_saved_descriptors.descriptors[G_saved_descriptors.read_count];
    G_saved_descriptors.read_count++;
    return 0;
}

bool instruction_descriptor_received(void) {
    return (get_descriptor_count() != 0);
}

static bool save_instruction_descriptor(saved_descriptors_t *saved_descriptors,
                                        bool is_main_net,
                                        uint64_t template_id,
                                        const instruction_descriptor_t *instruction_descriptor) {
    PRINTF("Attempting to save descriptor n %d\n", saved_descriptors->saved_count + 1);
    if (saved_descriptors->saved_count >= MAX_DISCRIMINATOR_NUMBER) {
        PRINTF("Error, saved_descriptors is full\n");
        return false;
    }

    if (saved_descriptors->saved_count == 0) {
        saved_descriptors->is_main_net = is_main_net;
        saved_descriptors->template_id = template_id;
    } else {
        if (is_main_net != saved_descriptors->is_main_net) {
            PRINTF("Error, is_main_net differs %d != %d\n",
                   is_main_net,
                   saved_descriptors->is_main_net);
            return false;
        }

        if (template_id != saved_descriptors->template_id) {
            PRINTF("Error, template_id differs\n");
            debug_print_u64("template_id", template_id);
            debug_print_u64("saved_descriptors->template_id", saved_descriptors->template_id);
            return false;
        }
    }

    PRINTF("Saving descriptor in slot n %d\n", saved_descriptors->saved_count);
    memcpy(&(saved_descriptors->descriptors[saved_descriptors->saved_count]),
           instruction_descriptor,
           sizeof(instruction_descriptor_t));
    ++saved_descriptors->saved_count;
    return true;
}

typedef struct tlv_out_s {
    TLV_reception_t received_tags;

    uint8_t structure_type;
    uint8_t version;

    bool is_main_net;
    uint64_t template_id;

    instruction_descriptor_t ins;

    // Progressive hash of the received TLVs (except the signature type)
    cx_sha256_t hash_ctx;
    buffer_t signature;
} tlv_out_t;

static bool handle_structure_type(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->structure_type);
}

static bool handle_version(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->version);
}

static bool handle_chain_id(const tlv_data_t *data, tlv_out_t *out) {
    uint32_t chain_id;
    if (!get_uint32_t_from_tlv_data(data, &chain_id)) {
        return false;
    }
    if (chain_id != LIFI_SOLANA_MAIN_NET && chain_id != LIFI_SOLANA_TEST_NET) {
        return false;
    }
    out->is_main_net = (chain_id == LIFI_SOLANA_MAIN_NET);
    return true;
}

static bool handle_template_id(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint64_t_from_tlv_data(data, &out->template_id);
}

static bool handle_program_id(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, PROGRAM_ADDRESS_SIZE, PROGRAM_ADDRESS_SIZE)) {
        return false;
    }
    memcpy(out->ins.program_id, temp.ptr, sizeof(out->ins.program_id));
    return true;
}

static bool handle_discriminator(const tlv_data_t *data, tlv_out_t *out) {
    buffer_t temp;
    if (!get_buffer_from_tlv_data(data, &temp, 0, MAX_DISCRIMINATOR_SIZE)) {
        return false;
    }
    out->ins.discriminator_size = temp.size;
    if (out->ins.discriminator_size != 0) {
        memcpy(out->ins.discriminator, temp.ptr, out->ins.discriminator_size);
    }
    return true;
}

static bool handle_amount_size(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->ins.amount_size);
}

static bool handle_amount_offset(const tlv_data_t *data, tlv_out_t *out) {
    return get_uint8_t_from_tlv_data(data, &out->ins.amount_offset);
}

static bool handle_amount_rules(const tlv_data_t *data, tlv_out_t *out) {
    uint8_t amount_rules;
    if (!get_uint8_t_from_tlv_data(data, &amount_rules)) {
        return false;
    }
    out->ins.amount_rules_big_endian = HAS_MASK(amount_rules, AMOUNT_RULES_ENDIANESS_MASK);
    out->ins.amount_rules_negative_offset = HAS_MASK(amount_rules, AMOUNT_RULES_OFFSET_TYPE_MASK);
    return true;
}

static bool handle_asset_account_index(const tlv_data_t *data, tlv_out_t *out) {
    out->ins.asset_account_index_received = true;
    return get_uint8_t_from_tlv_data(data, &out->ins.asset_account_index);
}

static bool handle_asset_ata_index(const tlv_data_t *data, tlv_out_t *out) {
    out->ins.asset_ata_index_received = true;
    return get_uint8_t_from_tlv_data(data, &out->ins.asset_ata_index);
}

static bool handle_recipient_account_index(const tlv_data_t *data, tlv_out_t *out) {
    out->ins.recipient_account_index_received = true;
    return get_uint8_t_from_tlv_data(data, &out->ins.recipient_account_index);
}

static bool handle_recipient_ata_index(const tlv_data_t *data, tlv_out_t *out) {
    out->ins.recipient_ata_index_received = true;
    return get_uint8_t_from_tlv_data(data, &out->ins.recipient_ata_index);
}

static bool handle_signature(const tlv_data_t *data, tlv_out_t *out) {
    return get_buffer_from_tlv_data(data,
                                    &out->signature,
                                    DER_SIGNATURE_MIN_SIZE,
                                    DER_SIGNATURE_MAX_SIZE);
}

static bool handle_common(const tlv_data_t *data, tlv_out_t *out);

// clang-format off
#define INSTRUCTION_DESCRIPTOR_TLV_TAGS(X)                                               \
X(0x01, TAG_STRUCTURE_TYPE,          handle_structure_type,          ENFORCE_UNIQUE_TAG) \
X(0x02, TAG_VERSION,                 handle_version,                 ENFORCE_UNIQUE_TAG) \
X(0x23, TAG_CHAIN_ID,                handle_chain_id,                ENFORCE_UNIQUE_TAG) \
X(0x90, TAG_TEMPLATE_ID,             handle_template_id,             ENFORCE_UNIQUE_TAG) \
X(0x91, TAG_PROGRAM_ID,              handle_program_id,              ENFORCE_UNIQUE_TAG) \
X(0x92, TAG_DISCRIMINATOR,           handle_discriminator,           ENFORCE_UNIQUE_TAG) \
X(0x93, TAG_AMOUNT_SIZE,             handle_amount_size,             ENFORCE_UNIQUE_TAG) \
X(0x94, TAG_AMOUNT_OFFSET,           handle_amount_offset,           ENFORCE_UNIQUE_TAG) \
X(0x95, TAG_AMOUNT_RULES,            handle_amount_rules,            ENFORCE_UNIQUE_TAG) \
X(0x96, TAG_ASSET_ACCOUNT_INDEX,     handle_asset_account_index,     ENFORCE_UNIQUE_TAG) \
X(0x97, TAG_ASSET_ATA_INDEX,         handle_asset_ata_index,         ENFORCE_UNIQUE_TAG) \
X(0x98, TAG_RECIPIENT_ACCOUNT_INDEX, handle_recipient_account_index, ENFORCE_UNIQUE_TAG) \
X(0x99, TAG_RECIPIENT_ATA_INDEX,     handle_recipient_ata_index,     ENFORCE_UNIQUE_TAG) \
X(0x15, TAG_DER_SIGNATURE,           handle_signature,               ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(INSTRUCTION_DESCRIPTOR_TLV_TAGS, &handle_common, parse_instruction_descriptor)

static bool handle_common(const tlv_data_t *data, tlv_out_t *out) {
    if (data->tag != TAG_DER_SIGNATURE) {
        CX_ASSERT(cx_hash_update((cx_hash_t *) &out->hash_ctx, data->raw.ptr, data->raw.size));
    }
    return true;
}

// Wrapper around handle_provide_trusted_info_internal to handle the challenge reroll
static int handle_provide_instruction_descriptor_internal(void) {
    // explicit_bzero(&g_dynamic_token_info, sizeof(g_dynamic_token_info));

    tlv_out_t tlv_extracted = {0};
    cx_sha256_init(&tlv_extracted.hash_ctx);

    // Convert G_command to buffer_t format. 0 copy
    buffer_t payload = {.ptr = G_command.message, .size = G_command.message_length};

    if (!parse_instruction_descriptor(&payload, &tlv_extracted, &tlv_extracted.received_tags)) {
        PRINTF("parse_instruction_descriptor failed\n");
        return ApduReplySolanaInvalidInstructionDescriptor;
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags, TAG_STRUCTURE_TYPE)) {
        PRINTF("Error: no struct type specified!\n");
        return ApduReplySolanaInvalidInstructionDescriptor;
    }

    if (tlv_extracted.structure_type != TYPE_SOLANA_SWAP_TEMPLATE) {
        PRINTF("Error: unexpected struct type %d\n", tlv_extracted.structure_type);
        return ApduReplySolanaInvalidInstructionDescriptor;
    }

    if (!TLV_CHECK_RECEIVED_TAGS(tlv_extracted.received_tags,
                                 TAG_VERSION,
                                 TAG_CHAIN_ID,
                                 TAG_TEMPLATE_ID,
                                 TAG_PROGRAM_ID,
                                 TAG_DISCRIMINATOR,
                                 TAG_DER_SIGNATURE)) {
        PRINTF("Error: missing required fields in struct version 1\n");
        return ApduReplySolanaInvalidInstructionDescriptor;
    }

    if (tlv_extracted.version == 0 || tlv_extracted.version > 1) {
        PRINTF("Error: unsupported struct version %d\n", tlv_extracted.version);
        return ApduReplySolanaInvalidInstructionDescriptor;
    }

    // Finalize hash object filled by the parser
    uint8_t tlv_hash[CX_SHA256_SIZE] = {0};
    CX_ASSERT(cx_hash_final((cx_hash_t *) &tlv_extracted.hash_ctx, tlv_hash));
    buffer_t hash = {.ptr = tlv_hash, .size = sizeof(tlv_hash)};

    // Verify that the signature field of the TLV is the signature of the TLV hash by the key
    // loaded by the PKI
    check_signature_with_pki_status_t err;
    uint8_t expected_key_usage = CERTIFICATE_PUBLIC_KEY_USAGE_SWAP_TEMPLATE;
    cx_curve_t curve = CX_CURVE_SECP256K1;
    err = check_signature_with_pki(hash, &expected_key_usage, &curve, tlv_extracted.signature);
    if (err != CHECK_SIGNATURE_WITH_PKI_SUCCESS) {
        PRINTF("Failed to verify signature of instruction descriptor\n");
        return ApduReplySolanaInvalidInstructionDescriptor;
    }

    PRINTF("is_main_net = 0x%08X\n", tlv_extracted.is_main_net);
    debug_print_u64("tlv_extracted.template_id", tlv_extracted.template_id);

    PRINTF("program_id = 0x%.*H\n",
           sizeof(tlv_extracted.ins.program_id),
           tlv_extracted.ins.program_id);
    PRINTF("discriminator = 0x%.*H\n",
           tlv_extracted.ins.discriminator_size,
           tlv_extracted.ins.discriminator);
    PRINTF("amount_size = %u\n", tlv_extracted.ins.amount_size);
    PRINTF("amount_offset = %u\n", tlv_extracted.ins.amount_offset);
    PRINTF("amount_rules_big_endian = %u\n", tlv_extracted.ins.amount_rules_big_endian);
    PRINTF("amount_rules_negative_offset = %u\n", tlv_extracted.ins.amount_rules_negative_offset);
    PRINTF("asset_account_index = %u\n", tlv_extracted.ins.asset_account_index);
    PRINTF("asset_ata_index = %u\n", tlv_extracted.ins.asset_ata_index);
    PRINTF("recipient_account_index = %u\n", tlv_extracted.ins.recipient_account_index);
    PRINTF("recipient_ata_index = %u\n", tlv_extracted.ins.recipient_ata_index);

    // Store descriptor
    if (!save_instruction_descriptor(&G_saved_descriptors,
                                     tlv_extracted.is_main_net,
                                     tlv_extracted.template_id,
                                     &tlv_extracted.ins)) {
        PRINTF("save_instruction_descriptor error\n");
        return ApduReplySolanaInvalidInstructionDescriptor;
    }

    return ApduReplySuccess;
}

void handle_provide_instruction_descriptor(void) {
    if (!G_called_from_swap) {
        PRINTF("Error: instruction descriptors are only allowed in swap context\n");
        THROW(ApduReplySolanaInvalidInstructionDescriptor);
    }

    int ret = handle_provide_instruction_descriptor_internal();
    if (ret == ApduReplySuccess) {
        THROW(ret);
    } else {
        PRINTF("Error handling instruction descriptor. Force early return to Exchange\n");
        G_swap_response_ready = true;
        sendResponse(0, ret, false);
    }
}

int read_amount_using_descriptor(const Instruction *instruction,
                                 const instruction_descriptor_t *instruction_descriptor,
                                 uint64_t *amount_value) {
    // First we get the offset of the amount
    uint32_t offset;
    if (instruction_descriptor->amount_rules_negative_offset) {
        if (instruction_descriptor->amount_offset > instruction->data_length) {
            PRINTF("Negative offset %d exceeds data length %d\n",
                   instruction_descriptor->amount_offset,
                   instruction->data_length);
            return -1;
        }
        PRINTF("instruction->data_length = %d\n", instruction->data_length);
        PRINTF("instruction_descriptor->amount_offset = %d\n",
               instruction_descriptor->amount_offset);
        offset = instruction->data_length - instruction_descriptor->amount_offset;
    } else {
        offset = instruction_descriptor->amount_offset;
    }

    if (offset + instruction_descriptor->amount_size > instruction->data_length) {
        PRINTF("Instruction data length %d too small to contain %d bytes of amount at offset %d\n",
               instruction->data_length,
               instruction_descriptor->amount_size,
               offset);
        return -1;
    }

    PRINTF("Reading %d bytes of amount at offset %d\n",
           instruction_descriptor->amount_size,
           offset);

    // Depending on whether we received a little or big endian format, reverse or not the amount
    const uint8_t *amount = &instruction->data[offset];
    uint8_t tmp_amount[8];  // up to uint64_t
    const uint8_t *amount_be = NULL;

    if (instruction_descriptor->amount_size > sizeof(tmp_amount)) {
        PRINTF("Amount size %d exceeds uint64_t capacity\n", instruction_descriptor->amount_size);
        return -1;
    }

    if (instruction_descriptor->amount_rules_big_endian) {
        amount_be = amount;
    } else {
        for (uint8_t i = 0; i < instruction_descriptor->amount_size; i++) {
            tmp_amount[i] = amount[instruction_descriptor->amount_size - 1 - i];
        }
        amount_be = tmp_amount;
        PRINTF("Converted amount from little-endian to big-endian\n");
    }

    // Convert big-endian byte array to uint64_t
    *amount_value = 0;
    for (uint8_t i = 0; i < instruction_descriptor->amount_size; i++) {
        *amount_value = (*amount_value << 8) | amount_be[i];
    }
    return 0;
}

int validate_instruction_using_descriptor(const MessageHeader *header,
                                          const Instruction *instruction) {
    // Retrieve / calculate the swap validated mint address and recipient address
    // With the current architecture we actually do this step at each instruction but the impact is
    // negligeable
    bool is_token_2022_kind;
    const uint8_t *validated_mint_address = get_token_mint_address(get_swap_ticker(),
                                                                   &is_token_2022_kind);
    if (validated_mint_address == NULL) {
        PRINTF("Error: no mint address retrieved\n");
        return -1;
    }
    uint8_t validated_recipient_address[PUBKEY_SIZE] = {0};
    if (get_swap_recipient(validated_recipient_address) != 0) {
        PRINTF("Error: no recipient address retrieved\n");
        return -1;
    }

    // Get descriptor for this instruction
    const instruction_descriptor_t *instruction_descriptor;
    if (get_next_descriptor(&instruction_descriptor) != 0) {
        PRINTF("Error in get_next_descriptor\n");
        return -1;
    }

    // CHECK PROGRAM ID
    const Pubkey *program_id = &header->pubkeys[instruction->program_id_index];
    PRINTF("program_id = %.*H\n", PUBKEY_SIZE, program_id);
    if (memcmp(program_id, instruction_descriptor->program_id, PUBKEY_SIZE) != 0) {
        PRINTF("Received program_id %.*H != expected program_id %.*H\n",
               PUBKEY_SIZE,
               program_id,
               PUBKEY_SIZE,
               instruction_descriptor->program_id);
        return -1;
    }
    PRINTF("Validated program_id '%.*H'\n", PUBKEY_SIZE, program_id);

    // CHECK DISCRIMINATOR
    if (instruction_descriptor->discriminator_size == 0) {
        PRINTF("Skipping discriminator check\n");
    } else {
        if (instruction->data_length < instruction_descriptor->discriminator_size) {
            PRINTF("Instruction data length %d too small to contain the discriminator length %d\n",
                   instruction->data_length,
                   instruction_descriptor->discriminator_size);
            return -1;
        }
        if (memcmp(instruction->data,
                   instruction_descriptor->discriminator,
                   instruction_descriptor->discriminator_size) != 0) {
            PRINTF("Discriminator mismatch received %.*H vs expected %.*H\n",
                   instruction_descriptor->discriminator_size,
                   instruction->data,
                   instruction_descriptor->discriminator_size,
                   instruction_descriptor->discriminator);
            return -1;
        }
        PRINTF("Validated discriminator '%.*H'\n",
               instruction_descriptor->discriminator_size,
               instruction_descriptor->discriminator);
    }

    // CHECK AMOUNT
    if (instruction_descriptor->amount_size == 0) {
        PRINTF("Skipping amount check\n");
    } else {
        uint64_t amount_value = 0;
        if (read_amount_using_descriptor(instruction, instruction_descriptor, &amount_value)) {
            PRINTF("Error failed to read amount from instruction\n");
            return -1;
        }

        if (!check_swap_amount_raw(amount_value)) {
            PRINTF("Error received wrong amount\n");
            return -1;
        }
    }

    // CHECK MINT ADDRESS
    if (!instruction_descriptor->asset_account_index_received) {
        PRINTF("Skipping asset_account_index check\n");
    } else {
        PRINTF("Received asset_account_index to check\n");
        const uint8_t *asset_account = get_account_from_ins(
            instruction,
            header,
            instruction_descriptor->asset_account_index);
        if (asset_account == NULL) {
            PRINTF("Error get_account_from_ins for asset_account\n");
            return -1;
        }
        if (memcmp(validated_mint_address, asset_account, PUBKEY_SIZE) != 0) {
            PRINTF("Error received wrong mint, %.*H != %.*H\n",
                   PUBKEY_SIZE,
                   validated_mint_address,
                   PUBKEY_SIZE,
                   asset_account);
            return -1;
        }
        PRINTF("Validated mint address %.*H\n", PUBKEY_SIZE, asset_account);
    }

    // CHECK MINT ATA
    if (!instruction_descriptor->asset_ata_index_received) {
        PRINTF("Skipping asset_ata check\n");
    } else {
        PRINTF("Received asset_ata to check\n");
        const uint8_t *asset_ata = get_account_from_ins(instruction,
                                                        header,
                                                        instruction_descriptor->asset_ata_index);
        if (asset_ata == NULL) {
            PRINTF("Error get_account_from_ins for asset_account\n");
            return -1;
        }

        uint8_t signer_pubkey[PUBKEY_SIZE];
        get_public_key(signer_pubkey, G_command.derivation_path, G_command.derivation_path_length);
        PRINTF("Derivated signer_pubkey = %.*H\n", sizeof(signer_pubkey), signer_pubkey);
        // Ensure our address + the mint == the ata in the TX
        if (!validate_associated_token_address(signer_pubkey,
                                               validated_mint_address,
                                               asset_ata,
                                               is_token_2022_kind)) {
            PRINTF("validate_associated_token_address failed\n");
            return -1;
        }
    }

    // CHECK RECIPIENT ADDRESS
    if (!instruction_descriptor->recipient_account_index_received) {
        PRINTF("Skipping recipient_account check\n");
    } else {
        PRINTF("Received recipient_account to check\n");
        const uint8_t *recipient_account = get_account_from_ins(
            instruction,
            header,
            instruction_descriptor->recipient_account_index);
        if (recipient_account == NULL) {
            PRINTF("Error get_account_from_ins for asset_account\n");
            return -1;
        }

        if (memcmp(validated_recipient_address, recipient_account, PUBKEY_SIZE) != 0) {
            PRINTF("Error received wrong recipient, %.*H != %.*H\n",
                   PUBKEY_SIZE,
                   validated_recipient_address,
                   PUBKEY_SIZE,
                   recipient_account);
            return -1;
        }
        PRINTF("validated_recipient_address = %.*H\n", PUBKEY_LENGTH, validated_recipient_address);
    }

    // CHECK RECIPIENT ATA
    if (!instruction_descriptor->recipient_ata_index_received) {
        PRINTF("Skipping recipient_ata check\n");
    } else {
        PRINTF("Received recipient_ata to check\n");
        const uint8_t *recipient_ata = get_account_from_ins(
            instruction,
            header,
            instruction_descriptor->recipient_ata_index);
        if (recipient_ata == NULL) {
            PRINTF("Error get_account_from_ins for asset_account\n");
            return -1;
        }

        PRINTF("validated_recipient_address = %.*H\n", PUBKEY_LENGTH, validated_recipient_address);
        // Ensure recipient address + the mint == the ata in the TX
        if (!validate_associated_token_address(validated_recipient_address,
                                               validated_mint_address,
                                               recipient_ata,
                                               is_token_2022_kind)) {
            PRINTF("validate_associated_token_address failed\n");
            return -1;
        }
    }
    return 0;
}
