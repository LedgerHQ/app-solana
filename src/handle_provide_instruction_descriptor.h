#pragma once

#include "buffer.h"

void handle_provide_instruction_descriptor(void);

void reset_saved_descriptors(void);

uint8_t get_descriptor_count(void);

bool instruction_descriptor_received(void);

#define PROGRAM_ADDRESS_SIZE   32
#define MAX_DISCRIMINATOR_SIZE 8

typedef struct instruction_descriptor_s {
    uint8_t program_id[PROGRAM_ADDRESS_SIZE];
    uint8_t discriminator[MAX_DISCRIMINATOR_SIZE];
    uint8_t discriminator_size;

    uint8_t amount_size;
    uint8_t amount_offset;
    bool amount_rules_big_endian;
    bool amount_rules_negative_offset;

    bool asset_account_index_received;
    uint8_t asset_account_index;

    bool asset_ata_index_received;
    uint8_t asset_ata_index;

    bool recipient_account_index_received;
    uint8_t recipient_account_index;

    bool recipient_ata_index_received;
    uint8_t recipient_ata_index;
} instruction_descriptor_t;

int get_next_descriptor(const instruction_descriptor_t **instruction_descriptor);

int validate_instruction_using_descriptor(const MessageHeader *header,
                                          const Instruction *instruction);
