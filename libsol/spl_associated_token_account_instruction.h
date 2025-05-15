#pragma once

#include "sol/print_config.h"

struct Instruction;
struct MessageHeader;
struct Pubkey;

extern const Pubkey spl_associated_token_account_program_id;

typedef struct SplAssociatedTokenAccountCreateInfo {
    const Pubkey *funder;
    const Pubkey *address;
    const Pubkey *owner;
    const Pubkey *mint;
} SplAssociatedTokenAccountCreateInfo;

typedef struct SplAssociatedTokenAccountInfo {
    union {
        SplAssociatedTokenAccountCreateInfo create;
    };
} SplAssociatedTokenAccountInfo;

int parse_spl_associated_token_account_instructions(const Instruction *instruction,
                                                    const MessageHeader *header,
                                                    SplAssociatedTokenAccountInfo *info);

int print_spl_associated_token_account_info(const SplAssociatedTokenAccountInfo *info,
                                            const PrintConfig *print_config);

int print_spl_associated_token_account_create_info(const SplAssociatedTokenAccountCreateInfo *info,
                                                   const PrintConfig *print_config);
