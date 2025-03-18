#pragma once

#include "common_byte_strings.h"
#include "util.h"
#include "sol/parser.h"
#include "sol/print_config.h"

// https://solana.com/docs/core/fees#compute-unit-limit
#define MAX_CU_PER_INSTRUCTION     200000
#define MAX_CU_PER_TRANSACTION     1400000
#define FEE_LAMPORTS_PER_SIGNATURE 5000
#define MICRO_LAMPORT_MULTIPLIER   1000000

extern const Pubkey compute_budget_program_id;

enum ComputeBudgetInstructionKind {
    ComputeBudgetRequestHeapFrame = 1,
    ComputeBudgetChangeUnitLimit,
    ComputeBudgetChangeUnitPrice,
    ComputeBudgetSetLoadedAccountsDataSizeLimit
};

typedef struct ComputeBudgetRequestHeapFrameInfo {
    uint32_t bytes;
} ComputeBudgetRequestHeapFrameInfo;

typedef struct ComputeBudgetChangeUnitLimitInfo {
    uint32_t units;
} ComputeBudgetChangeUnitLimitInfo;

typedef struct ComputeBudgetChangeUnitPriceInfo {
    uint64_t units;
} ComputeBudgetChangeUnitPriceInfo;

typedef struct ComputeBudgetSetLoadedAccountsDataSizeLimitInfo {
    uint32_t units;
} ComputeBudgetSetLoadedAccountsDataSizeLimitInfo;

typedef struct ComputeBudgetInfo {
    enum ComputeBudgetInstructionKind kind;
    size_t signatures_count;
    union {
        ComputeBudgetRequestHeapFrameInfo request_heap_frame;
        ComputeBudgetChangeUnitLimitInfo change_unit_limit;
        ComputeBudgetChangeUnitPriceInfo change_unit_price;
        ComputeBudgetSetLoadedAccountsDataSizeLimitInfo set_loaded_accounts_data_size_limit;
    };
} ComputeBudgetInfo;

typedef struct ComputeBudgetFeeInfo {
    ComputeBudgetChangeUnitLimitInfo *change_unit_limit;
    ComputeBudgetChangeUnitPriceInfo *change_unit_price;
    size_t instructions_count;
    size_t signatures_count;
} ComputeBudgetFeeInfo;

int parse_compute_budget_instructions(const Instruction *instruction,
                                      const MessageHeader *header,
                                      ComputeBudgetInfo *info);

void print_compute_budget(ComputeBudgetFeeInfo *info, const PrintConfig *print_config);
