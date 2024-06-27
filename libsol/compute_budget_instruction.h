#pragma once

#include "common_byte_strings.h"
#include "util.h"
#include "sol/parser.h"
#include "sol/print_config.h"

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

typedef struct ComputeBudgetSetLoadedAccountsDataSizeLimitInfo{
    uint32_t units;
} ComputeBudgetSetLoadedAccountsDataSizeLimitInfo;

typedef struct ComputeBudgetInfo {
    enum ComputeBudgetInstructionKind kind;
    union {
        ComputeBudgetRequestHeapFrameInfo request_heap_frame;
        ComputeBudgetChangeUnitLimitInfo change_unit_limit;
        ComputeBudgetChangeUnitPriceInfo change_unit_price;
        ComputeBudgetSetLoadedAccountsDataSizeLimitInfo set_loaded_accounts_data_size_limit;
    };
} ComputeBudgetInfo;

int parse_compute_budget_instructions(const Instruction* instruction, ComputeBudgetInfo* info);

int print_compute_budget(ComputeBudgetInfo* info, const PrintConfig* print_config);
