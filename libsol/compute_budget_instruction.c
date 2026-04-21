#include "compute_budget_instruction.h"
#include "sol/transaction_summary.h"
#include <limits.h>

const Pubkey compute_budget_program_id = {{PROGRAM_ID_COMPUTE_BUDGET}};

static int parse_compute_budget_instruction_kind(Parser *parser,
                                                 enum ComputeBudgetInstructionKind *kind) {
    uint8_t maybe_kind;
    BAIL_IF(parse_u8(parser, &maybe_kind));
    switch (maybe_kind) {
        case ComputeBudgetRequestHeapFrame:
        case ComputeBudgetChangeUnitLimit:
        case ComputeBudgetChangeUnitPrice:
        case ComputeBudgetSetLoadedAccountsDataSizeLimit:
            *kind = (enum ComputeBudgetInstructionKind) maybe_kind;
            return 0;
        default:
            return 1;
    }
}

static int parse_request_heap_frame_instruction(Parser *parser,
                                                ComputeBudgetRequestHeapFrameInfo *info) {
    BAIL_IF(parse_u32(parser, &info->bytes));

    return 0;
}

static int parse_unit_limit_instruction(Parser *parse, ComputeBudgetChangeUnitLimitInfo *info) {
    BAIL_IF(parse_u32(parse, &info->units));

    return 0;
}

static int parse_unit_price_instruction(Parser *parse, ComputeBudgetChangeUnitPriceInfo *info) {
    BAIL_IF(parse_u64(parse, &info->units));

    return 0;
}

static int parse_loaded_accounts_data_size_limit(
    Parser *parse,
    ComputeBudgetSetLoadedAccountsDataSizeLimitInfo *info) {
    BAIL_IF(parse_u32(parse, &info->units));

    return 0;
}

int calculate_max_fee(const ComputeBudgetFeeInfo *info, uint64_t *max_fee) {
    uint64_t compute_fee = 0;
    uint64_t base_fee = (uint64_t) FEE_LAMPORTS_PER_SIGNATURE * info->signatures_count;
    PRINTF("Base fee from signatures: %llu\n", base_fee);

    if (info == NULL || max_fee == NULL) {
        PRINTF("calculate_max_fee invalid argument\n");
        return -1;
    }

    if (info->change_unit_price != NULL) {
        uint64_t max_compute = 0;
        if (info->change_unit_limit != NULL) {
            max_compute = info->change_unit_limit->units;
        } else {
            max_compute = MIN(info->instructions_count * MAX_CU_PER_INSTRUCTION,
                              MAX_CU_PER_TRANSACTION);
        }
        if (max_compute != 0 && info->change_unit_price->units > UINT64_MAX / max_compute) {
            PRINTF("Overflow in compute fee calculation, rejecting\n");
            return -1;
        }
        compute_fee = (info->change_unit_price->units * max_compute) / MICRO_LAMPORT_MULTIPLIER;
        PRINTF("Fees from ComputeBudget: %llu\n", compute_fee);
    }

    if (base_fee > UINT64_MAX - compute_fee) {
        PRINTF("Overflow in total fee calculation, rejecting\n");
        return -1;
    }

    *max_fee = base_fee + compute_fee;
    PRINTF("Total fee: %llu\n", *max_fee);
    return 0;
}

int print_compute_budget_max_fee(uint64_t max_fee, const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;

    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Max fees", max_fee);

    return 0;
}

int parse_compute_budget_instructions(const Instruction *instruction,
                                      const MessageHeader *header,
                                      ComputeBudgetInfo *info) {
    Parser parser = {instruction->data, instruction->data_length};

    BAIL_IF(parse_compute_budget_instruction_kind(&parser, &info->kind));

    info->signatures_count = header->pubkeys_header.num_required_signatures;

    switch (info->kind) {
        case ComputeBudgetRequestHeapFrame:
            return parse_request_heap_frame_instruction(&parser, &info->request_heap_frame);
        case ComputeBudgetChangeUnitLimit:
            return parse_unit_limit_instruction(&parser, &info->change_unit_limit);
        case ComputeBudgetChangeUnitPrice:
            return parse_unit_price_instruction(&parser, &info->change_unit_price);
        case ComputeBudgetSetLoadedAccountsDataSizeLimit:
            return parse_loaded_accounts_data_size_limit(
                &parser,
                &info->set_loaded_accounts_data_size_limit);
        default:
            return 1;
    }
}
