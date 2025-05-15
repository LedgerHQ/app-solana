#include "compute_budget_instruction.h"
#include "sol/transaction_summary.h"

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

static uint32_t calculate_max_fee(const ComputeBudgetFeeInfo *info) {
    uint32_t max_fee = FEE_LAMPORTS_PER_SIGNATURE * info->signatures_count;

    if (info->change_unit_price != NULL) {
        uint32_t max_compute = 0;
        if (info->change_unit_limit != NULL) {
            max_compute = info->change_unit_limit->units;
        } else {
            max_compute =
                MIN(info->instructions_count * MAX_CU_PER_INSTRUCTION, MAX_CU_PER_TRANSACTION);
        }
        return max_fee +
               ((info->change_unit_price->units * max_compute) / MICRO_LAMPORT_MULTIPLIER);
    }
    return max_fee;
}

static int print_compute_budget_max_fee(uint32_t max_fee, const PrintConfig *print_config) {
    UNUSED(print_config);

    SummaryItem *item;

    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Max fees", max_fee);

    return 0;
}

/**
 * Display transaction max fees
 * RequestHeapFrame and SetLoadedAccountsDataSizeLimit instruction kinds
 * are omitted on purpose as they currently do not display any data on the screen
 */
void print_compute_budget(ComputeBudgetFeeInfo *info, const PrintConfig *print_config) {
    uint32_t transaction_max_fee = calculate_max_fee(info);
    print_compute_budget_max_fee(transaction_max_fee, print_config);
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
