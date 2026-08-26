#include "transaction_printers.c"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>

#define BRIEF_ENTRY(brief) {brief, ARRAY_LEN(brief), #brief}

static const struct {
    const InstructionBrief *briefs;
    size_t length;
    const char *name;
} G_all_briefs[] = {
    BRIEF_ENTRY(nonce_brief),
    BRIEF_ENTRY(create_stake_account_brief),
    BRIEF_ENTRY(create_stake_account_checked_brief),
    BRIEF_ENTRY(create_stake_account_with_seed_brief),
    BRIEF_ENTRY(create_stake_account_with_seed_checked_brief),
    BRIEF_ENTRY(create_stake_account_and_delegate_brief),
    BRIEF_ENTRY(create_stake_account_with_seed_and_delegate_brief),
    BRIEF_ENTRY(stake_split_brief_v1_1),
    BRIEF_ENTRY(stake_split_with_seed_brief_v1_1),
    BRIEF_ENTRY(stake_split_brief_v1_2),
    BRIEF_ENTRY(stake_split_with_seed_brief_v1_2),
    BRIEF_ENTRY(stake_split_brief_v1_3),
    BRIEF_ENTRY(stake_split_with_seed_brief_v1_3),
    BRIEF_ENTRY(stake_authorize_both_brief),
    BRIEF_ENTRY(stake_authorize_checked_both_brief),
    BRIEF_ENTRY(create_nonce_account_brief),
    BRIEF_ENTRY(create_nonce_account_with_seed_brief),
    BRIEF_ENTRY(create_vote_account_brief),
    BRIEF_ENTRY(create_vote_account_with_seed_brief),
    BRIEF_ENTRY(vote_authorize_both_brief),
    BRIEF_ENTRY(vote_authorize_checked_both_brief),
    BRIEF_ENTRY(spl_token_create_mint_brief),
    BRIEF_ENTRY(spl_token_create_account_brief),
    BRIEF_ENTRY(spl_token_create_account2_brief),
    BRIEF_ENTRY(spl_token_create_multisig_brief),
    BRIEF_ENTRY(spl_associated_token_account_create_with_transfer_brief),
    BRIEF_ENTRY(spl_associated_token_account_create_with_transfer_fee_brief),
};

// Compare the discriminated member, not the raw bytes
static bool briefs_equal(const InstructionBrief *a, const InstructionBrief *b) {
    if (a->program_id != b->program_id) {
        return false;
    }
    switch (a->program_id) {
        case ProgramIdSerumAssertOwner:
        case ProgramIdSplAssociatedTokenAccount:
        case ProgramIdSplMemo:
        case ProgramIdUnknown:
            return true;
        case ProgramIdComputeBudget:
            return (a->compute_budget == b->compute_budget);
        case ProgramIdSplToken:
            return (a->spl_token == b->spl_token);
        case ProgramIdStake:
            return (a->stake == b->stake);
        case ProgramIdSystem:
            return (a->system == b->system);
        case ProgramIdVote:
            return (a->vote == b->vote);
    }
    return false;
}

static bool sequences_equal(size_t i, size_t j) {
    if (G_all_briefs[i].length != G_all_briefs[j].length) {
        return false;
    }
    for (size_t k = 0; k < G_all_briefs[i].length; k++) {
        if (!briefs_equal(&G_all_briefs[i].briefs[k], &G_all_briefs[j].briefs[k])) {
            return false;
        }
    }
    return true;
}

// The dispatch chain tries the briefs in order, so a duplicate sequence is never reached
void test_no_duplicate_brief_sequences() {
    for (size_t i = 0; i < ARRAY_LEN(G_all_briefs); i++) {
        for (size_t j = i + 1; j < ARRAY_LEN(G_all_briefs); j++) {
            if (sequences_equal(i, j)) {
                printf("FAIL: %s and %s declare the same sequence\n",
                       G_all_briefs[i].name,
                       G_all_briefs[j].name);
            }
            assert(!sequences_equal(i, j));
        }
    }
}

int main() {
    RUN_TEST(test_no_duplicate_brief_sequences);

    printf("passed\n");
    return 0;
}
