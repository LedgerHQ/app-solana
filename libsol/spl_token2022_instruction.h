#pragma once

#include "sol/parser.h"
#include "sol/print_config.h"
#include "sol/transaction_summary.h"
#include "spl/token.h"
#include "instruction.h"

#define SplTokenExtensionKind(b) Token_TokenExtensionInstruction_##b

extern const Pubkey spl_token2022_program_id;
