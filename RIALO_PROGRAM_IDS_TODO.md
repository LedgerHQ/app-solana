# Rialo Program IDs Migration TODO

When Rialo finalizes their program IDs, the following need to be updated throughout the codebase:

## Core Program IDs (`libsol/common_byte_strings.h`)

### **Critical System Programs**
- [ ] **System Program** (`PROGRAM_ID_SYSTEM`)
  - Current: `11111111111111111111111111111111` (all zeros)
  - Files: `libsol/common_byte_strings.h:55`, `libsol/system_instruction.c:12`
  - Usage: Account creation, transfers, nonce operations

- [ ] **Stake Program** (`PROGRAM_ID_STAKE`) 
  - Current: `Stake11111111111111111111111111111111111111`
  - Files: `libsol/common_byte_strings.h:56-59`, `libsol/stake_instruction.h/c`
  - Usage: Staking operations, delegation, rewards

- [ ] **Vote Program** (`PROGRAM_ID_VOTE`)
  - Current: `Vote111111111111111111111111111111111111111`  
  - Files: `libsol/common_byte_strings.h:60-63`, `libsol/vote_instruction.h/c`
  - Usage: Validator voting, consensus operations

### **Token Programs**
- [ ] **SPL Token Program** (`PROGRAM_ID_SPL_TOKEN`)
  - Current: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
  - Files: `libsol/common_byte_strings.h:47-50`, `libsol/spl_token_instruction.h/c`
  - Usage: Fungible token operations (mint, transfer, burn)

- [ ] **SPL Token 2022 Program** (`PROGRAM_ID_SPL_TOKEN_2022`)
  - Current: `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
  - Files: `libsol/common_byte_strings.h:51-54`, `libsol/spl_token2022_instruction.h/c`
  - Usage: Extended token functionality

- [ ] **Associated Token Account Program** (`PROGRAM_ID_SPL_ASSOCIATED_TOKEN_ACCOUNT`)
  - Current: `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`
  - Files: `libsol/common_byte_strings.h:64-68`, `libsol/spl_associated_token_account_instruction.h/c`
  - Usage: Automatic token account creation

### **Utility Programs**  
- [ ] **Compute Budget Program** (`PROGRAM_ID_COMPUTE_BUDGET`)
  - Current: `ComputeBudget111111111111111111111111111111`
  - Files: `libsol/common_byte_strings.h:84-87`, `libsol/compute_budget_instruction.h/c`
  - Usage: Transaction compute unit management

- [ ] **SPL Memo Program** (`PROGRAM_ID_SPL_MEMO`)
  - Current: `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`
  - Files: `libsol/common_byte_strings.h:79-82`, `libsol/spl_memo_instruction.h/c`  
  - Usage: On-chain memos and notes

### **Serum Programs**
- [ ] **Serum Assert Owner Program** (`PROGRAM_ID_SERUM_ASSERT_OWNER`)
  - Current: `4MNPdKu9wFMvEeZBMt3Eipfs5ovVWTJb31pEXDJAAxX5`
  - Files: `libsol/common_byte_strings.h:69-73`, `libsol/serum_assert_owner_instruction.h/c`

- [ ] **Serum Assert Owner Phantom** (`PROGRAM_ID_SERUM_ASSERT_OWNER_PHANTOM`)
  - Current: `DeJBGdMFa1uynnnKiwrVioatTuHmNLpyFKnmB5kaFdzQ` 
  - Files: `libsol/common_byte_strings.h:74-78`

## System Variables (Sysvars)
- [ ] **Rent Sysvar** (`SYSVAR_RENT`)
  - Current: `SysvarRent111111111111111111111111111111111`
  - Files: `libsol/common_byte_strings.h:91-94`
  - Usage: Account rent calculations

## Native Token Address
- [ ] **Native RLO Token** (Wrapped RLO)
  - Current: `So11111111111111111111111111111111111111112` 
  - Files: `libsol/token_info.c:7-11` (already updated to show "RLO")
  - Usage: Wrapped native token operations

## Off-chain Message Signing
- [ ] **Message Domain Prefix**
  - Current: `\xffsolana offchain` 
  - Files: `libsol/common_byte_strings.h:97-98`, `examples/example-sign.js:138`
  - **Action**: Update to `\xffrialo offchain`

## Test Files Requiring Updates
- [ ] **Python Test Files**
  - `tests/python/test_staking.py` - Contains hardcoded program IDs
  - `tests/python/test_rialo_spl_token.py` - Token program references
  - `tests/python/test_donjon.py` - Security test program IDs
  - `tests/python/test_blind_signing.py` - Program ID validations

## Binary Test Data Files
- [ ] **Corpus Files** (`fuzzing/corpus/*.raw`)
  - All `.raw` files contain serialized transactions with hardcoded Solana program IDs
  - **Action**: Regenerate test transactions with Rialo program IDs

- [ ] **Ledger Communication Files** (`tests/ledgercomm/*.dat`)
  - Binary APDU test data with embedded program IDs
  - **Action**: Update test transaction data

## Cargo Dependencies (Future Consideration)
- [ ] **Rust SDK Dependencies** 
  - `tests/Cargo.toml` - Currently uses `solana-*` crates
  - `tools/apdu_generator/Cargo.toml` - Solana SDK dependency
  - **Action**: Evaluate if Rialo provides equivalent SDK crates

## Validation Checklist

After updating program IDs:
- [ ] Run unit tests: `make -C libsol`
- [ ] Run Python tests: `pytest tests/python/`
- [ ] Run fuzzing tests: `cd fuzzing && ./run.sh`
- [ ] Test on hardware devices with updated icons
- [ ] Verify all program instruction parsing works correctly
- [ ] Test token transfers, staking, and vote operations
- [ ] Validate off-chain message signing with new domain

## Critical Notes
⚠️ **Do not update program IDs until Rialo team provides official values**
⚠️ **All program IDs must be updated together for consistency**  
⚠️ **Test thoroughly on devnet before mainnet deployment**
⚠️ **Consider backward compatibility with existing user transactions**

## Implementation Priority
1. **Core programs** (System, Token, Stake, Vote) - **HIGH PRIORITY**
2. **Utility programs** (Compute Budget, Memo) - **MEDIUM PRIORITY**  
3. **Serum programs** - **LOW PRIORITY** (may not be needed for Rialo)
4. **Test data regeneration** - **AFTER CODE UPDATES**
5. **SDK dependencies** - **EVALUATE NEED**