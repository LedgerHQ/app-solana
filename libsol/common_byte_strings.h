#pragma once

// Visually distinguishable 32-byte arrays. Good for test hashes and pubkeys

#define BYTES32_BS58_1 /* "11111111111111111111111111111111" */                                   \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x00, 0x00

#define BYTES32_BS58_2 /* "22222222222222222222222222222222222222222222"*/                        \
    0x0f, 0x1e, 0x6b, 0x14, 0x21, 0xc0, 0x4a, 0x07, 0x04, 0x31, 0x26, 0x5c, 0x19, 0xc5, 0xbb,     \
        0xee, 0x19, 0x92, 0xba, 0xe8, 0xaf, 0xd1, 0xcd, 0x07, 0x8e, 0xf8, 0xaf, 0x70, 0x47, 0xdc, \
        0x11, 0xf7

#define BYTES32_BS58_3 /* "33333333333333333333333333333333333333333333"*/                        \
    0x1e, 0x3c, 0xd6, 0x28, 0x43, 0x80, 0x94, 0x0e, 0x08, 0x62, 0x4c, 0xb8, 0x33, 0x8b, 0x77,     \
        0xdc, 0x33, 0x25, 0x75, 0xd1, 0x5f, 0xa3, 0x9a, 0x0f, 0x1d, 0xf1, 0x5e, 0xe0, 0x8f, 0xb8, \
        0x23, 0xee

#define BYTES32_BS58_4 /* "44444444444444444444444444444444444444444444"*/                        \
    0x2d, 0x5b, 0x41, 0x3c, 0x65, 0x40, 0xde, 0x15, 0x0c, 0x93, 0x73, 0x14, 0x4d, 0x51, 0x33,     \
        0xca, 0x4c, 0xb8, 0x30, 0xba, 0x0f, 0x75, 0x67, 0x16, 0xac, 0xea, 0x0e, 0x50, 0xd7, 0x94, \
        0x35, 0xe5

#define BYTES32_BS58_5 /* "55555555555555555555555555555555555555555555"*/                        \
    0x3c, 0x79, 0xac, 0x50, 0x87, 0x01, 0x28, 0x1c, 0x10, 0xc4, 0x99, 0x70, 0x67, 0x16, 0xef,     \
        0xb8, 0x66, 0x4a, 0xeb, 0xa2, 0xbf, 0x47, 0x34, 0x1e, 0x3b, 0xe2, 0xbd, 0xc1, 0x1f, 0x70, \
        0x47, 0xdc

#define BYTES32_BS58_6 /* "66666666666666666666666666666666666666666666"*/                        \
    0x4b, 0x98, 0x17, 0x64, 0xa8, 0xc1, 0x72, 0x23, 0x14, 0xf5, 0xbf, 0xcc, 0x80, 0xdc, 0xab,     \
        0xa6, 0x7f, 0xdd, 0xa6, 0x8b, 0x6f, 0x19, 0x01, 0x25, 0xca, 0xdb, 0x6d, 0x31, 0x67, 0x4c, \
        0x59, 0xd3

#define BYTES32_BS58_7 /* "77777777777777777777777777777777777777777777"*/                        \
    0x5a, 0xb6, 0x82, 0x78, 0xca, 0x81, 0xbc, 0x2a, 0x19, 0x26, 0xe6, 0x28, 0x9a, 0xa2, 0x67,     \
        0x94, 0x99, 0x70, 0x61, 0x74, 0x1e, 0xea, 0xce, 0x2d, 0x59, 0xd4, 0x1c, 0xa1, 0xaf, 0x28, \
        0x6b, 0xca

#define BYTES32_BS58_8 /* "88888888888888888888888888888888888888888888"*/                        \
    0x69, 0xd4, 0xed, 0x8c, 0xec, 0x42, 0x06, 0x31, 0x1d, 0x58, 0x0c, 0x84, 0xb4, 0x68, 0x23,     \
        0x82, 0xb3, 0x03, 0x1c, 0x5c, 0xce, 0xbc, 0x9b, 0x34, 0xe8, 0xcc, 0xcc, 0x11, 0xf7, 0x04, \
        0x7d, 0xc1

#define BYTES32_BS58_9 /* "ComputeBudget111111111111111111111111111111" */ \
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, \
        0x9b, 0xe7, 0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, \
        0x00, 0x00

// Program IDs

#define PROGRAM_ID_SPL_TOKEN /* "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" */                  \
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79,     \
        0xac, 0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, \
        0x00, 0xa9
#define PROGRAM_ID_SYSTEM BYTES32_BS58_1
#define PROGRAM_ID_STAKE  /* "Stake11111111111111111111111111111111111111" */                     \
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a, 0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a,     \
        0xb2, 0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b, 0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, \
        0x00, 0x00
#define PROGRAM_ID_VOTE /* "Vote111111111111111111111111111111111111111" */                       \
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd,     \
        0xb3, 0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, \
        0x00, 0x00
#define PROGRAM_ID_SPL_ASSOCIATED_TOKEN_ACCOUNT                                                   \
    /* "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" */                                          \
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d,     \
        0x83, 0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, \
        0xf8, 0x59
#define PROGRAM_ID_SERUM_ASSERT_OWNER                                                             \
    /* "4MNPdKu9wFMvEeZBMt3Eipfs5ovVWTJb31pEXDJAAxX5" */                                          \
    0x31, 0xca, 0xdc, 0xe2, 0xaa, 0x36, 0xec, 0x04, 0x60, 0x46, 0x83, 0xea, 0xa6, 0xf1, 0x36,     \
        0x2c, 0x32, 0x9e, 0x11, 0x91, 0x04, 0x28, 0x42, 0xa0, 0x4e, 0x09, 0xb8, 0x2b, 0x75, 0x9f, \
        0xb3, 0x24
#define PROGRAM_ID_SERUM_ASSERT_OWNER_PHANTOM                                                     \
    /* "DeJBGdMFa1uynnnKiwrVioatTuHmNLpyFKnmB5kaFdzQ" */                                          \
    0xbb, 0xda, 0x27, 0xbc, 0x25, 0x19, 0xcb, 0xbe, 0xd7, 0xd4, 0x6f, 0x6b, 0x19, 0x77, 0x2f,     \
        0xe7, 0x1d, 0x72, 0xf3, 0x79, 0x94, 0x6c, 0x56, 0x9e, 0x7d, 0x85, 0x0e, 0xca, 0x3c, 0x71, \
        0x1d, 0x31
#define PROGRAM_ID_SPL_MEMO /* "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" */                   \
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38,     \
        0x7c, 0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, \
        0x44, 0x8d

#define PROGRAM_ID_COMPUTE_BUDGET BYTES32_BS58_9

// Sysvars
#define SYSVAR_RENT /* "SysvarRent111111111111111111111111111111111" */                           \
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x5c, 0x51, 0x21, 0x8c, 0xc9, 0x4c, 0x3d, 0x4a, 0xf1,     \
        0x7f, 0x58, 0xda, 0xee, 0x08, 0x9b, 0xa1, 0xfd, 0x44, 0xe3, 0xdb, 0xd9, 0x8a, 0x00, 0x00, \
        0x00, 0x00

// Domain specifiers
#define OFFCHAIN_MESSAGE_SIGNING_DOMAIN /* "\xffsolana offchain" */                               \
    0xff, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x20, 0x6f, 0x66, 0x66, 0x63, 0x68, 0x61, 0x69,     \
        0x6e
