#include "os.h"
#include "ux.h"
#include "os_io_seproxyhal.h"

#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#define CLA 0xE0

// header offsets
#define OFFSET_CLA              0
#define OFFSET_INS              1
#define OFFSET_P1               2
#define OFFSET_P2               3
#define OFFSET_LC               4
#define OFFSET_CDATA            5
#define DEPRECATED_OFFSET_CDATA 6

#define P1_CONFIRM     0x01
#define P1_NON_CONFIRM 0x00

#define P2_EXTEND 0x01
#define P2_MORE   0x02

#define ROUND_TO_NEXT(x, next) (((x) == 0) ? 0 : ((((x - 1) / (next)) + 1) * (next)))

/* See constant by same name in sdk/src/packet.rs */
#define PACKET_DATA_SIZE (1280 - 40 - 8)

#define MAX_BIP32_PATH_LENGTH             5
#define MAX_DERIVATION_PATH_BUFFER_LENGTH (1 + MAX_BIP32_PATH_LENGTH * 4)
#define TOTAL_SIGN_MESSAGE_BUFFER_LENGTH  (PACKET_DATA_SIZE + MAX_DERIVATION_PATH_BUFFER_LENGTH)

#define MAX_OFFCHAIN_MESSAGE_LENGTH PACKET_DATA_SIZE

// 1232 + 32 + 1 + 1 + 32 + 1 + 16
// Assuming that only one signer is present and that message is in ASCII format
#define OFFCHAIN_MESSAGE_HEADER_LENGTH 85

// Application buffer - no content reference value
#define OFFCHAIN_EMPTY_APPLICATION_DOMAIN                                                         \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x00, 0x00

#define MAX_MESSAGE_LENGTH ROUND_TO_NEXT(TOTAL_SIGN_MESSAGE_BUFFER_LENGTH, USB_SEGMENT_SIZE)

// credit: https://stackoverflow.com/questions/807244/c-compiler-asserts-how-to-implement
#define CASSERT(predicate, file) _impl_CASSERT_LINE(predicate, __LINE__, file)
#define _impl_PASTE(a, b)        a##b
#define _impl_CASSERT_LINE(predicate, line, file) \
    typedef char _impl_PASTE(assertion_failed_##file##_, line)[2 * !!(predicate) - 1];

typedef enum InstructionCode {
    // DEPRECATED - Use non "16" suffixed variants below
    InsDeprecatedGetAppConfiguration = 0x01,
    InsDeprecatedGetPubkey = 0x02,
    InsDeprecatedSignMessage = 0x03,
    // END DEPRECATED
    InsGetAppConfiguration = 0x04,
    InsGetPubkey = 0x05,
    InsSignMessage = 0x06,
    InsSignOffchainMessage = 0x07,
    InsTrustedInfoGetChallenge = 0x20,
    InsTrustedInfoProvideInfo = 0x21,
} InstructionCode;

extern volatile bool G_called_from_swap;
extern volatile bool G_swap_response_ready;

// display stepped screens
extern unsigned int ux_step;
extern unsigned int ux_step_count;

enum BlindSign {
    BlindSignDisabled = 0,
    BlindSignEnabled = 1,
};

enum PubkeyDisplay {
    PubkeyDisplayLong = 0,
    PubkeyDisplayShort = 1,
};

enum DisplayMode {
    DisplayModeUser = 0,
    DisplayModeExpert = 1,
};

typedef struct AppSettings {
    uint8_t allow_blind_sign;
    uint8_t pubkey_display;
    uint8_t display_mode;
} AppSettings;

typedef struct internalStorage_t {
    AppSettings settings;
    uint8_t initialized;
} internalStorage_t;

extern const internalStorage_t N_storage_real;
#define N_storage (*(volatile internalStorage_t *) PIC(&N_storage_real))
#endif
