#include <os.h>
#include <os_io.h>
#include <cx.h>
#include "apdu.h"
#include "handle_get_challenge.h"

static uint32_t challenge;

/**
 * Generate a new challenge from the Random Number Generator
 */
void roll_challenge(void) {
#ifdef FIXED_TLV_CHALLENGE
    challenge = 0xdeadbeef;
#else
    challenge = cx_rng_u32();
#endif
}

/**
 * Get the current challenge
 *
 * @return challenge
 */
uint32_t get_challenge(void) {
    return challenge;
}

/**
 * Send back the current challenge
 */
void handle_get_challenge(volatile unsigned int *tx) {
    PRINTF("New challenge -> %u\n", challenge);
    U4BE_ENCODE(G_io_apdu_buffer, 0, challenge);
    *tx += 4;
    THROW(ApduReplySuccess);
}
