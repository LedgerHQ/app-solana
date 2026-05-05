#include <os.h>
#include <os_io.h>
#include <cx.h>
#include "apdu.h"
#include "handle_get_challenge.h"
#include "io.h"

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
int handle_get_challenge(void) {
    PRINTF("New challenge -> %u\n", challenge);
    U4BE_ENCODE(G_io_apdu_buffer, 0, challenge);
    return io_send_response_pointer(G_io_apdu_buffer, 4, ApduReplySuccess);
}
