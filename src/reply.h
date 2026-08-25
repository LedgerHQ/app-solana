#pragma once

#include <stdint.h>
#include <stddef.h>

// Application response senders. Every APDU reply from the app goes through these instead of the
// raw SDK io_send_*: they release the received command buffer before sending, and on an error
// status word they also abandon the clear-signing session and the delayed-sign fingerprint.

int reply_sw(uint16_t sw);
int reply_data(const uint8_t *rdata, size_t rdata_len, uint16_t sw);
