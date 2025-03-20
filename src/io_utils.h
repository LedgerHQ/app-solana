#pragma once

#include <stdint.h>

#include "ux.h"
#include "os_io_seproxyhal.h"

#ifdef HAVE_BAGL
void io_seproxyhal_display(const bagl_element_t *element);
#endif  // HAVE_BAGL

/**
 * IO callback called when an interrupt based channel has received
 * data to be processed.
 *
 * @return 1 if success, 0 otherwise.
 *
 */
uint8_t io_event(uint8_t channel);

uint16_t io_exchange_al(uint8_t channel, uint16_t tx_len);

void sendResponse(uint8_t tx, uint16_t sw, bool display_menu);
