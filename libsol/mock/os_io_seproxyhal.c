#include <stdio.h>
#include "os_io_seproxyhal.h"

void os_io_seph_cmd_printf(const char *str, uint16_t charcount) {
    printf("%.*s", charcount, str);
}
