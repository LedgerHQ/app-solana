#include <stdio.h>

void mcu_usb_prints(const char *str, unsigned int charcount) {
    printf("%.*s", charcount, str);
}
