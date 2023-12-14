#include "include/sol/string_utils.h"


/**
 * Checks if data is in UTF-8 format.
 * Adapted from: https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
 */
bool is_data_utf8(const uint8_t *data, size_t length) {
    if (!data) {
        return false;
    }
    size_t i = 0;
    while (i < length) {
        if (data[i] < 0x80) {
            /* 0xxxxxxx */
            ++i;
        } else if ((data[i] & 0xe0) == 0xc0) {
            /* 110XXXXx 10xxxxxx */
            if (i + 1 >= length || (data[i + 1] & 0xc0) != 0x80 ||
                (data[i] & 0xfe) == 0xc0) /* overlong? */ {
                return false;
            } else {
                i += 2;
            }
        } else if ((data[i] & 0xf0) == 0xe0) {
            /* 1110XXXX 10Xxxxxx 10xxxxxx */
            if (i + 2 >= length || (data[i + 1] & 0xc0) != 0x80 || (data[i + 2] & 0xc0) != 0x80 ||
                (data[i] == 0xe0 && (data[i + 1] & 0xe0) == 0x80) || /* overlong? */
                (data[i] == 0xed && (data[i + 1] & 0xe0) == 0xa0) || /* surrogate? */
                (data[i] == 0xef && data[i + 1] == 0xbf &&
                 (data[i + 2] & 0xfe) == 0xbe)) /* U+FFFE or U+FFFF? */ {
                return false;
            } else {
                i += 3;
            }
        } else if ((data[i] & 0xf8) == 0xf0) {
            /* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
            if (i + 3 >= length || (data[i + 1] & 0xc0) != 0x80 || (data[i + 2] & 0xc0) != 0x80 ||
                (data[i + 3] & 0xc0) != 0x80 ||
                (data[i] == 0xf0 && (data[i + 1] & 0xf0) == 0x80) || /* overlong? */
                (data[i] == 0xf4 && data[i + 1] > 0x8f) || data[i] > 0xf4) /* > U+10FFFF? */ {
                return false;
            } else {
                i += 4;
            }
        } else {
            return false;
        }
    }
    return true;
}

/*
 * Checks if data is in ASCII format
 */
bool is_data_ascii(const uint8_t *data, size_t length) {
    if (!data) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        //Line feed char is accepted
        if (((data[i] < 0x20 && data[i] != 0x0A) || data[i] > 0x7e)) {
            return false;
        }
    }
    return true;
}

