#include "include/sol/string_utils.h"
#include "os_print.h"

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
        // Line feed char is accepted
        if (((data[i] < 0x20 && data[i] != 0x0A) || data[i] > 0x7e)) {
            return false;
        }
    }
    return true;
}

int encode_hex(const uint8_t *in, size_t in_len, char *out, size_t out_size) {
    static const char digits[] = "0123456789abcdef";

    if (in_len * 2 + 1 > out_size) {
        PRINTF("encode_hex: output does not fit\n");
        return -1;
    }
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2] = digits[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = digits[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
    return (int) (in_len * 2);
}

int encode_base64(const uint8_t *in, size_t in_len, char *out, size_t out_size) {
    static const char
        alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = ((in_len + 2) / 3) * 4;
    size_t o = 0;

    if (out_len + 1 > out_size) {
        PRINTF("encode_base64: output does not fit\n");
        return -1;
    }
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t triple = (uint32_t) in[i] << 16;
        size_t remaining = in_len - i;
        if (remaining > 1) {
            triple |= (uint32_t) in[i + 1] << 8;
        }
        if (remaining > 2) {
            triple |= (uint32_t) in[i + 2];
        }
        out[o++] = alphabet[(triple >> 18) & 0x3F];
        out[o++] = alphabet[(triple >> 12) & 0x3F];
        if (remaining > 1) {
            out[o++] = alphabet[(triple >> 6) & 0x3F];
        } else {
            out[o++] = '=';
        }
        if (remaining > 2) {
            out[o++] = alphabet[triple & 0x3F];
        } else {
            out[o++] = '=';
        }
    }
    out[o] = '\0';
    return (int) o;
}

int encode_text(const uint8_t *in, size_t in_len, bool ascii_only, char *out, size_t out_size) {
    if (in_len + 1 > out_size) {
        PRINTF("encode_text: output does not fit\n");
        return -1;
    }
    // The UTF-8 encoding renders multi-byte sequences verbatim, so the buffer must be valid
    // UTF-8; ASCII mode's per-byte range check already rejects any non-ASCII byte.
    if (!ascii_only && !is_data_utf8(in, in_len)) {
        PRINTF("encode_text: input is not well-formed UTF-8\n");
        return -1;
    }
    for (size_t i = 0; i < in_len; i++) {
        // An embedded NUL would terminate the C-string display early, showing fewer bytes than
        // were signed, so it is rejected in both encodings.
        if (in[i] == 0) {
            PRINTF("encode_text: embedded NUL byte\n");
            return -1;
        }
        // ASCII permits only printable 7-bit bytes; everything else is rejected.
        if (ascii_only && (in[i] < 0x20 || in[i] > 0x7E)) {
            PRINTF("encode_text: non-printable ASCII byte 0x%02x\n", in[i]);
            return -1;
        }
        out[i] = (char) in[i];
    }
    out[in_len] = '\0';
    return (int) in_len;
}
