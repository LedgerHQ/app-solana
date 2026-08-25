#pragma once
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

bool is_data_utf8(const uint8_t *data, size_t length);
bool is_data_ascii(const uint8_t *data, size_t length);

// Encode raw bytes to lowercase hexadecimal. Returns encoded length or -1.
int encode_hex(const uint8_t *in, size_t in_len, char *out, size_t out_size);

// Encode raw bytes to standard (padded) base64. Returns encoded length or -1.
int encode_base64(const uint8_t *in, size_t in_len, char *out, size_t out_size);

// Encode raw bytes as printable text. ASCII rejects non-printable bytes; UTF-8 requires
// well-formed UTF-8. Both reject embedded NUL. Returns encoded length or -1.
int encode_text(const uint8_t *in, size_t in_len, bool ascii_only, char *out, size_t out_size);