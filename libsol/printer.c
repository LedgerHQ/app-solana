#include <string.h>
#include <limits.h>
#include "os_error.h"
#include "rfc3339.h"
#include "sol/printer.h"
#include "util.h"

// max amount is max uint64 scaled down: "18446744073.709551615"
#define AMOUNT_MAX_SIZE 22

int print_token_amount(uint64_t amount,
                       const char *const asset,
                       uint8_t decimals,
                       char *out,
                       const size_t out_length) {
    BAIL_IF(out_length > INT_MAX);
    uint64_t dVal = amount;
    const int outlen = (int) out_length;
    int i = 0;
    int min_chars = decimals + 1;

    if (i < (outlen - 1)) {
        do {
            if (i == decimals) {
                out[i] = '.';
                i += 1;
            }
            out[i] = (dVal % 10) + '0';
            dVal /= 10;
            i += 1;
        } while ((dVal > 0 || i < min_chars) && i < outlen);
    }
    BAIL_IF(i >= outlen);
    // Reverse order
    int j, k;
    for (j = 0, k = i - 1; j < k; j++, k--) {
        char tmp = out[j];
        out[j] = out[k];
        out[k] = tmp;
    }
    // Strip trailing 0s
    for (i -= 1; i > 0; i--) {
        if (out[i] != '0') break;
    }
    i += 1;

    // Strip trailing .
    if (out[i - 1] == '.') i -= 1;

    if (asset) {
        const int asset_length = strlen(asset);
        // Check buffer has space
        BAIL_IF((i + 1 + asset_length + 1) > outlen);
        // Qualify amount
        out[i++] = ' ';
        strncpy(out + i, asset, asset_length + 1);
    } else {
        out[i] = '\0';
    }

    return 0;
}

int print_amount(uint64_t amount, char *out, size_t out_length) {
    return print_token_amount(amount, "SOL", SOL_DECIMALS, out, out_length);
}

int print_sized_string(const SizedString *string, char *out, size_t out_length) {
    size_t len = MIN(out_length, string->length);
    strncpy(out, string->string, len);
    if (string->length < out_length) {
        out[string->length] = '\0';
        return 0;
    } else {
        out[--out_length] = '\0';
        if (out_length != 0) {
            /* signal truncation */
            out[out_length - 1] = '~';
        }
        return 1;
    }
}

int print_string(const char *in, char *out, size_t out_length) {
    strncpy(out, in, out_length);
    int rc = (out[--out_length] != '\0');
    if (rc) {
        /* ensure the output is NUL terminated */
        out[out_length] = '\0';
        if (out_length != 0) {
            /* signal truncation */
            out[out_length - 1] = '~';
        }
    }
    return rc;
}

int print_summary(const char *in,
                  char *out,
                  size_t out_length,
                  size_t left_length,
                  size_t right_length) {
    BAIL_IF(out_length <= (left_length + right_length + 2));
    size_t in_length = strlen(in);
    if ((in_length + 1) > out_length) {
        memcpy(out, in, left_length);
        out[left_length] = '.';
        out[left_length + 1] = '.';
        memcpy(out + left_length + 2, in + in_length - right_length, right_length);
        out[left_length + right_length + 2] = '\0';
    } else {
        print_string(in, out, out_length);
    }

    return 0;
}

static const char BASE58_ALPHABET[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C',
                                       'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
                                       'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
                                       'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
                                       'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

int encode_base58(const void *in, size_t length, char *out, size_t maxoutlen) {
    uint8_t tmp[64];
    uint8_t buffer[64];
    uint8_t j;
    size_t start_at;
    size_t zero_count = 0;
    if (length > sizeof(tmp)) {
        return INVALID_PARAMETER;
    }
    memmove(tmp, in, length);
    while ((zero_count < length) && (tmp[zero_count] == 0)) {
        ++zero_count;
    }
    j = 2 * length;
    start_at = zero_count;
    while (start_at < length) {
        uint16_t remainder = 0;
        size_t div_loop;
        for (div_loop = start_at; div_loop < length; div_loop++) {
            uint16_t digit256 = (uint16_t) (tmp[div_loop] & 0xff);
            uint16_t tmp_div = remainder * 256 + digit256;
            tmp[div_loop] = (uint8_t) (tmp_div / 58);
            remainder = (tmp_div % 58);
        }
        if (tmp[start_at] == 0) {
            ++start_at;
        }
        buffer[--j] = (uint8_t) BASE58_ALPHABET[remainder];
    }
    while ((j < (2 * length)) && (buffer[j] == BASE58_ALPHABET[0])) {
        ++j;
    }
    while (zero_count-- > 0) {
        buffer[--j] = BASE58_ALPHABET[0];
    }
    length = 2 * length - j;
    if (maxoutlen < length + 1) {
        return EXCEPTION_OVERFLOW;
    }
    memmove(out, (buffer + j), length);
    out[length] = '\0';
    return 0;
}

int print_i64(int64_t i64, char *out, size_t out_length) {
    BAIL_IF(out_length < 1);
    uint64_t u64 = (uint64_t) i64;
    if (i64 < 0) {
        out[0] = '-';
        out++;
        out_length--;
        u64 = (u64 ^ 0xffffffffffffffff) + 1;
    }
    return print_u64(u64, out, out_length);
}

int print_u64(uint64_t u64, char *out, size_t out_length) {
    BAIL_IF(out_length > INT_MAX);
    uint64_t dVal = u64;
    int outlen = (int) out_length;
    int i = 0;
    int j = 0;

    if (i < (outlen - 1)) {
        do {
            if (dVal > 0) {
                out[i] = (dVal % 10) + '0';
                dVal /= 10;
            } else {
                out[i] = '0';
            }
            i++;
        } while (dVal > 0 && i < outlen);
    }

    BAIL_IF(i >= outlen);

    out[i--] = '\0';

    for (; j < i; j++, i--) {
        int tmp = out[j];
        out[j] = out[i];
        out[i] = tmp;
    }

    return 0;
}

int print_timestamp(int64_t timestamp, char *out, size_t out_length) {
    return rfc3339_format(out, out_length, timestamp);
}
