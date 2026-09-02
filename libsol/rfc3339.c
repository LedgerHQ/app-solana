/*
 * Copyright (c) 2014 Christian Hansen <chansen@cpan.org>
 * <https://github.com/chansen/c-timestamp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stddef.h>
#include "rfc3339.h"
#include "util.h"

static const uint16_t DayOffset[13] = {0, 306, 337, 0, 31, 61, 92, 122, 153, 184, 214, 245, 275};

/* Rata Die algorithm by Peter Baum */

static int rdn_to_ymd(uint32_t rdn, uint16_t *yp, uint16_t *mp, uint16_t *dp) {
    uint32_t Z, H, A, B;
    uint32_t y, m, d;

    Z = rdn + 306;
    H = 100 * Z - 25;
    A = H / 3652425;
    B = A - (A >> 2);
    y = (100 * B + H) / 36525;
    d = B + Z - (1461 * y >> 2);
    m = (535 * d + 48950) >> 14;
    if (m > 12) {
        y++;
        m -= 12;
    }

    // Test m before indexing DayOffset, the array only holds entries 0 to 12
    if (y > 9999 || m > 12 || d > (31U + DayOffset[m])) {
        PRINTF("Day number does not map to a displayable date, y=%u m=%u d=%u\n", y, m, d);
        return 1;
    }

    *yp = (uint16_t) y;
    *mp = (uint16_t) m;
    *dp = (uint16_t) (d - DayOffset[m]);

    return 0;
}

#define EPOCH INT64_C(62135683200) /* 1970-01-01 00:00:00 */

/* First Rata Die day number after 9999-12-31, the latest date rdn_to_ymd can render */
#define MAX_RDN_DAYS INT64_C(3652060)
/* 0000-12-31 00:00:00, the earliest date rdn_to_ymd can render */
#define MIN_FORMAT_SECONDS (-EPOCH)
/* 9999-12-31 23:59:59 */
#define MAX_FORMAT_SECONDS (MAX_RDN_DAYS * INT64_C(86400) - EPOCH - 1)

// Whether rfc3339_format can render the timestamp as a YYYY-MM-DD hh:mm:ss date
bool rfc3339_is_displayable(int64_t seconds) {
    bool displayable = (seconds >= MIN_FORMAT_SECONDS && seconds <= MAX_FORMAT_SECONDS);
    if (!displayable) {
        PRINTF("Timestamp outside displayable range, seconds=%lld\n", seconds);
    }
    return displayable;
}

int rfc3339_format(char *dst, size_t len, int64_t seconds) {
    unsigned char *p;
    uint64_t sec;
    uint32_t rdn, v;
    uint16_t y, m, d;
    size_t dlen;

    PRINTF("rfc3339_format seconds=%lld\n", seconds);

    dlen = sizeof("YYYY-MM-DD hh:mm:ss") - 1;
    BAIL_IF(dlen >= len);

    // Reject out of range values before the addition below, so it cannot overflow
    if (!rfc3339_is_displayable(seconds)) {
        return 1;
    }

    sec = (uint64_t) (seconds + EPOCH);
    rdn = (uint32_t) (sec / 86400);

    BAIL_IF(rdn_to_ymd(rdn, &y, &m, &d) != 0);

    /*
     *           1
     * 0123456789012345678
     * YYYY-MM-DDThh:mm:ss
     */
    p = (unsigned char *) dst;
    v = sec % 86400;
    p[18] = '0' + (v % 10);
    v /= 10;
    p[17] = '0' + (v % 6);
    v /= 6;
    p[16] = ':';
    p[15] = '0' + (v % 10);
    v /= 10;
    p[14] = '0' + (v % 6);
    v /= 6;
    p[13] = ':';
    p[12] = '0' + (v % 10);
    v /= 10;
    p[11] = '0' + (v % 10);
    p[10] = ' ';
    p[9] = '0' + (d % 10);
    d /= 10;
    p[8] = '0' + (d % 10);
    p[7] = '-';
    p[6] = '0' + (m % 10);
    m /= 10;
    p[5] = '0' + (m % 10);
    p[4] = '-';
    p[3] = '0' + (y % 10);
    y /= 10;
    p[2] = '0' + (y % 10);
    y /= 10;
    p[1] = '0' + (y % 10);
    y /= 10;
    p[0] = '0' + (y % 10);
    p += 19;

    *p = 0;
    return 0;
}
