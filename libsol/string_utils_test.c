#include "include/sol/string_utils.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>

void test_is_ascii() {
    uint8_t message[] = "normal ascii text";
    //                             don't count 0x00 byte at the end
    assert(is_data_ascii(message, sizeof(message) - 1) == true);
}

void test_is_ascii_invalid_end_char() {
    uint8_t message[] = "normal ascii text";

    // Null terminated string should not be recognized as ascii
    assert(is_data_ascii(message, sizeof(message)) == false);
}

void test_is_ascii_invalid_emoji() {
    uint8_t message[] = "👍";

    assert(is_data_ascii(message, sizeof(message)) == false);
}

void test_is_ascii_invalid_null() {
    uint8_t *message = NULL;
    assert(is_data_ascii(message, sizeof(message)) == false);
}

// test if emoji is going to be recognized as utf8 string
void test_is_utf8() {
    uint8_t message[] = "👍";

    assert(is_data_utf8(message, sizeof(message)) == true);
}

void test_is_utf8_2() {
    uint8_t message[] = "żółć 안녕하세요 привет";

    assert(is_data_ascii(message, sizeof(message) - 1) == false);  // And we ignore null terminator
    assert(is_data_utf8(message, sizeof(message)) == true);
}

void test_is_utf8_invalid_1() {
    // Invalid Sequence Identifier
    uint8_t message[] = {0xa0, 0xa1};

    assert(is_data_utf8(message, sizeof(message)) == false);
}

void test_is_utf8_invalid_overlong() {
    // Invalid UTF-8 (overlong)
    uint8_t message[] = {0xC0, 0xAF};
    uint8_t message2[] = {0xC0, 0x80};

    assert(is_data_utf8(message, sizeof(message)) == false);
    assert(is_data_utf8(message2, sizeof(message2)) == false);
}

void test_is_utf8_invalid_surrogate() {
    // Invalid UTF-8 (surrogate)
    uint8_t message[] = {0xED, 0xA0, 0x80};

    assert(is_data_utf8(message, sizeof(message)) == false);
}

void test_is_utf8_invalid_3() {
    uint8_t message1[] = {0x80};                    // Invalid UTF-8 (starts with 10xxxxxx)
    uint8_t message2[] = {0xF4, 0x90, 0x80, 0x80};  // Invalid UTF-8 (> U+10FFFF)

    assert(is_data_utf8(message1, sizeof(message1)) == false);
    assert(is_data_utf8(message2, sizeof(message2)) == false);
}

void test_is_utf8_invalid_null() {
    uint8_t *message = NULL;

    assert(is_data_utf8(message, sizeof(message)) == false);
}

void test_encode_text_ascii_valid() {
    uint8_t message[] = "hello world";
    char out[32];
    assert(encode_text(message, sizeof(message) - 1, true, out, sizeof(out)) == 11);
    assert(strcmp(out, "hello world") == 0);
}

void test_encode_text_ascii_rejects_control() {
    // Newline and DEL are control bytes and must be rejected even in ASCII mode.
    uint8_t newline[] = {'a', 0x0A, 'b'};
    uint8_t del[] = {'a', 0x7F, 'b'};
    char out[32];
    assert(encode_text(newline, sizeof(newline), true, out, sizeof(out)) == -1);
    assert(encode_text(del, sizeof(del), true, out, sizeof(out)) == -1);
}

void test_encode_text_ascii_rejects_high() {
    uint8_t message[] = "👍";
    char out[32];
    assert(encode_text(message, sizeof(message) - 1, true, out, sizeof(out)) == -1);
}

void test_encode_text_utf8_valid() {
    uint8_t message[] = "żółć";
    char out[32];
    int written = encode_text(message, sizeof(message) - 1, false, out, sizeof(out));
    assert(written == (int) (sizeof(message) - 1));
    assert(memcmp(out, message, sizeof(message) - 1) == 0);
}

void test_encode_text_utf8_rejects_malformed() {
    // Bare continuation byte is not well-formed UTF-8.
    uint8_t message[] = {0x80};
    char out[32];
    assert(encode_text(message, sizeof(message), false, out, sizeof(out)) == -1);
}

void test_encode_text_utf8_rejects_nul() {
    // An embedded NUL would truncate the displayed C-string, so it is rejected.
    uint8_t nul[] = {'a', 0x00, 'b'};
    char out[32];
    assert(encode_text(nul, sizeof(nul), false, out, sizeof(out)) == -1);
}

void test_encode_text_utf8_accepts_control_code_points() {
    // The StringEncoding spec filters non-printable bytes for ASCII only; UTF-8 requires just
    // well-formed UTF-8, so C0 (newline), DEL, and C1 (0xC2 0x85 = U+0085 NEL) pass through.
    uint8_t newline[] = {'a', 0x0A, 'b'};
    uint8_t del[] = {'a', 0x7F, 'b'};
    uint8_t nel[] = {'a', 0xC2, 0x85, 'b'};
    char out[32];
    assert(encode_text(newline, sizeof(newline), false, out, sizeof(out)) == 3);
    assert(encode_text(del, sizeof(del), false, out, sizeof(out)) == 3);
    assert(encode_text(nel, sizeof(nel), false, out, sizeof(out)) == 4);
}

void test_encode_text_rejects_overflow() {
    uint8_t message[] = "hello";
    char out[4];
    assert(encode_text(message, sizeof(message) - 1, true, out, sizeof(out)) == -1);
}

int main() {
    RUN_TEST(test_is_ascii);
    RUN_TEST(test_is_ascii_invalid_end_char);
    RUN_TEST(test_is_ascii_invalid_emoji);
    RUN_TEST(test_is_ascii_invalid_null);

    RUN_TEST(test_is_utf8);
    RUN_TEST(test_is_utf8_2);
    RUN_TEST(test_is_utf8_invalid_1);
    RUN_TEST(test_is_utf8_invalid_overlong);
    RUN_TEST(test_is_utf8_invalid_surrogate);
    RUN_TEST(test_is_utf8_invalid_3);
    RUN_TEST(test_is_utf8_invalid_null);

    RUN_TEST(test_encode_text_ascii_valid);
    RUN_TEST(test_encode_text_ascii_rejects_control);
    RUN_TEST(test_encode_text_ascii_rejects_high);
    RUN_TEST(test_encode_text_utf8_valid);
    RUN_TEST(test_encode_text_utf8_rejects_malformed);
    RUN_TEST(test_encode_text_utf8_rejects_nul);
    RUN_TEST(test_encode_text_utf8_accepts_control_code_points);
    RUN_TEST(test_encode_text_rejects_overflow);

    printf("passed\n");
    return 0;
}
