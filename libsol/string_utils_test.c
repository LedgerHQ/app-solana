#include "include/sol/string_utils.h"
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>

void test_is_ascii(){
    uint8_t message[] = "normal ascii text";
    //                             don't count 0x00 byte at the end
    assert(is_data_ascii(message, sizeof(message) -1 ) == true);
}

void test_is_ascii_invalid_end_char(){
    uint8_t message[] = "normal ascii text";

    //Null terminated string should not be recognized as ascii
    assert(is_data_ascii(message, sizeof(message) ) == false);
}

void test_is_ascii_invalid_emoji(){
    uint8_t message[] = "👍";

    assert(is_data_ascii(message, sizeof(message) ) == false);
}

void test_is_ascii_invalid_null(){
    uint8_t* message = NULL;
    assert(is_data_ascii(message, sizeof(message)) == false);
}





// test if emoji is going to be recognized as utf8 string
void test_is_utf8(){
    uint8_t message[] = "👍";

    assert(is_data_utf8(message, sizeof(message) ) == true);
}

void test_is_utf8_2(){
    uint8_t message[] = "żółć 안녕하세요 привет";

    assert(is_data_ascii(message, sizeof(message) -1 ) == false);//And we ignore null terminator
    assert(is_data_utf8(message, sizeof(message) ) == true);
}

void test_is_utf8_invalid_1(){
    //Invalid Sequence Identifier
    uint8_t message[] = {0xa0, 0xa1};

    assert(is_data_utf8(message, sizeof(message) ) == false);
}

void test_is_utf8_invalid_overlong(){
    // Invalid UTF-8 (overlong)
    uint8_t message[] = { 0xC0, 0xAF};
    uint8_t message2[] = { 0xC0, 0x80 };

    assert(is_data_utf8(message, sizeof(message) ) == false);
    assert(is_data_utf8(message2, sizeof(message2) ) == false);
}

void test_is_utf8_invalid_surrogate(){
    // Invalid UTF-8 (surrogate)
    uint8_t message[] = { 0xED, 0xA0, 0x80};

    assert(is_data_utf8(message, sizeof(message) ) == false);
}

void test_is_utf8_invalid_3(){
    uint8_t message1[] = { 0x80 };  // Invalid UTF-8 (starts with 10xxxxxx)
    uint8_t message2[] = { 0xF4, 0x90, 0x80, 0x80 };  // Invalid UTF-8 (> U+10FFFF)

    assert(is_data_utf8(message1, sizeof(message1) ) == false);
    assert(is_data_utf8(message2, sizeof(message2) ) == false);

}

void test_is_utf8_invalid_null(){
    uint8_t* message = NULL;

    assert(is_data_utf8(message, sizeof(message) ) == false);
}


int main(){
    test_is_ascii();
    test_is_ascii_invalid_end_char();
    test_is_ascii_invalid_emoji();
    test_is_ascii_invalid_null();

    test_is_utf8();
    test_is_utf8_2();
    test_is_utf8_invalid_1();
    test_is_utf8_invalid_overlong();
    test_is_utf8_invalid_surrogate();
    test_is_utf8_invalid_3();
    test_is_utf8_invalid_null();

    printf("passed\n");
    return 0;
}