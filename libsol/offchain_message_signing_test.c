#include "common_byte_strings.h"
#include "parser.c"
#include "sol/printer.h"
#include "test_utils.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// ── check_offchain_signing_domain ───────────────────────────────────

void test_check_signing_domain_valid() {
    uint8_t buffer[] = {OFFCHAIN_MESSAGE_SIGNING_DOMAIN, 0x42};
    assert(check_offchain_signing_domain(buffer, sizeof(buffer)) == 0);
}

void test_check_signing_domain_wrong() {
    uint8_t buffer[] = {OFFCHAIN_MESSAGE_SIGNING_DOMAIN};
    buffer[0] = 0x00;  // corrupt first byte
    assert(check_offchain_signing_domain(buffer, sizeof(buffer)) != 0);
}

void test_check_signing_domain_too_short() {
    uint8_t buffer[] = {0xff, 0x73, 0x6f};
    assert(check_offchain_signing_domain(buffer, sizeof(buffer)) == -1);
}

// ── is_offchain_application_domain_empty ────────────────────────────

void test_application_domain_empty() {
    OffchainMessageApplicationDomain domain;
    memset(domain.data, 0, sizeof(domain.data));
    assert(is_offchain_application_domain_empty(&domain) == true);
}

void test_application_domain_not_empty() {
    OffchainMessageApplicationDomain domain;
    memset(domain.data, 0, sizeof(domain.data));
    domain.data[31] = 0x01;
    assert(is_offchain_application_domain_empty(&domain) == false);
}

// ── get_offchain_message_header_length ──────────────────────────────

void test_header_length_v0() {
    OffchainMessageHeader header = {0};
    header.version = 0;
    header.signers_length = 1;
    // 16 (domain) + 1 (version) + 1 (signer_count) + 32 (1 signer)
    // + 32 (app_domain) + 1 (format) + 2 (msg_length) = 85
    assert(get_offchain_message_header_length(&header) == 85);
}

void test_header_length_v1() {
    OffchainMessageHeader header = {0};
    header.version = 1;
    header.signers_length = 2;
    // 16 (domain) + 1 (version) + 1 (signer_count) + 64 (2 signers) = 82
    assert(get_offchain_message_header_length(&header) == 82);
}

// ── parse_offchain_message_header ───────────────────────────────────

// Helper: build a V0 offchain message buffer
// domain(16) + version(1) + app_domain(32) + format(1) + signer_count(1) + signer(32) +
// msg_length(2) + body
static size_t build_v0_message(uint8_t *buf,
                               size_t buf_size,
                               const uint8_t *app_domain,
                               uint8_t format,
                               uint8_t signer_count,
                               const uint8_t *signers,
                               uint16_t msg_length,
                               const uint8_t *body,
                               size_t body_length) {
    size_t offset = 0;
    uint8_t domain[] = {OFFCHAIN_MESSAGE_SIGNING_DOMAIN};
    memcpy(buf + offset, domain, 16);
    offset += 16;
    buf[offset++] = 0x00;  // version
    memcpy(buf + offset, app_domain, 32);
    offset += 32;
    buf[offset++] = format;
    buf[offset++] = signer_count;
    memcpy(buf + offset, signers, signer_count * 32);
    offset += signer_count * 32;
    buf[offset++] = msg_length & 0xFF;
    buf[offset++] = (msg_length >> 8) & 0xFF;
    if (body_length > 0) {
        memcpy(buf + offset, body, body_length);
        offset += body_length;
    }
    assert(offset <= buf_size);
    return offset;
}

// Helper: build a V1 offchain message buffer
// domain(16) + version(1) + signer_count(1) + signers(32*n) + body
static size_t build_v1_message(uint8_t *buf,
                               size_t buf_size,
                               uint8_t signer_count,
                               const uint8_t *signers,
                               const uint8_t *body,
                               size_t body_length) {
    size_t offset = 0;
    uint8_t domain[] = {OFFCHAIN_MESSAGE_SIGNING_DOMAIN};
    memcpy(buf + offset, domain, 16);
    offset += 16;
    buf[offset++] = 0x01;  // version
    buf[offset++] = signer_count;
    memcpy(buf + offset, signers, signer_count * 32);
    offset += signer_count * 32;
    if (body_length > 0) {
        memcpy(buf + offset, body, body_length);
        offset += body_length;
    }
    assert(offset <= buf_size);
    return offset;
}

void test_parse_v0_happy_path() {
    uint8_t app_domain[32];
    memset(app_domain, 0xAB, sizeof(app_domain));
    uint8_t signer[32] = {BYTES32_BS58_2};
    uint8_t body[] = "hello";

    uint8_t buf[256];
    size_t len = build_v0_message(buf, sizeof(buf), app_domain, 0, 1, signer, 5, body, 5);

    Parser parser = {buf, len};
    OffchainMessageHeader header;
    assert(parse_offchain_message_header(&parser, &header) == 0);
    assert(header.version == 0);
    assert(header.application_domain != NULL);
    assert(memcmp(header.application_domain->data, app_domain, 32) == 0);
    assert(header.format == 0);
    assert(header.signers_length == 1);
    assert(memcmp(header.signers, signer, 32) == 0);
    assert(header.length == 5);
}

void test_parse_v1_happy_path() {
    // Two signers in ascending lexicographic order
    uint8_t signers[64];
    uint8_t s1[] = {BYTES32_BS58_2};
    uint8_t s2[] = {BYTES32_BS58_3};
    memcpy(signers, s1, 32);
    memcpy(signers + 32, s2, 32);

    uint8_t body[] = "world";
    uint8_t buf[256];
    size_t len = build_v1_message(buf, sizeof(buf), 2, signers, body, 5);

    Parser parser = {buf, len};
    OffchainMessageHeader header;
    assert(parse_offchain_message_header(&parser, &header) == 0);
    assert(header.version == 1);
    assert(header.application_domain == NULL);
    assert(header.format == 0);
    assert(header.signers_length == 2);
    assert(header.length == 5);
}

void test_parse_wrong_domain() {
    uint8_t buf[32];
    memset(buf, 0x00, sizeof(buf));
    Parser parser = {buf, sizeof(buf)};
    OffchainMessageHeader header;
    assert(parse_offchain_message_header(&parser, &header) != 0);
}

void test_parse_v1_signers_not_sorted() {
    // Two signers in DESCENDING order (s3 > s2)
    uint8_t signers[64];
    uint8_t s2[] = {BYTES32_BS58_2};
    uint8_t s3[] = {BYTES32_BS58_3};
    memcpy(signers, s3, 32);       // s3 first (larger)
    memcpy(signers + 32, s2, 32);  // s2 second (smaller)

    uint8_t body[] = "x";
    uint8_t buf[256];
    size_t len = build_v1_message(buf, sizeof(buf), 2, signers, body, 1);

    Parser parser = {buf, len};
    OffchainMessageHeader header;
    assert(parse_offchain_message_header(&parser, &header) == -1);
}

void test_parse_v1_signers_duplicate() {
    // Two identical signers
    uint8_t signers[64];
    uint8_t s2[] = {BYTES32_BS58_2};
    memcpy(signers, s2, 32);
    memcpy(signers + 32, s2, 32);

    uint8_t body[] = "x";
    uint8_t buf[256];
    size_t len = build_v1_message(buf, sizeof(buf), 2, signers, body, 1);

    Parser parser = {buf, len};
    OffchainMessageHeader header;
    assert(parse_offchain_message_header(&parser, &header) == -1);
}

void test_parse_v1_single_signer() {
    // Single signer — no ordering check needed
    uint8_t signer[] = {BYTES32_BS58_5};
    uint8_t body[] = "test";

    uint8_t buf[256];
    size_t len = build_v1_message(buf, sizeof(buf), 1, signer, body, 4);

    Parser parser = {buf, len};
    OffchainMessageHeader header;
    assert(parse_offchain_message_header(&parser, &header) == 0);
    assert(header.signers_length == 1);
    assert(header.length == 4);
}

void test_parse_v0_empty_app_domain() {
    uint8_t app_domain[32];
    memset(app_domain, 0, sizeof(app_domain));
    uint8_t signer[32] = {BYTES32_BS58_2};
    uint8_t body[] = "msg";

    uint8_t buf[256];
    size_t len = build_v0_message(buf, sizeof(buf), app_domain, 1, 1, signer, 3, body, 3);

    Parser parser = {buf, len};
    OffchainMessageHeader header;
    assert(parse_offchain_message_header(&parser, &header) == 0);
    assert(header.version == 0);
    assert(header.format == 1);
    assert(is_offchain_application_domain_empty(header.application_domain) == true);
    assert(header.length == 3);
}

int main() {
    // check_offchain_signing_domain
    RUN_TEST(test_check_signing_domain_valid);
    RUN_TEST(test_check_signing_domain_wrong);
    RUN_TEST(test_check_signing_domain_too_short);

    // is_offchain_application_domain_empty
    RUN_TEST(test_application_domain_empty);
    RUN_TEST(test_application_domain_not_empty);

    // get_offchain_message_header_length
    RUN_TEST(test_header_length_v0);
    RUN_TEST(test_header_length_v1);

    // parse_offchain_message_header
    RUN_TEST(test_parse_v0_happy_path);
    RUN_TEST(test_parse_v1_happy_path);
    RUN_TEST(test_parse_wrong_domain);
    RUN_TEST(test_parse_v1_signers_not_sorted);
    RUN_TEST(test_parse_v1_signers_duplicate);
    RUN_TEST(test_parse_v1_single_signer);
    RUN_TEST(test_parse_v0_empty_app_domain);

    printf("passed\n");
    return 0;
}
