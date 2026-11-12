#include "fixture.h"
#include "profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned assertions;
#define CHECK(test) do { \
    ++assertions; \
    if (!(test)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #test); \
        exit(1); \
    } \
} while (0)

static const uint8_t fix[4] = {0x20,0xe8,0x54,0x00};

static void rejected(const uint8_t image[DUBFIX_OTP_BYTES], const char *reason_part)
{
    struct dubfix_plan plan, empty = {0};
    char reason[160];
    memset(&plan, 0xa5, sizeof plan);
    memset(reason, 0xa5, sizeof reason);
    CHECK(dubfix_make_plan(image, &plan, reason, sizeof reason) == -1);
    CHECK(plan.state == DUBFIX_UNSUPPORTED);
    CHECK(reason[0] && memchr(reason, '\0', sizeof reason));
    CHECK(strstr(reason, reason_part) != NULL);
    empty.state = DUBFIX_UNSUPPORTED;
    CHECK(!memcmp(plan.mac, empty.mac, sizeof plan.mac));
    CHECK(!memcmp(plan.before_sha, empty.before_sha, sizeof plan.before_sha));
    CHECK(!memcmp(plan.after_sha, empty.after_sha, sizeof plan.after_sha));
    CHECK(!memcmp(plan.after, empty.after, sizeof plan.after));
}

static void successful_plan(void)
{
    uint8_t image[DUBFIX_OTP_BYTES], saved[DUBFIX_OTP_BYTES], hash[32];
    struct dubfix_plan plan, already;
    char reason[160];
    dubfix_test_fixture(image);
    memcpy(saved, image, sizeof saved);
    CHECK(!dubfix_make_plan(image, &plan, reason, sizeof reason));
    CHECK(plan.state == DUBFIX_FIXABLE);
    CHECK(!memcmp(plan.mac, image + 3, 6));
    CHECK(!memcmp(image, saved, sizeof image));
    CHECK(!memcmp(plan.after + DUBFIX_OFFSET, fix, sizeof fix));
    size_t changes = 0;
    for (size_t i = 0; i < sizeof image; ++i) {
        if (image[i] != plan.after[i]) {
            CHECK(i >= DUBFIX_OFFSET && i < DUBFIX_OFFSET + sizeof fix);
            CHECK(image[i] == 0xff);
            ++changes;
        }
    }
    CHECK(changes == sizeof fix);
    dubfix_sha256(image, sizeof image, hash);
    CHECK(!memcmp(plan.before_sha, hash, sizeof hash));
    dubfix_sha256(plan.after, sizeof plan.after, hash);
    CHECK(!memcmp(plan.after_sha, hash, sizeof hash));
    CHECK(memcmp(plan.before_sha, plan.after_sha, sizeof hash));
    CHECK(!dubfix_make_plan(plan.after, &already, reason, sizeof reason));
    CHECK(already.state == DUBFIX_ALREADY_FIXED);
    CHECK(!memcmp(already.after, plan.after, sizeof already.after));
    CHECK(!memcmp(already.before_sha, plan.after_sha, sizeof hash));
    CHECK(!memcmp(already.before_sha, already.after_sha, sizeof hash));

    /* Per-unit reserved/calibration bytes are private, unrestricted by the
     * shared layout fingerprint, and copied exactly. No tail byte is a plan
     * instruction, including bytes that resemble the startup record.
     */
    for (size_t i = DUBFIX_MAIN_BYTES; i < sizeof image; ++i)
        image[i] = (uint8_t)(i * 37u + 11u);
    memcpy(image + DUBFIX_MAIN_BYTES + 17u, fix, sizeof fix);
    CHECK(!dubfix_make_plan(image, &plan, reason, sizeof reason));
    CHECK(!memcmp(image + DUBFIX_MAIN_BYTES, plan.after + DUBFIX_MAIN_BYTES,
                  sizeof image - DUBFIX_MAIN_BYTES));
    CHECK(!dubfix_make_plan(plan.after, &already, NULL, 0));
    CHECK(already.state == DUBFIX_ALREADY_FIXED);

    static const uint8_t macs[][6] = {
        {0x02,0x11,0x22,0x33,0x44,0x55},
        {0x00,0x11,0x22,0x33,0x44,0x66},
        {0xfe,0x10,0x20,0x30,0x40,0x50},
        {0x02,0,0,0,0,1}
    };
    for (size_t i = 0; i < sizeof macs / sizeof macs[0]; ++i) {
        dubfix_test_fixture(image);
        memcpy(image + 3u, macs[i], sizeof macs[i]);
        CHECK(!dubfix_make_plan(image, &plan, reason, sizeof reason));
        CHECK(plan.state == DUBFIX_FIXABLE);
        CHECK(!memcmp(plan.mac, macs[i], sizeof macs[i]));
        CHECK(!memcmp(plan.after + 3u, macs[i], sizeof macs[i]));
    }
}

static void invalid_profiles(void)
{
    uint8_t image[DUBFIX_OTP_BYTES];
    dubfix_test_fixture(image);
    image[107] ^= 1u;
    rejected(image, "fingerprint");
    dubfix_test_fixture(image);
    image[9] = 0;
    rejected(image, "type");
    dubfix_test_fixture(image);
    image[9] = 0x60;
    rejected(image, "type");
    dubfix_test_fixture(image);
    image[0] = 0x45;
    rejected(image, "MAC record");
    dubfix_test_fixture(image);
    image[0] = 0x24;
    rejected(image, "MAC record");
    dubfix_test_fixture(image);
    image[2] = 1;
    rejected(image, "MAC record");
    dubfix_test_fixture(image);
    image[19] = 0xff;
    rejected(image, "after its terminator");
    dubfix_test_fixture(image);
    image[DUBFIX_OFFSET + 2u] = 0;
    rejected(image, "after its terminator");
    dubfix_test_fixture(image);
    image[DUBFIX_MAIN_BYTES - 1u] = 0;
    rejected(image, "after its terminator");

    /* Existing CPCR writes, overlapping spans, duplicate records and writes
     * after the accepted record must never be treated as a fresh append.
     */
    dubfix_test_fixture(image);
    image[20] = 0xe8; image[21] = 0x54;
    rejected(image, "CPCR");
    dubfix_test_fixture(image);
    image[24] = 0xe8; image[25] = 0x50;
    rejected(image, "CPCR");
    dubfix_test_fixture(image);
    memcpy(image + DUBFIX_OFFSET, fix, sizeof fix);
    image[DUBFIX_OFFSET + 3u] = 1;
    rejected(image, "CPCR");
    dubfix_test_fixture(image);
    memcpy(image + DUBFIX_OFFSET, fix, sizeof fix);
    memcpy(image + DUBFIX_OFFSET + 4u, fix, sizeof fix);
    rejected(image, "CPCR");
    dubfix_test_fixture(image);
    memcpy(image + DUBFIX_OFFSET + 4u, fix, sizeof fix);
    rejected(image, "after its terminator");
    dubfix_test_fixture(image);
    memcpy(image + DUBFIX_OFFSET, fix, sizeof fix);
    image[DUBFIX_OFFSET + 8u] = 0;
    rejected(image, "after its terminator");
    dubfix_test_fixture(image);
    image[DUBFIX_OFFSET] = 0x40;
    image[DUBFIX_OFFSET + 1u] = 0xc0;
    image[DUBFIX_OFFSET + 2u] = 0;
    image[DUBFIX_OFFSET + 3u] = 0;
    rejected(image, "layout");
    dubfix_test_fixture(image);
    image[101] = 0x24;
    image[DUBFIX_OFFSET] = 0;
    rejected(image, "not aligned");

    static const uint8_t bad_macs[][6] = {
        {0,0,0,0,0,0}, {0x02,0,0,0,0,0},
        {0x01,0x11,0x22,0x33,0x44,0x55},
        {0xff,0xff,0xff,0xff,0xff,0xff}
    };
    for (size_t i = 0; i < sizeof bad_macs / sizeof bad_macs[0]; ++i) {
        dubfix_test_fixture(image);
        memcpy(image + 3u, bad_macs[i], sizeof bad_macs[i]);
        rejected(image, "unicast MAC");
    }
    memset(image, 0xff, sizeof image);
    rejected(image, "layout");
}

static void boundary_records(void)
{
    uint8_t image[DUBFIX_OTP_BYTES];
    /* A valid MAC record followed by enough bounded synthetic records to
     * exercise the physical customer boundary, before fingerprint rejection.
     */
    for (unsigned variant = 0; variant < 3; ++variant) {
        dubfix_test_fixture(image);
        memset(image + 9, 0xff, sizeof image - 9);
        size_t offset = 9;
        size_t target = variant == 0 ? DUBFIX_MAIN_BYTES - 2u :
                        variant == 1 ? DUBFIX_MAIN_BYTES - 3u : DUBFIX_MAIN_BYTES;
        if (variant == 0 || variant == 2) {
            size_t length = variant == 0 ? 2u : 4u;
            image[offset] = (uint8_t)(0x20u | (length - 1u));
            image[offset + 1u] = 0x10; image[offset + 2u] = 0;
            memset(image + offset + 3u, 0, length);
            offset += 3u + length;
        }
        while (offset < target) {
            CHECK(target - offset >= 4u);
            image[offset] = 0x20;
            image[offset + 1u] = 0x10; image[offset + 2u] = 0;
            image[offset + 3u] = 0;
            offset += 4u;
        }
        CHECK(offset == target);
        if (variant < 2) image[offset] = 0x3f;
        rejected(image, variant < 2 ? "Truncated" : "Missing autoload terminator");
    }
    dubfix_test_fixture(image);
    image[9] = 0x21;
    image[10] = 0xff; image[11] = 0xff;
    rejected(image, "address wraps");
}

static void string_helpers(void)
{
    uint8_t mac[6], saved_mac[6], hash[32], expected[32], saved_hash[32];
    char mac_text[18], hash_text[65];
    CHECK(!dubfix_parse_mac("02:11:22:33:44:AA", mac));
    dubfix_mac_string(mac, mac_text);
    CHECK(!strcmp(mac_text, "02:11:22:33:44:aa"));
    memcpy(saved_mac, mac, sizeof mac);
    static const char *bad[] = {
        "", "02:11:22:33:44:5", "2:11:22:33:44:55", "02-11-22-33-44-55",
        "021122334455", "02:11:22:33:44:55 ", " 02:11:22:33:44:55",
        "02:11:22:33:44:gg", "02:11:22:33:44:55\n", "00:00:00:00:00:00",
        "02:00:00:00:00:00", "01:11:22:33:44:55", "ff:ff:ff:ff:ff:ff"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        CHECK(dubfix_parse_mac(bad[i], mac) == -1);
        CHECK(!memcmp(mac, saved_mac, sizeof mac));
    }
    CHECK(dubfix_parse_mac(NULL, mac) == -1);
    CHECK(dubfix_parse_mac(mac_text, NULL) == -1);
    dubfix_sha256("abc", 3, hash);
    dubfix_hash_string(hash, hash_text);
    CHECK(!strcmp(hash_text,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(!dubfix_parse_hash(hash_text, expected));
    CHECK(!memcmp(hash, expected, sizeof hash));
    CHECK(!dubfix_parse_hash(
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", expected));
    memcpy(saved_hash, expected, sizeof expected);
    hash_text[63] = 'x';
    CHECK(dubfix_parse_hash(hash_text, expected) == -1);
    CHECK(!memcmp(expected, saved_hash, sizeof expected));
    CHECK(dubfix_parse_hash("", expected) == -1);
    CHECK(dubfix_parse_hash(NULL, expected) == -1);
    CHECK(dubfix_parse_hash("00", expected) == -1);
    CHECK(dubfix_parse_hash("not a hash", NULL) == -1);

    struct dubfix_plan plan;
    char tiny[1] = {'x'};
    CHECK(dubfix_make_plan(NULL, &plan, tiny, sizeof tiny) == -1);
    CHECK(plan.state == DUBFIX_UNSUPPORTED);
    CHECK(tiny[0] == '\0');
    CHECK(dubfix_make_plan(NULL, NULL, NULL, 0) == -1);
}

int main(void)
{
    successful_plan();
    invalid_profiles();
    boundary_records();
    string_helpers();
    printf("profile tests: %u assertions passed\n", assertions);
    return 0;
}
