#include "profile.h"

#include <CommonCrypto/CommonDigest.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Common factory record stream, with only the six-byte factory MAC removed
 * before hashing. This is a layout fingerprint, not any unit's NVM hash.
 * Other layouts must receive their own reviewed support profile.
 */
static const uint8_t factory_layout_sha[32] = {
    0x92,0x46,0x9c,0xe9,0x5d,0xb0,0x69,0xc9,
    0x7a,0x27,0x82,0xf2,0x6a,0xad,0x82,0x49,
    0x54,0xf0,0x0f,0xae,0x11,0x17,0xa7,0x49,
    0xc6,0xb8,0x2a,0x47,0x06,0xb0,0xa1,0xce
};
static const uint8_t startup_record[4] = {0x20,0xe8,0x54,0x00};

void dubfix_sha256(const void *data, size_t size, uint8_t out[32])
{
    const uint8_t *p = data;
    CC_SHA256_CTX context;
    (void)CC_SHA256_Init(&context);
    while (size) {
        CC_LONG part = size > UINT_MAX ? UINT_MAX : (CC_LONG)size;
        (void)CC_SHA256_Update(&context, p, part);
        p += part;
        size -= part;
    }
    (void)CC_SHA256_Final(out, &context);
}

static int valid_mac(const uint8_t mac[6])
{
    static const uint8_t zero[6] = {0};
    static const uint8_t privacy[6] = {0x02,0,0,0,0,0};
    return !(mac[0] & 1u) && memcmp(mac, zero, sizeof zero) &&
           memcmp(mac, privacy, sizeof privacy);
}

static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int dubfix_parse_mac(const char *text, uint8_t out[6])
{
    uint8_t parsed[6];
    if (!text || !out || strlen(text) != 17) return -1;
    for (size_t i = 0; i < 6; ++i) {
        int hi = hex_digit((unsigned char)text[i * 3]);
        int lo = hex_digit((unsigned char)text[i * 3 + 1]);
        if (hi < 0 || lo < 0 || (i < 5 && text[i * 3 + 2] != ':')) return -1;
        parsed[i] = (uint8_t)((hi << 4) | lo);
    }
    if (!valid_mac(parsed)) return -1;
    memcpy(out, parsed, sizeof parsed);
    return 0;
}

void dubfix_mac_string(const uint8_t mac[6], char out[18])
{
    (void)snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void dubfix_hash_string(const uint8_t hash[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out[i * 2] = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 15u];
    }
    out[64] = '\0';
}

int dubfix_parse_hash(const char *text, uint8_t out[32])
{
    uint8_t parsed[32];
    if (!text || !out || strlen(text) != 64) return -1;
    for (size_t i = 0; i < 32; ++i) {
        int hi = hex_digit((unsigned char)text[i * 2]);
        int lo = hex_digit((unsigned char)text[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        parsed[i] = (uint8_t)((hi << 4) | lo);
    }
    memcpy(out, parsed, sizeof parsed);
    return 0;
}

static void set_reason(char *reason, size_t size, const char *message)
{
    if (reason && size) (void)snprintf(reason, size, "%s", message);
}

static int unsupported(struct dubfix_plan *plan, char *reason,
                       size_t size, const char *message)
{
    if (plan) {
        memset(plan, 0, sizeof *plan);
        plan->state = DUBFIX_UNSUPPORTED;
    }
    set_reason(reason, size, message);
    return -1;
}

int dubfix_make_plan(const uint8_t before[DUBFIX_OTP_BYTES],
                     struct dubfix_plan *plan, char *reason, size_t reason_size)
{
    size_t offset = 0, records = 0, fix_records = 0;
    uint8_t mac[6] = {0}, normalized[DUBFIX_OFFSET], layout_sha[32];
    struct dubfix_plan result = {0};
    if (!before || !plan)
        return unsupported(plan, reason, reason_size, "Missing image or plan output.");

    /* Parse only customer autoload records. Payload is opaque: an FF in a
     * descriptor is not a terminator, and a byte pattern inside payload is not
     * another command. No padding, unknown tags or address wrap is accepted.
     */
    while (offset < DUBFIX_MAIN_BYTES && before[offset] != 0xff) {
        size_t length;
        uint32_t address;
        unsigned bank = before[offset] >> 5;
        if (bank != 1 && bank != 2)
            return unsupported(plan, reason, reason_size, "Unknown autoload record type.");
        length = (before[offset] & 31u) + 1u;
        if (DUBFIX_MAIN_BYTES - offset < 3u ||
            length > DUBFIX_MAIN_BYTES - offset - 3u)
            return unsupported(plan, reason, reason_size, "Truncated autoload record.");
        address = ((uint32_t)before[offset + 1] << 8) | before[offset + 2];
        if (address + length > 0x10000u)
            return unsupported(plan, reason, reason_size, "Autoload record address wraps.");
        if (!records) {
            if (bank != 1 || address != 0xc000u || length != 6u)
                return unsupported(plan, reason, reason_size, "Factory MAC record is missing.");
            memcpy(mac, before + offset + 3u, sizeof mac);
            if (!valid_mac(mac))
                return unsupported(plan, reason, reason_size, "Invalid factory unicast MAC.");
        }
        if (bank == 1 && address <= 0xe854u && address + length > 0xe854u) {
            if (offset != DUBFIX_OFFSET || length != 1u ||
                memcmp(before + offset, startup_record, sizeof startup_record))
                return unsupported(plan, reason, reason_size,
                                   "Conflicting or misplaced CPCR startup record.");
            ++fix_records;
        }
        ++records;
        offset += 3u + length;
    }
    if (offset >= DUBFIX_MAIN_BYTES)
        return unsupported(plan, reason, reason_size, "Missing autoload terminator.");
    for (size_t i = offset; i < DUBFIX_MAIN_BYTES; ++i)
        if (before[i] != 0xff)
            return unsupported(plan, reason, reason_size,
                               "Customer area contains data after its terminator.");
    if (offset % 4u)
        return unsupported(plan, reason, reason_size, "Autoload append point is not aligned.");
    if (!((offset == DUBFIX_OFFSET && records == 12u && fix_records == 0u) ||
          (offset == DUBFIX_OFFSET + 4u && records == 13u && fix_records == 1u)))
        return unsupported(plan, reason, reason_size, "Factory layout is unsupported.");

    memcpy(normalized, before, sizeof normalized);
    memset(normalized + 3u, 0, sizeof mac);
    dubfix_sha256(normalized, sizeof normalized, layout_sha);
    if (memcmp(layout_sha, factory_layout_sha, sizeof layout_sha))
        return unsupported(plan, reason, reason_size, "Factory layout fingerprint is unsupported.");

    memcpy(result.mac, mac, sizeof mac);
    memcpy(result.after, before, sizeof result.after);
    dubfix_sha256(before, DUBFIX_OTP_BYTES, result.before_sha);
    if (!fix_records) {
        /* The initial support profile fixes an already aligned append point.
         * Do not round up over a terminator or insert unverified NOP padding.
         * Both the candidate and the following DWORD must be blank in bounds.
         */
        if (offset + 8u > DUBFIX_MAIN_BYTES)
            return unsupported(plan, reason, reason_size, "Insufficient customer append space.");
        for (size_t i = offset; i < offset + 8u; ++i)
            if (before[i] != 0xff)
                return unsupported(plan, reason, reason_size, "Append area is not blank.");
        memcpy(result.after + offset, startup_record, sizeof startup_record);
        result.state = DUBFIX_FIXABLE;
        set_reason(reason, reason_size, "Known factory layout; one startup record can be appended.");
    } else {
        result.state = DUBFIX_ALREADY_FIXED;
        set_reason(reason, reason_size, "Known startup fix is already present; no programming needed.");
    }
    dubfix_sha256(result.after, DUBFIX_OTP_BYTES, result.after_sha);
    *plan = result;
    return 0;
}
