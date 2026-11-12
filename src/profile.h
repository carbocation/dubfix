#ifndef DUBFIX_PROFILE_H
#define DUBFIX_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#define DUBFIX_OTP_BYTES 2048u
#define DUBFIX_MAIN_BYTES 0x508u
#define DUBFIX_OFFSET 0x6cu

enum dubfix_profile_state {
    DUBFIX_UNSUPPORTED = -1,
    DUBFIX_FIXABLE = 0,
    DUBFIX_ALREADY_FIXED = 1
};

struct dubfix_plan {
    uint8_t mac[6];
    uint8_t before_sha[32];
    uint8_t after_sha[32];
    uint8_t after[DUBFIX_OTP_BYTES];
    enum dubfix_profile_state state;
};

/* Pure, offline NVM classification. Hardware VID/PID, revision, chip and USB
 * configuration must additionally be checked by the hardware transaction.
 * Returns 0 for FIXABLE or ALREADY_FIXED, -1 for UNSUPPORTED. Unsupported
 * output has no usable image or hashes; a reason is provided when possible.
 */
int dubfix_make_plan(const uint8_t before[DUBFIX_OTP_BYTES],
                     struct dubfix_plan *plan, char *reason, size_t reason_size);
void dubfix_sha256(const void *data, size_t size, uint8_t out[32]);

/* Exact colon-separated MAC / 64-hex SHA-256 fields; no surrounding whitespace,
 * separators other than colons, or trailing data. MACs must be nonzero unicast
 * and cannot be the privacy placeholder 02:00:00:00:00:00. Hex is case-insensitive.
 * Parsers return 0 on success, -1 on failure and leave output unchanged on error.
 */
int dubfix_parse_mac(const char *text, uint8_t out[6]);
void dubfix_mac_string(const uint8_t mac[6], char out[18]);
void dubfix_hash_string(const uint8_t hash[32], char out[65]);
int dubfix_parse_hash(const char *text, uint8_t out[32]);

#endif
