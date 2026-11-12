#ifndef DUBFIX_TEST_FIXTURE_H
#define DUBFIX_TEST_FIXTURE_H

#include "profile.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Synthetic test image assembled from the generic factory record schema.
 * The MAC is invented and the entire calibration/reserved tail is blank.
 * This is not a device backup and must never be programmed onto hardware.
 */
static inline void dubfix_test_fixture(uint8_t out[DUBFIX_OTP_BYTES])
{
    static const struct {
        uint8_t bank, length;
        uint16_t address;
        uint8_t payload[32];
    } records[] = {
        {1,6,0xc000,{0x02,0x11,0x22,0x33,0x44,0x55}},
        {2,2,0xc008,{0x01,0x20}},
        {2,2,0xc014,{0x01,0xb3}},
        {1,1,0xe83c,{0x07}},
        {1,8,0xdd8a,{0x15,0x12,0x02,0x12,0x2b,0x02,0x2b,0x00}},
        {2,9,0xc900,{0xff,0x0e,0x03,'D','-','L','i','n','k'}},
        {2,25,0xc930,{0xff,0x2e,0x03,'D','U','B','E','2','5','0',' ',
                      '2','.','5','G','b','E',' ','A','d','a','p','t','e','r'}},
        {1,1,0xe85b,{0x02}},
        {1,1,0xe822,{0x08}},
        {2,1,0xc012,{0x86}},
        {2,12,0xc9c0,{0xff,0x14,0x03,'0','0','1','0','0','0','0','0','1'}},
        {1,4,0xd3a0,{0x0d,0x02,0xfd,0x03}}
    };
    size_t offset = 0;
    memset(out, 0xff, DUBFIX_OTP_BYTES);
    for (size_t i = 0; i < sizeof records / sizeof records[0]; ++i) {
        out[offset] = (uint8_t)((records[i].bank << 5) | (records[i].length - 1u));
        out[offset + 1] = (uint8_t)(records[i].address >> 8);
        out[offset + 2] = (uint8_t)records[i].address;
        memcpy(out + offset + 3u, records[i].payload, records[i].length);
        offset += 3u + records[i].length;
    }
}

#endif
