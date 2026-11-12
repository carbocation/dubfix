/*
 * Minimal macOS USB transport for dubfix.
 * Derived from ncmsize by Paul-Louis Charrière (2026), MIT licensed.
 * Upstream revision: 65f57e4e3402c0c4372966e5920f84111731742e.
 * The complete upstream license is retained in transport_macos.c.
 */
#ifndef DUBFIX_TRANSPORT_MACOS_H
#define DUBFIX_TRANSPORT_MACOS_H

#include <stdint.h>
#include <net/if.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOBSD.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <libkern/OSByteOrder.h>

#define MAX_ADAPTERS 16
#define USB_TIMEOUT_MS 1000
#define RTL_REQ_GET_REGS 0x05
#define RTL_MCU_TYPE_PLA 0x0100
#define RTL_PLA_TCR0 0xe610
#define RTL_VERSION_MASK 0x7cf0

struct chip {
    const char *name;
    const char *label;
    const char *later;
    uint16_t release;
    uint16_t version[4];
};

/* Each returned adapter owns one retained usb reference; dev is initially NULL. */
struct adapter {
    io_service_t usb;
    IOUSBDeviceInterface182 **dev;
    char name[IFNAMSIZ];
    unsigned int vid, pid;
    unsigned int release;
    int known;
    unsigned int version;
    const struct chip *chip;
    unsigned int read_size;
    int ifnum;
    uint16_t size_len;
    uint8_t size_tail[4];
};

/* Cached registry enumeration only; candidates are limited to 2001:b301.
 * On failure, no retained adapter references are returned. */
int find_adapters(struct adapter *list);
int number_property(io_registry_entry_t entry, CFStringRef key, unsigned int *val);

/* Creates/releases the user-client interface without detaching Apple's driver.
 * The caller separately owns normal USBDeviceOpen/USBDeviceClose if required. */
int open_device(struct adapter *a);
void close_device(struct adapter *a);

/* One bounded control transfer. The transaction core owns all OUT allowlists. */
int request(struct adapter *a, uint8_t type, uint8_t req, uint16_t value,
            uint16_t index, void *buf, uint16_t len);

/* Version reads require the cached exact 2001:b301 / bcdDevice 3100 profile.
 * Writing still requires the core's separate exact version 7410 guard. */
int identify_chip(struct adapter *a);
/* 0: found; -1: no NCM interface; -2: unreadable/ambiguous descriptors. */
int find_ncm(struct adapter *a);
int get_size(struct adapter *a, unsigned int *size);

#endif
