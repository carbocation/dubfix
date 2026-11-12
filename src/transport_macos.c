/*
 * USB enumeration and read helpers extracted from ncmsize, upstream revision
 * 65f57e4e3402c0c4372966e5920f84111731742e. The extraction limits enumeration
 * to D-Link 2001:b301 and contains no block-size setter or persistent helper.
 *
 * MIT License
 *
 * Copyright (c) 2026 Paul-Louis Charrière
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "transport_macos.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <mach/mach_error.h>

#define DUB_VID 0x2001
#define DUB_PID 0xb301
#define DUB_RELEASE 0x3100
#define DUB_VERSION 0x7410
#define NCM_SUBCLASS 0x0d
#define NCM_FUNCTIONAL_DESC 0x1a
#define NCM_NTB_INPUT_SIZE_8 0x20
#define GET_NTB_INPUT_SIZE 0x85

static const struct chip supported_chip = {
    "rtl8156b", "RTL8156B", NULL, DUB_RELEASE, { DUB_VERSION }
};

static void report(const struct adapter *a, const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "%s: ", a && a->name[0] ? a->name : "adapter");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

int number_property(io_registry_entry_t entry, CFStringRef key, unsigned int *val)
{
    CFTypeRef v;
    int64_t number = 0;
    int ok;

    if (!entry || !key || !val)
        return -1;
    v = IORegistryEntryCreateCFProperty(entry, key, NULL, 0);
    ok = v && CFGetTypeID(v) == CFNumberGetTypeID() &&
         CFNumberGetValue(v, kCFNumberSInt64Type, &number) &&
         number >= 0 && (uint64_t)number <= UINT_MAX;
    if (v)
        CFRelease(v);
    if (!ok)
        return -1;
    *val = (unsigned int)number;
    return 0;
}

static int known_id(io_service_t usb, unsigned int *vid, unsigned int *pid)
{
    *vid = *pid = 0;
    return !number_property(usb, CFSTR(kUSBHostMatchingPropertyVendorID), vid) &&
           !number_property(usb, CFSTR(kUSBHostMatchingPropertyProductID), pid) &&
           *vid == DUB_VID && *pid == DUB_PID;
}

/* Inspect the first USB-device parent, never a hub further up the tree. */
static int ncm_driver(io_service_t ncm, struct adapter *a)
{
    io_registry_entry_t e, parent;
    CFTypeRef name;
    int found;

    memset(a, 0, sizeof(*a));
    a->ifnum = -1;
    if (number_property(ncm, CFSTR("InputSize"), &a->read_size))
        return 0;
    name = IORegistryEntrySearchCFProperty(ncm, kIOServicePlane,
                CFSTR(kIOBSDNameKey), NULL, kIORegistryIterateRecursively);
    found = name && CFGetTypeID(name) == CFStringGetTypeID() &&
            CFStringGetCString(name, a->name, sizeof(a->name), kCFStringEncodingUTF8);
    if (name)
        CFRelease(name);
    if (!found)
        return 0;

    e = ncm;
    if (IOObjectRetain(e) != KERN_SUCCESS)
        return 0;
    while (IORegistryEntryGetParentEntry(e, kIOServicePlane, &parent) == KERN_SUCCESS) {
        IOObjectRelease(e);
        e = parent;
        if (!IOObjectConformsTo(e, kIOUSBHostDeviceClassName))
            continue;
        /* Filter entirely from cached properties before a user client or
         * vendor request can be created for an unrelated adapter. */
        if (!known_id(e, &a->vid, &a->pid) ||
            number_property(e, CFSTR(kUSBHostMatchingPropertyDeviceReleaseNumber),
                            &a->release)) {
            IOObjectRelease(e);
            return 0;
        }
        a->known = 1;
        a->usb = e;
        return 1;
    }
    IOObjectRelease(e);
    return 0;
}

int find_adapters(struct adapter *list)
{
    io_iterator_t it = IO_OBJECT_NULL;
    io_service_t ncm;
    struct adapter candidate;
    int n = 0;

    if (!list)
        return -1;
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
            IOServiceMatching("AppleUSBNCMData"), &it) != KERN_SUCCESS) {
        fputs("cannot list the adapters run by macOS's NCM driver\n", stderr);
        return -1;
    }
    while ((ncm = IOIteratorNext(it))) {
        int found = ncm_driver(ncm, &candidate);
        IOObjectRelease(ncm);
        if (!found)
            continue;
        if (n == MAX_ADAPTERS) {
            close_device(&candidate);
            while (n)
                close_device(&list[--n]);
            IOObjectRelease(it);
            fputs("too many D-Link adapters for a complete inventory\n", stderr);
            return -1;
        }
        list[n++] = candidate;
    }
    IOObjectRelease(it);
    return n;
}

int open_device(struct adapter *a)
{
    IOCFPlugInInterface **plug = NULL;
    SInt32 score = 0;
    kern_return_t kr;
    HRESULT hr;

    if (!a || !a->usb || a->vid != DUB_VID || a->pid != DUB_PID)
        return -1;
    if (a->dev)
        return 0;
    kr = IOCreatePlugInInterfaceForService(a->usb, kIOUSBDeviceUserClientTypeID,
                                         kIOCFPlugInInterfaceID, &plug, &score);
    if (kr != kIOReturnSuccess || !plug) {
        if (plug)
            (*plug)->Release(plug);
        report(a, "cannot create USB interface: %s (0x%08x)",
               mach_error_string(kr), (unsigned int)kr);
        return -1;
    }
    hr = (*plug)->QueryInterface(plug, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID182),
                                (LPVOID *)&a->dev);
    (*plug)->Release(plug);
    if (hr || !a->dev) {
        if (a->dev)
            (*a->dev)->Release(a->dev);
        a->dev = NULL;
        report(a, "cannot create USB interface: no USB device interface");
        return -1;
    }
    return 0;
}

void close_device(struct adapter *a)
{
    if (!a)
        return;
    if (a->dev)
        (*a->dev)->Release(a->dev);
    a->dev = NULL;
    if (a->usb)
        IOObjectRelease(a->usb);
    a->usb = IO_OBJECT_NULL;
}

int request(struct adapter *a, uint8_t type, uint8_t req, uint16_t value,
            uint16_t index, void *buf, uint16_t len)
{
    IOUSBDevRequestTO r = {
        .bmRequestType = type,
        .bRequest = req,
        .wValue = value,
        .wIndex = index,
        .wLength = len,
        .pData = buf,
        .noDataTimeout = USB_TIMEOUT_MS,
        .completionTimeout = USB_TIMEOUT_MS,
    };
    IOReturn kr;

    if (!a || !a->dev || (len && !buf))
        return -1;
    kr = (*a->dev)->DeviceRequestTO(a->dev, &r);
    if (kr != kIOReturnSuccess) {
        report(a, "USB request 0x%02x failed: %s (0x%08x)", req,
               mach_error_string(kr), (unsigned int)kr);
        return -1;
    }
    if (r.wLenDone != len) {
        report(a, "USB request 0x%02x: transferred %u of %u bytes", req,
               (unsigned int)r.wLenDone, (unsigned int)len);
        return -1;
    }
    return 0;
}

int identify_chip(struct adapter *a)
{
    uint32_t b = 0;

    if (!a || a->vid != DUB_VID || a->pid != DUB_PID || a->release != DUB_RELEASE)
        return -1;
    a->version = 0;
    a->chip = NULL;
    if (request(a, USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice),
                RTL_REQ_GET_REGS, RTL_PLA_TCR0, RTL_MCU_TYPE_PLA, &b, sizeof(b)))
        return -1;
    a->version = OSReadLittleInt16(&b, 2) & RTL_VERSION_MASK;
    if (a->version == DUB_VERSION)
        a->chip = &supported_chip;
    return 0;
}

int find_ncm(struct adapter *a)
{
    IOUSBDeviceInterface182 **dev;
    IOUSBConfigurationDescriptorPtr cd = NULL;
    const uint8_t *p;
    size_t remaining;
    unsigned int config;
    int cls = -1, sub = -1, intf = -1;
    UInt8 count = 0, i, cur;

    if (!a || !a->dev)
        return -2;
    dev = a->dev;
    a->ifnum = -1;
    a->size_len = 0;
    if (number_property(a->usb, CFSTR(kUSBHostDevicePropertyCurrentConfiguration), &config)) {
        if ((*dev)->GetConfiguration(dev, &cur) != kIOReturnSuccess)
            return -2;
        config = cur;
    }
    if ((*dev)->GetNumberOfConfigurations(dev, &count) != kIOReturnSuccess)
        return -2;
    for (i = 0; i < count; i++) {
        if ((*dev)->GetConfigurationDescriptorPtr(dev, i, &cd) == kIOReturnSuccess &&
            cd && cd->bConfigurationValue == config)
            break;
    }
    if (i == count)
        return config ? -2 : -1;

    remaining = USBToHostWord(cd->wTotalLength);
    if (remaining < sizeof(*cd) || cd->bLength < sizeof(*cd))
        return -2;
    p = (const uint8_t *)cd;
    while (remaining) {
        uint8_t length;
        if (remaining < 2 || p[0] < 2 || p[0] > remaining)
            return -2;
        length = p[0];
        if (p[1] == kUSBInterfaceDesc && length >= 9) {
            intf = p[2];
            cls = p[5];
            sub = p[6];
        } else if (p[1] == kUSBClassSpecificDescriptor && length >= 6 &&
                   p[2] == NCM_FUNCTIONAL_DESC &&
                   cls == kUSBCommunicationControlInterfaceClass && sub == NCM_SUBCLASS) {
            if (a->ifnum >= 0 && a->ifnum != intf)
                return -2;
            a->ifnum = intf;
            a->size_len = (p[5] & NCM_NTB_INPUT_SIZE_8) ? 8 : 4;
        }
        p += length;
        remaining -= length;
    }
    return a->ifnum >= 0 ? 0 : -1;
}

int get_size(struct adapter *a, unsigned int *size)
{
    uint32_t b[2] = {0};

    if (!a || !size || a->ifnum < 0 || a->ifnum > UINT8_MAX ||
        (a->size_len != 4 && a->size_len != 8))
        return -1;
    if (request(a, USBmakebmRequestType(kUSBIn, kUSBClass, kUSBInterface),
                GET_NTB_INPUT_SIZE, 0, (uint16_t)a->ifnum, b, a->size_len))
        return -1;
    *size = OSReadLittleInt32(b, 0);
    memset(a->size_tail, 0, sizeof(a->size_tail));
    if (a->size_len == 8)
        memcpy(a->size_tail, (const uint8_t *)b + 4, sizeof(a->size_tail));
    return 0;
}
