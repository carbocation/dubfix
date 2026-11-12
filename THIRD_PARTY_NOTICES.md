# Third-party notices

`src/transport_macos.c` and `src/transport_macos.h` adapt macOS USB enumeration, descriptor inspection, device requests, chip identification, and native NCM queries from Paul-Louis Charrière's `ncmsize` in [rtl8156b-macos](https://github.com/plcharriere/rtl8156b-macos), commit [`65f57e4e3402c0c4372966e5920f84111731742e`](https://github.com/plcharriere/rtl8156b-macos/tree/65f57e4e3402c0c4372966e5920f84111731742e).

The extraction removes the original command line interface, watcher, background helper, and NCM-size mutation. It narrows discovery to the supported D-Link USB identity and exposes a small transport API for the fixed transaction. The upstream MIT license, including its copyright notice, is retained in [third_party/ncmsize.LICENSE](third_party/ncmsize.LICENSE).

The repository's own source is covered by its root MIT LICENSE. No vendor programming utility, proprietary firmware payload, or GPL driver source is bundled.
