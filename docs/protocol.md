# How the write works

This is the technical detail behind `dubfix fix`: what is in the adapter's memory, what gets added, and the USB commands that add it.

## The adapter's memory

The RTL8156B has 2,048 bytes of one-time-programmable memory (eFuse). Every bit starts as 1 and can be changed to 0 once, so blank space reads as `ff`.

The first `0x508` bytes hold a list of records that the chip applies each time it powers up. Each record sets one or more bytes of a register:

| Bytes | Meaning |
| --- | --- |
| 1 | Top 3 bits: register bank (1 = PLA, 2 = USB). Low 5 bits: payload length minus one. |
| 2 | Register address, high byte first |
| 1–32 | Payload, written to the register starting at that address |

The list ends at the first `ff` byte. On a factory DUB-E250 there are twelve records, 108 bytes in total, holding the MAC address, USB descriptor strings and a few settings. So the list ends at `0x006c`, and everything from there to `0x0508` is blank.

The rest of the memory, from `0x0508` up, holds per-unit calibration data. `dubfix` never writes there.

## What gets added

One four-byte record at `0x006c`, directly after the factory ones:

| Byte | Meaning |
| --- | --- |
| `20` | PLA bank, one payload byte |
| `e8 54` | Register `0xe854` (CPCR) |
| `00` | Value |

The factory value of that byte is `01`. Bit 0 is the flow-control enable, so writing `00` turns flow control off at every power-up.

## Recognising a supported adapter

Before writing, `dubfix` reads the whole memory twice and requires:

- **The factory record list is the known one.** Its 108 bytes, with the six MAC bytes zeroed out, must have this SHA-256:

  ```text
  92469ce95db069c97a2782f26aad824954f00fae1117a749c6b82a4706b0a1ce
  ```

- **The slot is free.** Everything from `0x006c` to `0x0508` is blank. (If the fix record is already there and the rest is blank, the adapter is reported as already fixed.)
- **The MAC in memory matches the MAC the adapter is using.**
- **Nothing else has patched the chip**, and flow control is still at its factory setting.

Anything else is refused. The tool never looks for another free slot or accepts a different layout.

## USB commands

All register access uses one vendor control request, number 5:

| | `bmRequestType` | `wValue` | `wIndex` | Data |
| --- | --- | --- | --- | --- |
| Read | `0xc0` | Register address | Bank (`0x000` USB, `0x100` PLA) | 4 bytes, little-endian |
| Write | `0x40` | Register address | Bank, plus a mask of which bytes to write | 4 bytes, little-endian |

The eFuse is reached through two PLA registers:

| Register | Use |
| --- | --- |
| `0xdd00` | Data: the word just read, or the word to be programmed |
| `0xdd04` | Command and status |

Memory is addressed in 4-byte words, so the record at `0x006c` is word `0x1b`. Commands written to `0xdd04`:

| Command | Meaning |
| --- | --- |
| `0x8000` + word number | Read a word |
| `0x8800` + word number | Margin read: the same read with a stricter threshold, used to check a freshly programmed word |
| `0x4000` + word number | Program a word from `0xdd00` |

While a command runs, `0xdd04` reads back with bit 15 set (reading) or bit 14 set (programming).

## The write, step by step

1. **Save** the current value of every register the next step changes.
2. **Prepare.** Programming needs a few clock, power and access settings changed in PLA registers `0xe84c`, `0xe81c`, `0xe85b` and `0xe0ca`, USB registers `0xcfd8` and `0xd848`, and the Ethernet PHY, which is powered down. This is why the network link drops. Only the specific bits involved are touched.
3. **Check** that word `0x1b` still reads as blank, both normally and with a margin read, and that the whole memory still equals the backup.
4. **Stage** the record by writing `0x0054e820` to `0xdd00`. That is `20 e8 54 00` as a little-endian word.
5. **Program** by writing `0x401b` to `0xdd04`, once.
6. **Wait** for the programming bit to clear.
7. **Read back** word `0x1b` normally and with a margin read, then read all 2,048 bytes and compare them with the backup plus the four new bytes.
8. **Restore** the registers from step 1 in reverse order, and check that each one took.

`dubfix fix` runs steps 1–3 and 8 first as a rehearsal, then the whole sequence after you confirm.

The code that sends USB writes only allows the specific registers and values above. The stage and program commands are hard-coded to this one record and this one word; there is no way to pass in a different address or payload.

## When something goes wrong

- **Before step 5**, nothing permanent has happened. The registers are restored.
- **At or after step 5**, the write may or may not have landed, even if the USB request reported an error. The program command is never sent a second time. If the chip does not report that it has finished, the tool leaves it alone and does not try to restore registers or reset it.
- **The log is written to disk before the program command is sent**, so there is a record of the attempt even if the Mac loses power.

`dubfix fix` checks those logs. If an earlier attempt reached step 4 or never finished, and the adapter does not read back as fixed, it refuses to write again. The lower-level `dubfix step apply` has no such check.

Ctrl-C and a closed terminal are both handled: the tool finishes or backs out cleanly before exiting. It also keeps the Mac from idle-sleeping while it runs. Pulling the cable, a crash, or `kill -9` can still interrupt it.

## Sources

The USB transport code is adapted from the MIT-licensed [rtl8156b-macos / ncmsize](https://github.com/plcharriere/rtl8156b-macos/tree/65f57e4e3402c0c4372966e5920f84111731742e). The register behaviour was worked out from Realtek's drivers and programming interfaces and then confirmed on real adapters. No Realtek programming utility, firmware, or memory image from a real adapter is included. See [third-party notices](../THIRD_PARTY_NOTICES.md).
