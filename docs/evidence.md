# Evidence

## The problem

With flow control on, as shipped, a DUB-E250 on a Mac floods the switch with PAUSE frames while receiving. On a 1 Gbps link that costs about 7% of the download speed and makes the switch drop frames.

## The fix

Turning flow control off removes the PAUSE frames and the slowdown. Measured on a 1 Gbps full-duplex link:

| | Download | PAUSE frames per run | Switch frame discards |
| --- | ---: | ---: | --- |
| Flow control on (factory) | 875–876 Mbps | 19,000–21,000 | Yes |
| Flow control off, set temporarily | 935–941 Mbps | 0 | None |
| Flow control off, written permanently, after replugging | 940.7 Mbps | 0 | None |

Upload after the permanent fix was 937.0 Mbps with zero retransmissions, and there were no CRC, alignment or symbol errors. Nothing else was running on the Mac to help: no background helper, and the driver's default settings.

## The write

The fix has been written to two adapters, on an M1 Mac and on an M4 Pro Mac running macOS 27.0.1. The second was done with this repository's `check`, `fix` and `verify` commands exactly as the README describes. Both times:

- the adapter's memory had the factory layout the tool expects,
- reading all 2,048 bytes back showed that only the four bytes at `0x006c` had changed, and
- after unplugging and replugging, the adapter started up with flow control off.

The speeds in the table were measured on the first adapter.

## Other things tried

- **Changing the NCM aggregation size from the Mac.** This also restores the speed, but it needs a helper running on every Mac the adapter is plugged into. That is what this fix replaces.
- **The chip's other NCM/ECM modes and Realtek's RAM patches.** Neither helped.

## Not tested

2.5 Gbps links, sleep/wake, and operating systems other than macOS.
