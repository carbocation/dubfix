# dubfix

The D-Link DUB-E250 USB Ethernet adapter is slower than it should be on macOS. `dubfix` fixes that by turning off Ethernet flow control (PAUSE frames) inside the adapter.

On a 1 Gbps link, download speed went from about 875 Mbps to about 941 Mbps. The fix is stored in the adapter, so it works on any Mac with nothing installed.

> [!WARNING]
> **This can destroy your adapter.** The fix is written to one-time-programmable memory. It cannot be undone, and if the write goes wrong the adapter may never work again. Use it at your own risk: the software comes with no warranty of any kind, as set out in the [license](LICENSE).

## Supported hardware

| | |
| --- | --- |
| Product | D-Link DUB-E250, hardware version A1 |
| USB ID | `2001:b301`, device revision `3100` |
| Chip | Realtek RTL8156B (identifier `7410`) |

You don't need to check these yourself. The tool does, and it refuses anything else.

## Use

You need a Mac with Apple's command line tools (`xcode-select --install`). Plug the adapter into the Mac, then build:

```sh
make
```

See whether your adapter is supported. This saves a backup and changes nothing:

```sh
./build/dubfix check
```

Write the fix:

```sh
./build/dubfix fix
```

`fix` rehearses the write, then asks you to type the last four digits of the adapter's MAC address (it shows you which) before it writes anything. The Ethernet link may drop for a moment. Leave the adapter plugged in until it finishes.

Then unplug the adapter, wait five seconds, plug it back in, and confirm:

```sh
./build/dubfix verify
```

If more than one DUB-E250 is attached, add the interface name the tool shows you, for example `./build/dubfix fix en7`.

## What it leaves on disk

Everything goes in `dubfix-data/` in the folder you ran the tool from, with one folder per adapter, named after its MAC address:

```text
dubfix-data/02-11-22-33-44-55/
  backup/                      the adapter's memory before the fix
  20261111-193000-preflight/   one folder per step, each with a transaction.log
  20261111-193004-dry-run/
  20261111-193020-apply/
```

Run `verify` from the same folder you ran `fix` in, because it compares the adapter with that backup.

## If the write fails

`fix` prints what went wrong and where the full log is. It then refuses to write to that adapter again, because a second write on top of a half-finished one can ruin it. A write that was refused before programming started is the exception, and `fix` lets you retry it.

Run `./build/dubfix check` to see where the adapter stands. If it says the fix is already stored, the write landed and you can go on to `verify`. Otherwise read the `transaction.log` in the newest `-apply` folder.

## How it works

The adapter's chip reads a list of register settings from its memory every time it powers up. `dubfix` appends one entry to that list: set the low byte of register `0xe854` to `0x00`, which clears the flow-control enable bit. In the adapter's memory that is `20 e8 54 00` at offset `0x006c`, the first unused slot after the factory entries. Nothing else changes, and the tool reads all 2,048 bytes back to prove it.

It is not new firmware and not a driver. [docs/protocol.md](docs/protocol.md) describes the USB commands, and [docs/evidence.md](docs/evidence.md) has the measurements. The fix has been applied to two adapters so far; 2.5 Gbps links have not been measured.

## Running the steps by hand

`check`, `fix` and `verify` run a fixed sequence of smaller steps: `list`, `backup`, `plan`, `preflight`, `dry-run`, `apply` and `verify`. Each is available on its own if you want to choose the folders or stop between steps. Run `./build/dubfix step` to see them. `step apply` takes the confirmation token printed by `step plan` in place of the typed prompt, and it does not refuse to retry a failed write the way `fix` does.

## Development

```sh
make test
```

The tests use made-up memory images and a fake USB layer, so they never touch a real adapter. They need Python 3.

If the tool refuses your adapter, an issue with the USB ID, revision, chip identifier and the reason given is welcome.

MIT licensed. The USB transport code is adapted from Paul-Louis Charrière's `ncmsize`; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
