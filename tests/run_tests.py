#!/usr/bin/env python3
"""Compile and run synthetic tests without the real macOS transport backend.

Only the fake backend linked by test_transaction.c can satisfy transaction
transport calls. No USB enumeration, network access or power assertion is
performed by this test runner. Temporary transaction directories are deleted
after the run; reproducibility results stay under ignored build/tests/.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    build = root / "build" / "tests"
    build.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which(os.environ.get("CC", "clang"))
    if not compiler:
        print("clang is required for the offline C tests", file=sys.stderr)
        return 2
    if sys.platform != "darwin":
        print("These tests currently use the macOS SDK and require macOS.", file=sys.stderr)
        return 2

    flags = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-Isrc", "-Itests"]
    frameworks = ["-framework", "IOKit", "-framework", "CoreFoundation"]
    suites = {
        "profile": ["tests/test_profile.c", "src/profile.c"],
        "transaction": ["tests/test_transaction.c", "src/profile.c"],
        "cli": ["tests/test_cli.c", "src/profile.c"],
    }
    report: dict[str, object] = {
        "scope": "Synthetic fixtures and fake transport only; no real USB or power-management backend is linked.",
        "source_sha256": {},
        "suites": {},
        "pass": False,
    }
    sources = sorted({*suites["profile"], *suites["transaction"], *suites["cli"],
                      "src/cli.c", "src/dubfix.c", "src/profile.h", "src/transport_macos.h", "tests/fixture.h"})
    for name in sources:
        path = root / name
        if path.exists():
            report["source_sha256"][name] = digest(path)

    succeeded = True
    with tempfile.TemporaryDirectory(prefix="dubfix-tests-") as temporary:
        environment = {**os.environ, "DUBFIX_TEST_TMPDIR": temporary}
        for name, inputs in suites.items():
            binary = f"build/tests/test_{name}"
            command = flags + inputs + ["-o", binary] + frameworks
            compiled = subprocess.run(command, cwd=root, capture_output=True, text=True)
            (build / f"{name}.compile.stdout.txt").write_text(compiled.stdout)
            (build / f"{name}.compile.stderr.txt").write_text(compiled.stderr)
            suite: dict[str, object] = {"compile_returncode": compiled.returncode,
                                       "compile_inputs": inputs,
                                       "real_transport_linked": False}
            report["suites"][name] = suite
            if compiled.returncode:
                succeeded = False
                print(compiled.stdout, end="")
                print(compiled.stderr, end="", file=sys.stderr)
                continue
            suite["binary_sha256"] = digest(root / binary)
            # A future direct core call must not silently bypass the fake
            # backend through a framework import. Types/framework linkage are
            # fine; importing a real IOKit or network operation is forbidden.
            undefined = subprocess.run(["nm", "-u", binary], cwd=root,
                                       capture_output=True, text=True, check=True)
            prohibited = []
            for line in undefined.stdout.splitlines():
                symbol = line.strip().split()[-1:] or [""]
                if (re.fullmatch(r"_IO[A-Za-z0-9_]+", symbol[0]) or
                        symbol[0] in {"_socket", "_connect", "_bind", "_listen",
                                      "_accept", "_send", "_recv", "_getifaddrs", "_ioctl"}):
                    prohibited.append(symbol[0])
            suite["prohibited_hardware_imports"] = prohibited
            if prohibited:
                succeeded = False
                print(f"{name}: forbidden real hardware/network imports: {prohibited}", file=sys.stderr)
                continue
            started = time.monotonic()
            try:
                run = subprocess.run([str(root / binary)], cwd=root, env=environment,
                                     capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired as exc:
                succeeded = False
                suite["timeout_seconds"] = 60
                (build / f"{name}.stdout.txt").write_text(text_output(exc.stdout))
                (build / f"{name}.stderr.txt").write_text(text_output(exc.stderr))
                print(f"{name}: offline test timeout", file=sys.stderr)
                continue
            suite["elapsed_seconds"] = round(time.monotonic() - started, 3)
            suite["returncode"] = run.returncode
            (build / f"{name}.stdout.txt").write_text(run.stdout)
            (build / f"{name}.stderr.txt").write_text(run.stderr)
            summary = re.search(r"DUBFIX_TRANSACTION_TEST_RESULT cases=(\d+) assertions=(\d+) failures=(\d+)", run.stdout)
            if summary:
                suite.update(cases=int(summary[1]), assertions=int(summary[2]),
                             failures=int(summary[3]))
            if run.returncode:
                succeeded = False
                print(run.stdout, end="")
                print(run.stderr, end="", file=sys.stderr)
            else:
                last_line = run.stdout.rstrip().splitlines()[-1:]
                print(f"{name}: PASS" + (f" — {last_line[0]}" if last_line else ""))
    report["pass"] = succeeded
    (build / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
