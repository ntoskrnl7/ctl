"""Compare every CTL BLAKE2 digest size with Python's hashlib.

The companion executable prints deterministic results rather than embedding a
second BLAKE2 implementation in this repository. hashlib is used only as an
independent review oracle and is not a runtime dependency of CTL.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys


def patterned(size: int) -> bytes:
    return bytes((index * 73 + 19) & 0xFF for index in range(size))


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} PATH-TO-BLAKE2-PROBE", file=sys.stderr)
        return 2

    process = subprocess.Popen(
        [sys.argv[1]], stdout=subprocess.PIPE, text=True, encoding="ascii"
    )
    assert process.stdout is not None

    checked = 0
    for line in process.stdout:
        family, digest_text, size_text, actual = line.rstrip("\n").split("\t")
        digest_size = int(digest_text)
        message_size = int(size_text)
        message = patterned(message_size)
        constructor = hashlib.blake2s if family == "s" else hashlib.blake2b
        expected = constructor(message, digest_size=digest_size).hexdigest()
        if actual != expected:
            process.kill()
            print(
                f"BLAKE2{family}/{digest_size} differs at {message_size} bytes",
                file=sys.stderr,
            )
            return 1
        checked += 1

    if process.wait() != 0:
        return 1

    expected_count = 513 * (32 + 64)
    if checked != expected_count:
        print(f"expected {expected_count} answers, received {checked}", file=sys.stderr)
        return 1

    print(
        f"{checked} BLAKE2 answers (all digest sizes, 0..512-byte inputs) "
        "agree with hashlib"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
