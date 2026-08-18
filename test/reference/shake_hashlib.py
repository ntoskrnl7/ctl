"""Compare CTL SHAKE128/256 with Python's hashlib.

The companion executable prints deterministic answers across the absorb and
squeeze rate boundaries. hashlib is an independent review oracle and is not a
runtime dependency of CTL.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys


def patterned(size: int) -> bytes:
    return bytes((index * 73 + 19) & 0xFF for index in range(size))


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} PATH-TO-SHAKE-PROBE", file=sys.stderr)
        return 2

    process = subprocess.Popen(
        [sys.argv[1]], stdout=subprocess.PIPE, text=True, encoding="ascii"
    )
    assert process.stdout is not None

    checked = 0
    for line in process.stdout:
        family, message_text, output_text, actual = line.rstrip("\n").split("\t")
        message_size = int(message_text)
        output_size = int(output_text)
        message = patterned(message_size)
        constructor = hashlib.shake_128 if family == "1" else hashlib.shake_256
        expected = constructor(message).hexdigest(output_size)
        if actual != expected:
            process.kill()
            print(
                f"SHAKE{family} differs at {message_size}-byte input and "
                f"{output_size}-byte output",
                file=sys.stderr,
            )
            return 1
        checked += 1

    if process.wait() != 0:
        return 1

    expected_count = 2 * 25 * 25
    if checked != expected_count:
        print(f"expected {expected_count} answers, received {checked}", file=sys.stderr)
        return 1

    print(
        f"{checked} SHAKE answers (both rates and adjacent boundaries) "
        "agree with hashlib"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
