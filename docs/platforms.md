# Where it has been run

Thirteen build configurations over four architectures and both byte orders, what
each one is there to cover, and what is known not to work.

The published vectors and every test run on each of these, so the byte order
handling and the vector paths are covered rather than assumed.

| | How | Result |
| --- | --- | --- |
| x86-64, AES-NI and AVX2 | on the machine | 131 tests |
| x86-64, `CTL_NO_HW_ACCEL` | on the machine | 131 tests |
| x86-64, `CTL_AES_CONSTANT_TIME` | on the machine | 131 tests |
| x86-64, both of those together | on the machine | 131 tests |
| ARM64, cryptographic instructions and NEON | cross built, run under qemu | 131 tests |
| ARM64, `CTL_AES_CONSTANT_TIME` | cross built, run under qemu | 131 tests |
| ARM 32 bit, NEON | cross built, run under qemu | 131 tests |
| MIPS64 little endian, MSA | cross built, run under qemu | 131 tests |
| MIPS64 big endian, MSA, `-fno-tree-vectorize` | cross built, run under qemu | 131 tests |
| MIPS64 little endian, no MSA | cross built, run under qemu | 131 tests |
| MIPS64 little endian, `CTL_AES_CONSTANT_TIME` | cross built, run under qemu | 131 tests |
| MIPS64 big endian | cross built, run under qemu | 131 tests |
| MIPS32r2, no SIMD of any kind | cross built, run under qemu | 131 tests |

The MIPS32r2 row is the oldest thing here: a single core with no MSA, since
that needs release 5, and no cryptographic instructions, since MIPS has none at
any release. Nothing is accelerated there and everything still works, which is
the point of the row. What that target does have is a rotate instruction, which
is the one thing LEA asks of a processor, and no need for the eight and a half
kilobytes of table AES carries. The table free AES runs there too, on a
processor whose registers are half the width its words want, which is the worst
case that path has.

MSA is not tied to a byte order and the LEA and ARIA vector paths now run on
both. ARIA bitslices eight blocks into eight byte vectors, evaluates its
tower-field inversion with same-width and/xor operations, and uses `vshf.b`
for the fixed diffusion permutations. No vector cast changes element width.
For each key size, its dedicated test repeatedly compares an eight-block MSA
batch plus three scalar remainder blocks with the software path in both byte
orders. The dispatch and mode-composition tests pass there as well.

LEA needs a different boundary. The
round remains the same four word additions, exclusive ors and rotations, but the
boundary around it is different on big endian. MSA loads and stores are mixed
endian with respect to a whole vector, and a register cast between byte, word
and doubleword vector types is not the bit-preserving reinterpretation it is on
little endian. The original round and exchange used all three widths.

The big endian path therefore keeps the state as `v4u32` throughout. It reads
and writes each block through the little endian word helpers, broadcasts each
native round-key word with `fill.w`, uses the ordinary vector operators for the
round, and exchanges blocks by addressing the four word elements. The boundary
is paid once on each side of a batch; the 24 to 32 rounds still run four blocks
at a time. Disassembly of the tested binary contains `addv.w`, `subv.w`,
`xor.v`, `slli.w`, `srli.w` and `fill.w`, so passing the dispatch test is not a
scalar fallback mistaken for acceleration.

That distinction also explains why the earlier byte-shuffle fix did not work.
An input block is a little endian byte string, while the expanded round keys are
already native `uint32_t` values; applying the same byte reversal to both
corrupts one of them. Replacing the doubleword exchange with `vshf.w` still left
the result dependent on the compiler's vector indexing convention. Expressing
the boundary in terms of C++ word values removes both ambiguities.

Probes for this need inputs hidden behind `volatile`. With visible constants the
cross compiler can fold an operation on the x86 build host and make a byte-order
experiment report the host's answer instead of the target's.

There is a separate GCC 12 toolchain defect in the tested big endian build.
Merely enabling `-mmsa` lets its tree vectorizer turn unrelated ordinary loops
into wrong MSA code; three tests fail even when the explicit LEA path is left
out. `-fno-tree-vectorize` prevents those unrelated transformations and is
therefore required for that compiler. This is separate from the explicit MSA
intrinsics and vector operators used by LEA.

The big endian row matters more than it looks. Every load and store of a word
goes through `ctl/detail/endian`, which has a path for hosts whose byte order
does not match the specification's, and until that row existed no test had ever
taken it.

What the emulated rows do not show is speed. They say the answers are right on
those architectures, not how fast they arrive. In particular, QEMU's cost for
an MSA byte shuffle is not evidence for its cost on a physical MIPS core, so no
ARIA MSA throughput is claimed without a real-hardware measurement.

---

[Back to the README](../README.md)
