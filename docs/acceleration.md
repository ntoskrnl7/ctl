# What runs on what

Which instructions each cipher and each mode reaches for, how the choice is
made, and what is done on a processor that offers none of them.

Chosen at run time through CPUID, so one binary runs anywhere.

- **AES-NI on x86 and the ARMv8 cryptographic instructions on ARM** for AES,
  interleaving eight blocks so the parallel modes reach the throughput the
  instruction can sustain rather than its latency. The two divide a round
  differently: AESENC ends with the round key and AESE begins with it, so the
  schedule is offset by one between them, and decryption takes the equivalent
  inverse cipher keys on both but reads them in opposite directions.
- **PCLMULQDQ** for the GHASH of GCM, folding four blocks into a single
  reduction.
- **Vector instructions for ARIA**, which has no instruction of its own. On x86
  and ARM its SB1 is supplied by the AES S-box instruction and SB3 by the AES
  inverse S-box instruction. The other two follow from an affine relation
  recovered from the tables and checked at compile time. x86 spells the byte
  lookup `pshufb` and ARM spells it `tbl`.

  MSA has the byte lookup, `vshf.b`, but no AES instruction. Its path therefore
  bitslices eight independent blocks across eight vector registers, one
  register per bit of every byte. The four S-boxes become affine basis changes
  around one inversion circuit in the tower GF(2^2) inside GF(2^4) inside
  GF(2^8). The circuit is shared with the table-free AES implementation, and no
  secret value indexes memory. The affine maps are generated and checked at
  compile time; repeated batches are compared with the scalar ARIA path in the
  tests.

  The diffusion layer is seven byte shuffles: once on x86 and ARM, and once per
  bit plane on MSA. MSA uses byte vectors and same-width bitwise operations
  throughout, so the same code runs on little- and big-endian MIPS without the
  width-changing cast ambiguity that affected LEA. A partial batch takes the
  scalar path; modes that can supply independent blocks hand over eight at once.
- **SSE2 and AVX2 on x86, NEON on ARM, MSA on MIPS, for LEA**, which needs no
  instruction set of its own at all. A round is four 32 bit words put through
  addition, exclusive or and rotation, and none of those look outside their own
  lane, so four blocks run through four lanes with the sequence one block uses,
  or eight through eight where AVX2 is there. The cost is that only AVX-512 has
  a vector rotate, so each of the three per round becomes a pair of shifts and
  an or, and that the blocks have to be exchanged into lanes on the way in and
  back on the way out. On x86 the two widths together come to about five times
  the throughput of one block at a time.

  The round is written once and each architecture says only what its handful of
  lane operations are. NEON needs no run time check, since it is part of 64 bit
  ARM, and it is asked for by the instructions it needs rather than by the name
  of the architecture, which is what 32 bit ARM was being turned away by. MSA is
  compiled in only when the compiler was told the target has it. Little endian
  reads blocks directly into registers; big endian keeps the rounds in `v4u32`
  and converts at the batch boundary so no vector cast changes element width.
  GCC 12 additionally needs `-fno-tree-vectorize` on that big endian target for
  an unrelated compiler defect described in [the platform notes](platforms.md).

Define `CTL_NO_HW_ACCEL` to leave all of it out. The published vectors pass
either way, and every cipher with two paths has a test that runs the same inputs
through both and compares.

# GHASH without a table either

The tag of GCM is a multiplication in GF(2^128) per block. With PCLMULQDQ or
PMULL that is one instruction; without them it used to be a loop of a hundred
and twenty eight shifts and masks, which is where software GCM spent three
quarters of its time. A table would fix that and cannot be used here: a GHASH
table is built from the subkey and indexed by data derived from it, which is a
cache timing channel on the one value that has to stay secret.

There is a third way, and it needs no table. An ordinary integer multiply is
already a carry-less multiply that also carries, so the only problem is to stop
the carries from reaching anything that is kept. Splitting each operand into the
bits at positions congruent to 0, 1, 2 and 3 modulo four does that: every
partial product of one piece by another lands at a position congruent to the sum
of the two, so the three positions above each one receive nothing but carries
and are masked away. Sixteen multiplications then give an exact half product,
the other half comes from handing the same routine its operands backwards, and
Karatsuba over the two halves makes three of those rather than four.

| | one bit at a time | by multiplication |
| --- | --- | --- |
| GHASH, x86-64 | 133 MB/s | 560 |
| AES-128-GCM, x86-64, software throughout | 95 | 271 |

It is chosen by the width of a general register rather than taken everywhere.
Where a 64 bit multiply has to be built out of 32 bit ones it stops being a
bargain, and the two MIPS targets disagree by more than the factor itself:
emulated, MIPS64 gains three quarters and MIPS32r2 loses a quarter. So a target
with narrow registers keeps the loop, and the two are checked against each other
on every target either way, over single bits in each of the 128 positions and
four thousand random pairs.

# AES without tables

The table driven AES indexes memory with a value that depends on the key. Which
cache lines that touches is visible to anything else on the machine, and
recovering a key from that has been demonstrated more than once. Define
`CTL_AES_CONSTANT_TIME` and AES indexes nothing: every step is a shift, an and,
or an exclusive or on whole words, and the memory trace is the same for every
key and every block. The key schedule substitutes through the same circuit, so
it does not give the key away either.

Four blocks are held across eight 64 bit words, one bit of every byte per word,
and a round works on all sixty four bytes at once. The S-box becomes a circuit
rather than a lookup: an inversion in GF(2^8) is expensive in the field FIPS 197
names and cheap in a tower of GF(2^2) inside GF(2^4) inside GF(2^8), so the
state changes basis into the tower, inverts, and changes back with the affine
map folded in. The two basis changes are 8x8 matrices over GF(2), found by
searching every isomorphism between the two fields for the one of least weight;
both S-boxes were then checked against FIPS 197 for all 256 inputs before any of
it was written in C++.

What it costs, on the machine and buffer the [throughput](throughput.md) page
uses, with `CTL_NO_HW_ACCEL`
so that the two software paths are what is being compared.

| | Tables | Table free |
| --- | --- | --- |
| ECB, four blocks per pass | 565 MB/s | 162 |
| CTR | 490 | 142 |
| XTS | 482 | 143 |
| GCM | 271 | 102 |
| CBC encrypt, one block at a time | 436 | 44 |

About three and a half times the cost where blocks can go through together, and
ten where they cannot. CBC encryption chains, so it hands over one block at a
time and three of the four lanes are idle; a mode that can run blocks in
parallel does not pay that. GCM moves least of the parallel modes, since the tag
is a share of its work that the cipher choice does not touch.

That the tables are gone is checked rather than asserted, and checking it found
something. A program that uses AES through a mode and never names the reference
path, built both ways, comes out 2,048 bytes smaller with the macro defined and
holds neither round table nor either S-box. But that only held with optimization
on: which of the two software paths runs was decided at each of seven call
sites, and where the decision was an ordinary condition on a compile time
constant, the branch never taken still named the table path, so an unoptimized
build linked all eight and a half kilobytes of tables it could not reach. One
function decides now, and the tables are absent at `/O2` and at `/Od` alike.
There is nothing left to index.

Worth saying plainly: on a processor with no AES instructions, LEA is table free
by construction and three to five times faster than this, depending on the mode.
Where the cipher is negotiable,
that is the better answer, and this path is for where it is not — a format or a
protocol that names AES, on a processor that has no instruction for it.

The circuit is compiled in every build whether or not `CTL_AES_CONSTANT_TIME`
selects it, and `encrypt_block_constant_time`, `encrypt_blocks_constant_time`
and their decrypting counterparts are always callable, so a caller can ask for
it on one buffer rather than for the whole build. The tests compare it against
the table path on every configuration for that reason.

A build that does not select it pays nothing for it, which took a second
attempt to get right. Its round keys want a different arrangement from the
table path's, and keeping them in the cipher whether or not anything reached
them doubled the object and cost a fifth of a key setup. They are kept only
where the macro selects the path; where it does not, the entry points above
build them on the stack, once per call rather than once per group of four, so
a buffer of any length pays that back and only a single block does not. The
object is the size it was and a key setup is as quick as it was.

---

[Back to the README](../README.md)
