# ctl

Cryptographic Template Library

A header only C++17 library of symmetric ciphers and modes of operation. A mode
takes its block cipher as a template argument, so any cipher composes with any
mode through the same code and nothing dispatches virtually per block.

```cpp
#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/mode/xts>

using namespace ctl::symmetric;

std::vector<uint8_t> key(64), sector(512), out(512);

mode::xts<cipher::aes<256>> xts(key);
xts.encrypt(sector_number, sector, out);
```

## What is implemented

| | Sizes | Verified against |
| --- | --- | --- |
| AES | 128, 192, 256 | FIPS 197 appendix C, SP 800-38A F.1.1 |
| ARIA | 128, 192, 256 | RFC 5794 appendix A |
| LEA | 128, 192, 256 | the vectors published with KS X 3246 |
| ECB | | SP 800-38A F.1.1 |
| CBC | | SP 800-38A F.2.1 |
| CTR | | SP 800-38A F.5.1 |
| XTS | | NIST CAVP XTSTestVectors, ciphertext stealing included |
| GCM | tags of 128 down to 96 bits | the canonical GCM test cases, non 96 bit IVs included |

Every published vector runs in both the accelerated and the software only
build, so the same known answers cover both paths.

Tables are generated rather than transcribed. The AES S-box and its round
tables, and ARIA's SB1, SB3 and SB4, are all built at compile time from the
algebraic definitions in the specifications. Only ARIA's SB2 is copied from its
document, because RFC 5794 gives no definition for it, and a `static_assert`
checks that what was copied is a permutation, so a single mistyped byte fails
the build.

LEA has no table to generate or transcribe. It is built from addition, rotation
and exclusive or, and the only values copied from its document are eight round
constants, which satisfy no property that could check them. The published
vectors are what confirms those, and the tests say so where they sit.

## Requirements

C++17 and CMake. The only dependency is
[ext](https://github.com/ntoskrnl7/ext), which CPM fetches.

## Using it

Headers carry no extension, in the same style as `ext`.

```cpp
#include <ctl/bytes>                    // bytes, writable_bytes
#include <ctl/symmetric/cipher/aes>     // cipher::aes<128|192|256>
#include <ctl/symmetric/cipher/aria>    // cipher::aria<128|192|256>
#include <ctl/symmetric/cipher/lea>     // cipher::lea<128|192|256>
#include <ctl/symmetric/mode/ecb>       // mode::ecb<Cipher>
#include <ctl/symmetric/mode/cbc>       // mode::cbc<Cipher>
#include <ctl/symmetric/mode/ctr>       // mode::ctr<Cipher>
#include <ctl/symmetric/mode/xts>       // mode::xts<Cipher>
#include <ctl/symmetric/mode/gcm>       // mode::gcm<Cipher, TagBits>
```

Operations that can fail return `ext::void_result`; those that cannot say so by
returning nothing. Every one of those results is `[[nodiscard]]`, so dropping
the outcome of a decryption does not compile quietly.

### Buffers carry their own length

No call takes a pointer and a length side by side. Hand over the object that
holds the bytes and the length comes from that object, so the two cannot
disagree.

```cpp
std::vector<uint8_t> key(16), plain(64), out(64);
uint8_t iv[16];

mode::cbc<cipher::aes<128>> cbc(key);
cbc.encrypt(iv, plain, out);
```

Anything contiguous works: `std::vector`, `std::array`, a C array, a
`std::string`, or `ctl::bytes(pointer, length)` where nothing else describes the
buffer. Output buffers carry a length too, so writing past the end is reported
rather than silently corrupting whatever follows.

Where the length is fixed by the algorithm, it is part of the type, and getting
it wrong fails to compile.

```cpp
uint8_t wrong[15];
cipher::aes<128> aes(wrong);       // error: the array is not key_size bytes
```

A container whose length is only decided at run time is checked once, where it
is handed over, and throws `std::invalid_argument` rather than being read past
its end. The same applies to an output buffer that cannot hold the result: its
length is decided entirely by the calling code and never by the data, so a
buffer that is too small is a mistake in that code rather than a condition to
recover from.

Parts of a buffer are named rather than computed:

```cpp
ctl::bytes(packet).first(header_size)
ctl::bytes(packet).last(tag_size)
ctl::writable_bytes(out).subview(offset, run)
```

A view holds only what it needs, so `ctl::bytes` is a pointer and a length and a
fixed length view such as `aes<128>::key_view` is just the pointer. Neither owns
anything, and neither may outlive the buffer it was made from.

### A block cipher on its own

```cpp
cipher::aes<128> aes(key);
aes.encrypt_block(in, out);
aes.decrypt_block(out, back);
```

### CTR, with random access

An offset can be given, so a stream is picked up in the middle without
processing what comes before it.

```cpp
mode::ctr<cipher::aes<128>> ctr(key);
ctr.crypt(nonce, byte_offset, in, out);
```

### XTS, for storage

The key is two block cipher keys concatenated, and a data unit number such as a
sector number becomes the tweak.

```cpp
mode::xts<cipher::aes<256>> xts(key);   // the key is 64 bytes here
xts.encrypt(sector_number, sector, out);
```

Because the key is twice as long as the block cipher key, filling the slot by
writing the same key twice produces a buffer of exactly the right length that is
not a key. K1 encrypts the data and K2 encrypts the tweak, and the mode offers
nothing once the two coincide, so a key whose halves are equal is refused.

### GCM, authenticated with associated data

Additional authenticated data stays in the clear but is covered by the tag,
which is what binds a ciphertext to its context. Inputs are given as a list of
runs, so data spread over several buffers needs no copying first. GHASH consumes
the concatenation of a list, so where the runs are split makes no difference,
though their order does.

```cpp
using gcm_t = mode::gcm<cipher::aes<128>>;
gcm_t gcm(key);

uint8_t tag[gcm_t::tag_size];
gcm.encrypt(iv, {header, sequence}, {plain}, out, tag);

if (auto r = gcm.decrypt(iv, {header, sequence}, {cipher_text}, out, tag); !r) {
  // Verification failed, and out has already been erased.
}
```

Naming the last `tag_size` bytes of the buffer that also holds the ciphertext
appends the tag there, which is the layout a wire format usually wants.

```cpp
std::vector<uint8_t> packet(plain.size() + gcm_t::tag_size);
gcm.encrypt(iv, {}, {plain},
            ctl::writable_bytes(packet).first(plain.size()),
            ctl::writable_bytes(packet).last(gcm_t::tag_size));
```

When the data does not all exist at once there is an incremental form. The two
phases are separate types, so supplying AAD once encryption has begun is a
compile error rather than a wrong tag at run time.

```cpp
auto writer = gcm.encryptor(iv).aad(header).data();
while (read(chunk, &n)) {
  writer.write(ctl::bytes(chunk, n),
               ctl::writable_bytes(out).subview(written, n));
  written += n;
}
writer.finish(tag);
```

Finishing straight from the AAD phase authenticates without encrypting, which is
GMAC.

```cpp
gcm.encryptor(iv).aad(message).finish(tag);
```

The incremental form cannot make the guarantee the single call makes. When a tag
fails there, the plaintext has already gone out across the caller's own buffers
and nothing here can reach them, so discarding it becomes the caller's job.

A writer holds on to the `gcm` it came from, so making one from a temporary would
leave it pointing at a destroyed object. That does not compile; give the `gcm` a
name. Both forms also refuse to carry one invocation past the roughly 64 GiB the
specification allows, because the counter is only the last four bytes of the
block and past that limit the key stream repeats.

## Hardware acceleration

Chosen at run time through CPUID, so one binary runs anywhere.

- **AES-NI** for AES, interleaving eight blocks so the parallel modes reach the
  throughput the instruction can sustain rather than its latency.
- **PCLMULQDQ** for the GHASH of GCM, folding four blocks into a single
  reduction.
- **AES-NI and SSSE3 for ARIA**, which has no instruction of its own. Its SB1 is
  the AES S-box and its SB3 is the AES inverse S-box, so the AES round
  instructions provide two of the four; the other two follow from an affine
  relation recovered from the tables and checked at compile time. The diffusion
  layer becomes seven byte shuffles. The state then stays in one register for
  the whole block instead of being written out and read back every round, which
  is where the time was going.
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
  compiled in only when the compiler was told the target has it, and only where
  words are already little endian.

Define `CTL_NO_HW_ACCEL` to leave all of it out. The published vectors pass
either way, and every cipher with two paths has a test that runs the same inputs
through both and compares.

## Measured throughput

AES-128 over a 4096 byte buffer, Intel Core Ultra 7 265K, MSVC `/O2`.

| Mode | Software | Accelerated |
| --- | --- | --- |
| ECB | 543 MB/s | 11,510 MB/s |
| XTS | 472 | 6,230 |
| CTR | 470 | 4,470 |
| GCM | 103 | 1,970 |
| CBC, which chains and cannot be parallelized | 426 | 1,590 |

XTS over 512 byte sectors reaches 4,440 MB/s. ARIA runs at 132 MB/s in software
and 294 MB/s with the vector path, and ARIA-XTS at 221 MB/s. No operation
performs a heap allocation.

The other two ciphers, over the same 4096 byte buffer.

| | ECB | CTR | XTS | GCM |
| --- | --- | --- | --- | --- |
| LEA-128, eight blocks at a time | 3,530 MB/s | 2,140 | 2,640 | 1,330 |
| LEA-128, four blocks at a time | 1,820 | 1,500 | 1,570 | 1,100 |
| LEA-128, one block at a time | 729 | 598 | 593 | 613 |
| ARIA-128, vector path | 290 | 234 | 219 | 222 |
| ARIA-128, one block at a time | 132 | — | — | — |

Worth comparing LEA against the 543 MB/s the software path of AES reaches in the
table above. Without AES-NI it is six times faster than AES, and it gets there
without a table. Against AES with AES-NI it is a third of the throughput in ECB
and about two thirds in GCM, where the tag rather than the cipher is most of the
work.

ARIA does not move with any of this, because its vector path processes one block
at a time and it says so: a mode asks its cipher whether handing over a batch is
worth anything, and ARIA answers no.

Describing a buffer by a view rather than by a pointer and a length is close to
free. Measured against the interface it replaced, six runs of each interleaved so
that neither sees a different thermal state, CBC, GCM, ARIA and ARIA-XTS are
level, CTR is slightly ahead, ECB is about one percent behind and XTS is about
two percent behind at both data unit sizes.

Two places had to be shaped for this rather than just converted. Where a mode
hands work to its cipher inside a loop, once per batch rather than once per
call, the batch is one length both sides already know, so it is part of the
argument types; a pointer and a length together do not fit in a register on
x86-64, and three of them stated separately cost CTR two to three percent before
the length moved into the type. And a mode's own private helpers take pointers,
since the range was settled by the entry point that called them.

XTS's two percent is not in the code that runs. It appeared at the commit where
the entry points started taking views, not at the batch rework; ECB moved by the
same amount there and CBC did not, though CBC takes the same two views. The
generated batch loop is the same in both, three pointers where there used to be
three pointers and a count. Forcing back the one inlining decision that did
change moves XTS to half a percent behind and takes CTR from ahead to level,
which is trading one mode against another rather than removing a cost. And
putting dead code in front of an otherwise identical benchmark moves XTS by one
percent on its own. So it is where the code lands, and it is left written down
rather than explained away.

## Where it has been run

The published vectors and every test run on each of these, so the byte order
handling and the vector paths are covered rather than assumed.

| | How | Result |
| --- | --- | --- |
| x86-64, AES-NI and AVX2 | on the machine | 91 tests |
| x86-64, `CTL_NO_HW_ACCEL` | on the machine | 91 tests |
| ARM64, NEON | cross built, run under qemu | 91 tests |
| ARM 32 bit, NEON | cross built, run under qemu | 91 tests |
| MIPS64 little endian, MSA | cross built, run under qemu | 91 tests |
| MIPS64 big endian, MSA | not supported, see below | |
| MIPS64 little endian, no MSA | cross built, run under qemu | 91 tests |
| MIPS64 big endian | cross built, run under qemu | 91 tests |
| MIPS32r2, no SIMD of any kind | cross built, run under qemu | 91 tests |

The MIPS32r2 row is the oldest thing here: a single core with no MSA, since
that needs release 5, and no cryptographic instructions, since MIPS has none at
any release. Nothing is accelerated there and everything still works, which is
the point of the row. What that target does have is a rotate instruction, which
is the one thing LEA asks of a processor, and no need for the eight and a half
kilobytes of table AES carries.

MSA is not tied to a byte order and big endian MIPS can have it. Not supporting
it there is this library's limit rather than the hardware's. Opening the gate
leaves five tests failing, every one of them the vector path of LEA disagreeing
with the block at a time path, and the vector output is not a permutation of the
right answer but different values, so what is wrong is the arithmetic and not
the arrangement.

Where it is not is worth writing down, because two plausible answers were tried
and both made it worse. Probes on both byte orders say that ld.b gives the same
word elements from the same sixteen bytes on each, that round keys load
identically, and that the four step exchange produces the same result; so
neither reversing the bytes of a block nor swapping the words inside each
doubleword of the exchange is the fix. Each was tried on the strength of a
difference that a probe with constant inputs appeared to show, and a probe
written differently disagreed with the first, which says more about a cross
compiler folding vector builtins than about the hardware.

One thing that came out of looking is worth having on its own. Building for big
endian with the MSA flag breaks three tests with none of this code compiled in,
because the compiler turns ordinary loops into MSA there and gets them wrong;
`-fno-tree-vectorize` makes those three pass. That is a fault in the compiler
rather than in this library, and it is why no clean comparison was available
until it was found. The block at a time path is correct on big endian MIPS and
is what runs.

The big endian row matters more than it looks. Every load and store of a word
goes through `ctl/detail/endian`, which has a path for hosts whose byte order
does not match the specification's, and until that row existed no test had ever
taken it.

What the emulated rows do not show is speed. They say the answers are right on
those architectures, not how fast they arrive.

## Status and limits

Written from the specifications and checked against their published vectors. It
has not been independently audited, and where an audited implementation is a
requirement, use one.

Two properties are worth knowing before picking a build.

The software AES path is table driven. That is the usual construction and is
what the published vectors verify, but table lookups indexed by key dependent
data can leak through cache timing. The AES-NI path does not have that property.
Where an attacker can measure timing on the same machine and acceleration is not
available, this matters. ARIA is table driven in the same way on its software
path. LEA is not, and cannot be: it has no table, so there is no lookup to
index, on any path. That is worth knowing where a build has to run without
AES-NI and timing is part of the threat model.

GHASH is either the carry-less instruction or a bit at a time, and never a
table, for the same reason: a GHASH table is built from the hash subkey and
indexed by data derived from it.

## Building the tests

```sh
cmake -S test -B test/build
cmake --build test/build
```

## License

MIT. See [LICENSE](LICENSE).
