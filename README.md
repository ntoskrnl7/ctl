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

## Requirements

C++17 and CMake. The only dependency is
[ext](https://github.com/ntoskrnl7/ext), which CPM fetches.

## Using it

Headers carry no extension, in the same style as `ext`.

```cpp
#include <ctl/bytes>                    // bytes, writable_bytes
#include <ctl/symmetric/cipher/aes>     // cipher::aes<128|192|256>
#include <ctl/symmetric/cipher/aria>    // cipher::aria<128|192|256>
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

Define `CTL_NO_HW_ACCEL` to leave all of it out. The published vectors pass
either way, and every cipher with two paths has a test that runs the same inputs
through both and compares.

## Measured throughput

AES-128 over a 4096 byte buffer, Intel Core Ultra 7 265K, MSVC `/O2`.

| Mode | Software | Accelerated |
| --- | --- | --- |
| ECB | 543 MB/s | 11,400 MB/s |
| XTS | 472 | 6,270 |
| CTR | 470 | 4,510 |
| CBC, which chains and cannot be parallelized | 426 | 1,590 |
| GCM | 103 | 936 |

XTS over 512 byte sectors reaches 4,500 MB/s. ARIA runs at 132 MB/s in software
and 291 MB/s with the vector path, and ARIA-XTS at 220 MB/s. No operation
performs a heap allocation.

Describing a buffer by a view rather than by a pointer and a length costs
nothing measurable. Running the same benchmark against the interface it
replaced, interleaved so that neither sees a different thermal state, puts every
mode within the ±2% the runs vary by on their own.

## Status and limits

Written from the specifications and checked against their published vectors. It
has not been independently audited, and where an audited implementation is a
requirement, use one.

Two properties are worth knowing before picking a build.

The software AES path is table driven. That is the usual construction and is
what the published vectors verify, but table lookups indexed by key dependent
data can leak through cache timing. The AES-NI path does not have that property.
Where an attacker can measure timing on the same machine and acceleration is not
available, this matters.

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
