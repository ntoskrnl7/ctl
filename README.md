# ctl

Cryptographic Template Library

A header only C++17 library of symmetric ciphers and modes of operation. A mode
takes its block cipher as a template argument, so any cipher composes with any
mode through the same code and nothing dispatches virtually per block.

```cpp
#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/mode/xts>

using namespace ctl::symmetric;

mode::xts<cipher::aes<256>> xts(key, key_size);
xts.encrypt(sector_number, plain, sector_size, out);
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
#include <ctl/symmetric/cipher/aes>     // cipher::aes<128|192|256>
#include <ctl/symmetric/cipher/aria>    // cipher::aria<128|192|256>
#include <ctl/symmetric/mode/ecb>       // mode::ecb<Cipher>
#include <ctl/symmetric/mode/cbc>       // mode::cbc<Cipher>
#include <ctl/symmetric/mode/ctr>       // mode::ctr<Cipher>
#include <ctl/symmetric/mode/xts>       // mode::xts<Cipher>
#include <ctl/symmetric/mode/gcm>       // mode::gcm<Cipher, TagBits>
```

Operations that can fail return `ext::void_result`; those that cannot say so by
returning nothing. Setting a key cannot fail, since any byte string is a valid
key, so a wrong length is treated as a programming error and throws.

### A block cipher on its own

```cpp
cipher::aes<128> aes(key, key_size);
aes.encrypt_block(in, out);
aes.decrypt_block(out, back);
```

### CTR, with random access

An offset can be given, so a stream is picked up in the middle without
processing what comes before it.

```cpp
mode::ctr<cipher::aes<128>> ctr(key, key_size);
ctr.crypt(nonce, byte_offset, in, size, out);
```

### XTS, for storage

The key is two block cipher keys concatenated, and a data unit number such as a
sector number becomes the tweak.

```cpp
mode::xts<cipher::aes<256>> xts(key, key_size);   // key_size is 64 here
xts.encrypt(sector_number, plain, 512, out);
```

### GCM, authenticated with associated data

Additional authenticated data stays in the clear but is covered by the tag,
which is what binds a ciphertext to its context. Inputs are given as a list of
runs, so data spread over several buffers needs no copying first. GHASH consumes
the concatenation of a list, so where the runs are split makes no difference,
though their order does.

```cpp
using gcm_t = mode::gcm<cipher::aes<128>>;
gcm_t gcm(key, key_size);

uint8_t tag[gcm_t::tag_size];
gcm.encrypt(iv, iv_size,
            {{header, header_size}, {sequence, sequence_size}},   // AAD
            {{plain, plain_size}},                                // data
            out, tag);

if (auto r = gcm.decrypt(iv, iv_size,
                         {{header, header_size}, {sequence, sequence_size}},
                         {{cipher_text, size}}, out, tag);
    !r) {
  // Verification failed, and out has already been erased.
}
```

Passing `out + size` as the tag pointer appends the tag to the ciphertext, which
is the layout a wire format usually wants.

When the data does not all exist at once there is an incremental form. The two
phases are separate types, so supplying AAD once encryption has begun is a
compile error rather than a wrong tag at run time.

```cpp
auto writer = gcm.encryptor(iv, iv_size).aad({header, header_size}).data();
while (read(chunk, &n)) {
  writer.write({chunk, n}, out + written);
  written += n;
}
writer.finish(tag);
```

Finishing straight from the AAD phase authenticates without encrypting, which is
GMAC.

```cpp
gcm.encryptor(iv, iv_size).aad({message, size}).finish(tag);
```

The incremental form cannot make the guarantee the single call makes. When a tag
fails there, the plaintext has already gone out across the caller's own buffers
and nothing here can reach them, so discarding it becomes the caller's job.

## Hardware acceleration

Chosen at run time through CPUID, so one binary runs anywhere.

- **AES-NI** for AES, interleaving eight blocks so the parallel modes reach the
  throughput the instruction can sustain rather than its latency.
- **PCLMULQDQ** for the GHASH of GCM, folding four blocks into a single
  reduction.

Define `CTL_NO_HW_ACCEL` to leave all of it out. The published vectors pass
either way. ARIA has no accelerated path.

## Measured throughput

AES-128 over a 4096 byte buffer, Intel Core Ultra 7 265K, MSVC `/O2`.

| Mode | Software | Accelerated |
| --- | --- | --- |
| ECB | 542 MB/s | 12,076 MB/s |
| XTS | 438 | 6,581 |
| CTR | 470 | 4,643 |
| CBC, which chains and cannot be parallelized | 503 | 1,627 |
| GCM | 101 | 912 |

XTS over 512 byte sectors reaches 4,530 MB/s. ARIA runs at about 121 MB/s, where
most of the time goes to its byte at a time substitution layer. No operation
performs a heap allocation.

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
