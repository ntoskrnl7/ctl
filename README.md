# ctl

Cryptographic Template Library

A header only C++17 library of symmetric ciphers and modes of operation. A mode
takes its block cipher as a template argument, so any cipher composes with any
mode through the same code and nothing dispatches virtually per block.

```cpp
#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/mode/xts>
#include <ctl/random/system>

using namespace ctl::symmetric;

using xts_type = mode::xts<cipher::aes<256>>;

xts_type::component_key_t data_key, tweak_key;
ctl::random_bytes(data_key);
ctl::random_bytes(tweak_key);
std::vector<uint8_t> sector(512), out(512);

xts_type xts(data_key, tweak_key);
xts.encrypt(sector_number, sector, out);
```

## What is implemented

| | Sizes | Verified against |
| --- | --- | --- |
| AES | 128, 192, 256 | FIPS 197 appendix C, SP 800-38A F.1.1 |
| ARIA | 128, 192, 256 | RFC 5794 appendix A |
| LEA | 128, 192, 256 | the vectors published with KS X 3246 |
| CTR_DRBG | on any of the ciphers | NIST CAVP, the no derivation function vectors |
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
the build. LEA has nothing to transcribe beyond eight round constants, and the
published vectors are what confirms those.

## Requirements

C++17 and CMake. The only dependency is
[ext](https://github.com/ntoskrnl7/ext), which CPM fetches.

## A first look

No call takes a pointer and a length side by side. Hand over the object that
holds the bytes and the length comes from that object, so the two cannot
disagree.

```cpp
#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/mode/gcm>

using namespace ctl::symmetric;
using gcm_t = mode::gcm<cipher::aes<128>>;

std::vector<uint8_t> key(16), header(8), plain(64), out(64);
uint8_t iv[12], tag[gcm_t::tag_size];

gcm_t gcm(key);
gcm.encrypt(iv, {header}, {plain}, out, tag);

if (auto r = gcm.decrypt(iv, {header}, {out}, plain, tag); !r) {
  // Verification failed, and plain has already been erased.
}
```

Where a length is fixed by the algorithm it is part of the type, so an array of
the wrong size does not compile. Where it is only known at run time it is
checked once, where the buffer is handed over. Operations that can fail return
`ext::void_result`, and every one of those is `[[nodiscard]]`, so dropping the
outcome of a decryption does not compile quietly.

## Documentation

| | |
| --- | --- |
| [Using it](docs/interface.md) | every cipher and mode, and why the interface has the shape it has |
| [What runs on what](docs/acceleration.md) | the instructions each path uses, and what is done where there are none |
| [Measured throughput](docs/throughput.md) | numbers, and what they are and are not comparable to |
| [Where it has been run](docs/platforms.md) | thirteen configurations, four architectures, both byte orders |
| [Status and limits](docs/limits.md) | what to know before choosing a build |
| [Internal security review](docs/security-review.md) | reviewed scope, corrected findings and residual risks |

## Building the tests

```sh
cmake -S test -B test/build
cmake --build test/build
```

## License

MIT. See [LICENSE](LICENSE).
