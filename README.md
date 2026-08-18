# ctl

Cryptographic Template Library

A header only C++17 cryptographic library. Its symmetric modes take the block
cipher as a template argument, and its MACs and KDFs take the hash in the same
way, so the compositions share code and do not dispatch virtually per block.

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
| System random | Windows, Linux, Apple and BSD | platform API contracts and failure-path tests |
| CTR_DRBG | AES-128, AES-192, AES-256; DF by default, explicit no-DF variant | NIST CAVP vectors |
| HMAC_DRBG | approved SHA-2 profiles | NIST CAVP vectors |
| Hash_DRBG | approved SHA-2 profiles | NIST CAVP vectors, including 440/888-bit seed lengths |
| RBG policy | system seed, automatic/fresh reseed, fork detection | deterministic source and system integration tests |
| ECB | | SP 800-38A F.1.1 |
| CBC | | SP 800-38A F.2.1 |
| CTR | | SP 800-38A F.5.1 |
| XTS | | NIST CAVP XTSTestVectors, ciphertext stealing included |
| GCM | tags of 128 down to 96 bits | the canonical GCM test cases, non 96 bit IVs included |
| SHA-2 | 224, 256, 384, 512, 512/224, 512/256 | FIPS 180-4 examples |
| SHA-3 | 224, 256, 384, 512 | FIPS 202 examples |
| SHAKE | 128 and 256, repeated byte-oriented squeeze | FIPS 202 examples and 1,250 `hashlib` answers |
| BLAKE2s | unkeyed, byte-aligned digests from 8 through 256 bits | RFC 7693 appendix B and reference answers |
| BLAKE2b | unkeyed, byte-aligned digests from 8 through 512 bits | RFC 7693 appendix A and reference answers |
| HMAC | over any fixed-output hash above, full tags | RFC 4231 and reference answers |
| HKDF-HMAC | extract, expand, and combined derive | RFC 5869 and generic-composition tests |
| PBKDF2-HMAC | all fixed-output hashes above | RFC 7914, RFC 8018 and reference answers |

Every published cipher and mode vector runs in both the accelerated and the
software only build, so the same known answers cover both paths. All twelve
standard-size fixed hashes were differentially checked against OpenSSL for
hashing, HMAC and both KDFs. Every one of BLAKE2's 96 permitted digest byte
lengths was also checked against `hashlib` for inputs from 0 through 512 bytes.
SHA-3 and BLAKE2 cover empty, exact-block and multi-block inputs, every
streaming split point, and composition through HMAC and both KDF templates.
SHAKE128 and SHAKE256 use a separate absorb-then-squeeze interface; official
2048-bit outputs and an independent boundary matrix cover both Keccak rates.

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
