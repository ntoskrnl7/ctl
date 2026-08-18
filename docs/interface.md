# Using it

Every call takes buffers that carry their own length, and every length an
algorithm fixes is part of a type. What follows is one example of each cipher
and mode, and the reasoning behind the shape they share.

Headers carry no extension, in the same style as `ext`.

```cpp
#include <ctl/bytes>                    // bytes, writable_bytes
#include <ctl/random/system>            // random_bytes, from the system
#include <ctl/random/ctr_drbg>           // AES CTR_DRBG with derivation
#include <ctl/random/ctr_drbg_no_df>     // explicit no-derivation variant
#include <ctl/random/hmac_drbg>          // HMAC_DRBG<Sha2>
#include <ctl/random/hash_drbg>          // Hash_DRBG<Sha2>
#include <ctl/random/rbg>                // system-seeded/reseeded owner
#include <ctl/hash/fixed>               // fixed_hash, compute<Hash>
#include <ctl/hash/sha2>                // hash::sha224 ... sha512_256
#include <ctl/hash/sha3>                // hash::sha3_224 ... sha3_512
#include <ctl/hash/xof>                 // xof, is_xof, expand<Xof>
#include <ctl/hash/shake>               // hash::shake128, shake256
#include <ctl/hash/blake2>              // hash::blake2s<Bits>, blake2b<Bits>
#include <ctl/mac/hmac>                 // mac::hmac<Hash>
#include <ctl/kdf/hkdf>                 // kdf::hkdf<Hash>, RFC 5869
#include <ctl/kdf/pbkdf2>               // kdf::pbkdf2<Hash>, RFC 8018
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

## Buffers carry their own length

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

Transforms accept disjoint input and output or an exact in-place operation.
Shifted overlap, such as writing at `input + 1`, is rejected before anything is
written; these APIs do not provide direction-dependent `memmove` semantics.

## Fixed-output hashes, HMAC and key derivation

All six SHA-2 functions in FIPS 180-4 and all four fixed-output SHA-3 functions
in FIPS 202 are available. BLAKE2s and BLAKE2b take their byte-aligned digest
size in bits as a template argument; the named aliases cover the standard
128/160/224/256-bit BLAKE2s and 160/256/384/512-bit BLAKE2b sets. Every one is
available as a one-shot or streaming operation. A streaming context has one
owner, `finish` consumes it, and `reset` explicitly begins a new digest. State
owned by the context is erased on finish, reset, move and destruction.

Every fixed-output hash has the same compile-time contract: `block_size`,
`digest_size`, digest storage and views, and `reset`, `update` and `finish`.
`is_fixed_hash_v<Hash>` checks that shape, and generic code uses `compute`.
Algorithms keep their static `hash` convenience function, so existing and
generic spellings are both available.

```cpp
ctl::hash::sha256::digest_t digest;
ctl::hash::sha256::hash(message, digest);

static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha256>);
ctl::hash::compute<ctl::hash::sha256>(message, digest);

ctl::hash::sha512 stream;
stream.update(first);
stream.update(second);
ctl::hash::sha512::digest_t streamed_digest;
stream.finish(streamed_digest);

ctl::hash::blake2b<256>::digest_t blake_digest;
ctl::hash::blake2b<256>::hash(message, blake_digest);
```

### Extendable-output functions

SHAKE128 and SHAKE256 have no fixed `digest_size`. They satisfy the separate
`is_xof_v<Xof>` contract: absorb with `update`, call `finish` once to apply the
SHAKE domain suffix and enter the output phase, then call `squeeze` as often as
needed. Successive calls continue one output stream rather than restarting it;
only `reset` begins a new invocation. `expand` is the one-shot spelling.

```cpp
std::vector<uint8_t> output(96);
ctl::hash::shake256::expand(message, output);

static_assert(ctl::hash::is_xof_v<ctl::hash::shake256>);
ctl::hash::shake256 stream;
stream.update(first);
stream.update(second);
stream.finish();
stream.squeeze(ctl::writable_bytes(output).first(32));
stream.squeeze(ctl::writable_bytes(output).subview(32, 64));
```

SHAKE output has the prefix property: requesting 32 bytes and 64 bytes from the
same input produces outputs where the former is the prefix of the latter. The
requested length is not encoded into SHAKE. A protocol using one input for
different purposes must therefore provide explicit domain separation rather
than treating output lengths as separate domains. The API is byte-oriented, so
it does not represent FIPS 202 inputs or outputs whose bit length is not a
multiple of eight.

RFC 7693's built-in keyed BLAKE2 mode remains reserved for a future MAC
interface; the default-constructible BLAKE2 hash types are deliberately
unkeyed.

HMAC is generic over the hash and exposes only a full-length tag. Verification
uses a content-independent comparison. A protocol that standardizes a shorter
tag can truncate at that protocol boundary; this interface does not silently
choose one. HMAC-BLAKE2 is the generic HMAC construction and is not RFC 7693's
native keyed BLAKE2 mode. Likewise, a protocol has to define identifiers and
parameters before using a SHA-3 or BLAKE2 HMAC/KDF combination; generic template
compatibility by itself is not an interoperability profile.

```cpp
using hmac_t = ctl::mac::hmac<ctl::hash::sha256>;
hmac_t::tag_t tag;
hmac_t::authenticate(key, message, tag);

if (!hmac_t::verify(key, received_message, tag)) {
  // Reject before using received_message as authenticated data.
}
```

The streaming HMAC form also consumes the current message at `finish`.
`reset()` begins another message under the same key, while `set_key()` replaces
the key. The context does not retain the caller's buffer, but it necessarily
keeps an equivalent key-derived outer pad until rekeying or destruction and
therefore has to be protected like the key itself.

HKDF follows RFC 5869's extract and expand split. Usually the combined form is
the right one; `info` should name the protocol, purpose and context so derived
keys for different uses are separated.

```cpp
std::vector<uint8_t> session_key(32);
ctl::kdf::hkdf<ctl::hash::sha256>::derive(
    salt, shared_secret, protocol_context, session_key);
```

An empty salt has the RFC's defined zero-salt meaning. Output is capped at
`255 * HashLen` and must be disjoint from salt, input key material and info.
HKDF extracts entropy already present in key material; it is not a substitute
for password stretching.

PBKDF2-HMAC accepts the password as octets and gives no character encoding an
implicit meaning. Its work factor is mandatory and has no library default.

```cpp
std::vector<uint8_t> password_key(32);
ctl::kdf::pbkdf2<ctl::hash::sha256>::derive(
    password_bytes, per_password_salt, deployment_iterations, password_key);
```

Choose and periodically review `deployment_iterations` by benchmarking the
actual deployment and following its current security profile. The 80,000
iteration value in the RFC 7914 test is a known answer, not a recommendation.
RFC 8018's positive iteration and output-length requirements are enforced;
salt quality and an adequate work factor remain application policy. KDF output
must be disjoint from password and salt. All intermediate PRKs, HMAC pads and
PBKDF2 `U` values owned by the library are erased on success and exception, but
the caller remains responsible for erasing its password and derived-key
buffers.

## A block cipher on its own

```cpp
cipher::aes<128> aes(key);
aes.encrypt_block(in, out);
aes.decrypt_block(out, back);
```

## CTR, with random access

An offset can be given, so a stream is picked up in the middle without
processing what comes before it.

```cpp
mode::ctr<cipher::aes<128>> ctr(key);
ctr.crypt(nonce, byte_offset, in, out);
```

For encryption, every counter block used under a key has to be unique across
all messages. The initial counter and the offset ranges handed to separate
calls therefore have to be allocated together; the library does not retain a
history of them. This is the uniqueness requirement in
[SP 800-38A appendix B](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf).

## Entropy, DRBGs and the owned RBG

`ctl::random_bytes` fills a buffer directly from the operating system. It is
the normal choice when an application just needs a key or nonce. The three
SP 800-90A generator families are separate deterministic state machines:

- `ctr_drbg<aes<Bits>>` conditions separate entropy, nonce and optional
  personalization strings with `Block_Cipher_df`; this is the recommended CTR
  form and therefore owns the unqualified name.
- `ctr_drbg_no_df<aes<Bits>>` takes exactly `seed_size` full-entropy bytes and
  is reserved for callers whose upstream design already supplies that exact
  seed contract.
- `hmac_drbg<Sha2>` and `hash_drbg<Sha2>` implement their named SHA-2 based
  mechanisms. Only the SHA-2 types approved by SP 800-90A Rev. 1 are accepted;
  generic compatibility with SHA-3 or BLAKE2 is deliberately not presented as
  an approved DRBG profile.

The high-level form owns both the DRBG and its system entropy source. It seeds
on construction, automatically reseeds before the selected request interval,
and on Unix-like systems detects a changed process ID and reseeds before the
child can generate. It accepts the three conditioned forms (`ctr_drbg`,
`hmac_drbg` and `hash_drbg`); the deliberately different no-DF seed contract
is not hidden behind this wrapper.

```cpp
using drbg_t = ctl::hmac_drbg<ctl::hash::sha256>;
ctl::rbg<drbg_t> random;

random.generate(out);
random.generate_fresh(session_key); // reseed immediately before this request
```

For deterministic testing or a protocol that supplies its own entropy and
nonce, instantiate the mechanism directly:

```cpp
uint8_t entropy[ctl::ctr_drbg<cipher::aes<256>>::entropy_size];
uint8_t nonce[ctl::ctr_drbg<cipher::aes<256>>::nonce_size];
ctl::random_bytes(entropy);
ctl::random_bytes(nonce);

ctl::ctr_drbg<cipher::aes<256>> generator(entropy, nonce, context);
generator.generate(out, additional_input);
```

All generators cap one request at 2^19 bits and refuse to pass the SP 800-90A
2^48-request reseed limit. Entropy and nonce arguments enforce their minimum
lengths, but a byte count cannot prove that input really contains the claimed
entropy. Additional input must be disjoint from output. DRBG and RBG objects
cannot be copied; moving transfers and erases the one state. Direct DRBG use
still requires explicit reseeding after `fork`; the `rbg` wrapper performs the
process-ID check where that facility exists. None is safe for concurrent calls
without external synchronization.

`rbg` is a policy wrapper, not a claim that the opaque output of a host API has
itself received SP 800-90B validation. A FIPS or SP 800-90C deployment must
still validate its complete entropy-source and module boundary.

## XTS, for storage

The two component keys are supplied separately, and a data unit number such as
a sector number becomes the tweak. For AES-256 each component is 32 bytes; the
caller does not concatenate them or calculate the split point.

```cpp
using xts_t = mode::xts<cipher::aes<256>>;
xts_t::component_key_t data_key, tweak_key;
ctl::random_bytes(data_key);
ctl::random_bytes(tweak_key);

xts_t xts(data_key, tweak_key);
xts.encrypt(sector_number, sector, out);
```

K1 (`data_key`) encrypts the data and K2 (`tweak_key`) encrypts the tweak. They
have to be generated or established independently. The constructor also rejects
equal values as required by
[FIPS 140-3 Implementation Guidance C.I](https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf).
That comparison catches one prohibited value pair; it cannot establish how two
different keys were generated, which remains the caller's responsibility.

## GCM, authenticated with associated data

Additional authenticated data stays in the clear but is covered by the tag,
which is what binds a ciphertext to its context. Inputs are given as a list of
runs, so data spread over several buffers needs no copying first. GHASH consumes
the concatenation of a list, so where the runs are split makes no difference,
though their order does.

Every encryption under one key needs an IV that has not been used for another
set of inputs. Repetition can expose plaintext and make tag forgery possible,
and a local type cannot prove uniqueness across processes, restarts and
devices. The caller has to arrange that scope as required by
[SP 800-38D section 8](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
Decryption uses the IV that arrived with the ciphertext; it does not allocate a
new one.

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
auto writer =
    gcm.encryptor(iv).aad(header).data(ctl::writable_bytes(out));
while (read(chunk, &n)) {
  writer.write(ctl::bytes(chunk, n));
}
writer.finish(tag);
```

That is the usual form: the writer holds one output buffer and advances through
it itself. When each run really belongs in a different buffer, leave the output
out of `data` and give a destination to each write instead. This is a separate
invocation and therefore uses its own IV.

```cpp
auto scattered = gcm.encryptor(fresh_iv).aad(header).data();
scattered.write(first, first_destination)
         .write(second, second_destination);
scattered.finish(scattered_tag);
```

Input and output may be disjoint or exactly in place. A shifted overlap such as
writing at `input + 1` is refused rather than given direction-dependent
semantics. The scatter form can check the two buffers of the current write, but
cannot know that an earlier output covers input the caller will supply later;
those cross-call ranges remain the caller's responsibility.

The tag must not cover any data-output byte. It may immediately follow the data
in the same allocation, as in the packet example above. A writer that holds its
output knows how much it has written and enforces the same rule at `finish`; a
scatter writer no longer retains all earlier destinations, so their relationship
to the tag remains the caller's responsibility.

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
name. Phase and writer objects cannot be copied, because a copy would fork one
IV into two identical key streams. Moving is a transfer, moving from AAD to data
consumes the AAD phase, and `finish` consumes the invocation; using an earlier
phase or a finished writer throws `std::logic_error`. Both forms also refuse to
carry one invocation past the roughly 64 GiB the specification allows, because
the counter is only the last four bytes of the block and past that limit the key
stream repeats.

---

[Back to the README](../README.md)
