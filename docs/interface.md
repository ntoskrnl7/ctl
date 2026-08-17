# Using it

Every call takes buffers that carry their own length, and every length an
algorithm fixes is part of a type. What follows is one example of each cipher
and mode, and the reasoning behind the shape they share.

Headers carry no extension, in the same style as `ext`.

```cpp
#include <ctl/bytes>                    // bytes, writable_bytes
#include <ctl/random/system>            // random_bytes, from the system
#include <ctl/random/ctr_drbg>          // ctr_drbg<Cipher>, SP 800-90A
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

## Entropy and CTR_DRBG

`ctl::random_bytes` fills a buffer from the operating system. `ctr_drbg` turns a
full-entropy seed into repeated bounded requests using the no-derivation-
function construction from SP 800-90A.

```cpp
using drbg_t = ctl::ctr_drbg<cipher::aes<256>>;
uint8_t seed[drbg_t::seed_size];
ctl::random_bytes(seed);

drbg_t generator(seed);
generator.generate(out);
```

A generator cannot be copied: copying its key and counter would create two
objects that emit the same stream. It can be moved, which transfers the state
and erases the source. The moved-from object refuses generation and reseeding
until `instantiate` gives it a fresh seed. It also must be reseeded in the child
after a process fork, and concurrent access requires external synchronization.

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
