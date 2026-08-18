# Status and limits

What this library has and has not been through, and the properties worth
knowing before choosing a build of it.

Written from the specifications and checked against their published vectors. It
has undergone a documented [internal security review](security-review.md), but
has not been independently audited. Where an independently audited or validated
implementation is a requirement, use one.

ARIA is table driven on its software path, and so is AES unless the
[table free path](acceleration.md) is selected. Table lookups indexed by key
dependent data can leak through cache timing; the AES-NI path, the ARM path and
the table free path do not have that property, and neither does LEA on any
path, since it has no table to index.

CTR_DRBG uses AES and inherits that choice. On a processor without AES
instructions, select the table-free AES build when cache timing is in scope, or
use HMAC_DRBG/Hash_DRBG, whose SHA-2 paths have no secret-indexed lookup.

The ARIA MSA path also has no secret-indexed memory lookup. It evaluates the
S-boxes as a bitwise tower-field circuit over eight blocks and uses `vshf.b`
only for fixed diffusion permutations; this statement is about its
memory-access pattern, not a physical-hardware throughput result.

SHA-2, SHA-3, BLAKE2, HMAC, HKDF and PBKDF2 use no lookup or branch indexed by
secret byte values; control flow still depends on public lengths and iteration
counts. A plain digest does not authenticate a message and ad hoc constructions
such as `SHA256(key || message)` can have extension and composition problems;
use a standardized MAC where authentication is required. RFC 7693's native
keyed BLAKE2 mode is not exposed by the unkeyed
hash type in this release. HMAC-BLAKE2 is a different construction. BLAKE2 is
specified by an Informational RFC and is not one of
[NIST's approved hash algorithms](https://csrc.nist.gov/projects/hash-functions);
do not place it inside a FIPS-approved boundary on the strength of this
implementation or review.

The SHA-3 interface covers the four fixed-output FIPS 202 hashes, and the
separate XOF interface covers SHAKE128 and SHAKE256. Both accept byte-aligned
messages and outputs; they do not represent FIPS 202 strings whose bit length
is not a multiple of eight. SHAKE output lengths are not domain separators:
shorter output is a prefix of longer output for the same message, so protocols
must separate purposes in the input.

HKDF assumes input keying material with suitable entropy. It does not slow
password guessing. PBKDF2 does, but it is CPU-hard rather than memory-hard and
its safety depends on a unique salt and a work factor calibrated for the actual
deployment. The library deliberately supplies no iteration default that could
age unnoticed. NIST's current
[SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final) remains final while a
revision that will add a memory-hard construction is planned; application
policy should be reviewed when that guidance changes.

The SP 800-90A mechanisms are restricted to the approved AES and SHA-2 types
implemented here. `ctr_drbg_no_df` requires exactly its full-entropy seed size;
the recommended `ctr_drbg` applies the derivation function when entropy, nonce
and personalization are separate inputs.
DRBG input-length checks cannot measure entropy quality. Direct generators do
not reseed themselves or serialize concurrent access. The `rbg` policy obtains
fresh system bytes for construction and reseeding and detects a changed process
ID on supported platforms, but it is not evidence that the host facility has
undergone SP 800-90B entropy-source validation or that the combined binary is a
validated SP 800-90C/FIPS module.

GHASH never uses a table either, for the same reason and a sharper one: a
GHASH table is built from the hash subkey itself and indexed by data derived
from it. What it uses instead is in [what runs on what](acceleration.md).

---

[Back to the README](../README.md)
