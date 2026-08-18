# Internal security review

Review completed 2026-08-19. This is a source-assisted internal review, not an
independent third-party audit, a FIPS validation, or a certification of fitness
for a particular protocol. It records what was examined, what was corrected,
and what a caller still has to provide.

## Scope

The review covered the byte-view boundary, AES, ARIA, LEA, ECB, CBC, CTR, XTS,
GCM and GHASH, SHA-2, the four fixed-output SHA-3 functions, SHAKE128 and
SHAKE256, unkeyed BLAKE2s and BLAKE2b, HMAC, HKDF, PBKDF2, operating-system
entropy, CTR_DRBG with and without derivation, HMAC_DRBG, Hash_DRBG, the
system-fed RBG policy, run-time instruction dispatch, endian conversion,
secret-state erasure, and the native and cross-target tests.

The `ext` result type, operating-system RNG implementations themselves,
application protocols, key storage, process isolation, compiler correctness,
and physical side-channel behaviour were outside the source-review boundary.
QEMU was used to establish cross-target functional correctness and dispatch,
not physical-hardware timing.

The specifications and guidance used for the security properties were
[FIPS 197](https://csrc.nist.gov/pubs/fips/197/final),
[SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final),
[SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
[SP 800-38E](https://csrc.nist.gov/pubs/sp/800/38/e/final),
[SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final),
[SP 800-90C](https://csrc.nist.gov/pubs/sp/800/90/c/final),
[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final),
[FIPS 202](https://csrc.nist.gov/pubs/fips/202/final),
[SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final),
[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104),
[RFC 4231](https://www.rfc-editor.org/rfc/rfc4231),
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869),
[RFC 8018](https://www.rfc-editor.org/rfc/rfc8018),
[RFC 7693](https://www.rfc-editor.org/rfc/rfc7693), and
[RFC 5794](https://www.rfc-editor.org/rfc/rfc5794).

## Method

- Read every public header and the implementation paths it selects, following
  buffer lengths, overlap, integer bounds, state transitions, key-derived
  temporaries, and destruction.
- Compiled every public header by itself with both Clang and GCC under C++17,
  with warnings promoted to errors.
- Built and ran the suite with Clang warnings, AddressSanitizer and
  UndefinedBehaviorSanitizer, both with normal dispatch and with
  `CTL_NO_HW_ACCEL`.
- Differentially compared 300 generated cases in each build against OpenSSL
  for AES-ECB, AES-CBC, AES-CTR, AES-GCM (including non-96-bit IVs), and
  AES-XTS (including ciphertext stealing).
- Differentially compared another 300 generated cases for each of the six
  SHA-2, four fixed-output SHA-3 and standard-size BLAKE2s/BLAKE2b variants
  against OpenSSL for digest, HMAC, HKDF and PBKDF2 results, compiling the
  reference harness with both Clang and GCC warning sets.
- Compared all 96 permitted BLAKE2 digest byte lengths with Python `hashlib`
  for every input length from 0 through 512 bytes: 49,248 independent answers.
- Compared SHAKE128 and SHAKE256 with Python `hashlib` over 1,250 input/output
  combinations around both absorb and squeeze rates. NIST's empty and
  1,600-bit messages were also checked against their published 2,048-bit
  outputs, which cross the first squeeze boundary in both functions.
- Built the current tree in four MSVC Release configurations (normal,
  `CTL_NO_HW_ACCEL`, `CTL_AES_CONSTANT_TIME`, and both) and ran all 196 Windows
  tests in each. The same 196 tests pass under MSVC AddressSanitizer, and every
  new public random and XOF header compiles alone with `/W4 /WX`.
- Compared CTR_DRBG no-DF and with-DF, HMAC_DRBG and Hash_DRBG with the
  [NIST CAVP DRBG response files](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators).
  The cases cover AES-128/192/256 no-DF, AES-128/192/256 with-DF,
  SHA-256 HMAC/Hash generation, SHA-512's 888-bit and SHA-512/224's 440-bit
  Hash_DRBG seeds, optional personalization and additional input, and explicit
  reseeding.
- Ran coverage-guided structural fuzzing with ASan and UBSan over AES, ARIA,
  LEA, CTR, GCM and XTS: 50,000 inputs with normal dispatch and 50,000 with
  hardware acceleration disabled.
- Ran a separate ASan/UBSan structural target over all twelve standard-size
  fixed hashes, both SHAKE functions, HMAC, HKDF and PBKDF2 for 50,000 inputs.
  It checked streaming against one-shot hashing and XOF expansion, split
  squeezes, HMAC verification, extract-plus-expand against combined HKDF, and
  partial PBKDF2 output against the corresponding full derivation.
- Ran the complete cross-target matrix after the corrections, including both
  MIPS byte orders and the MSA paths; all 197 Unix tests passed in every target.
  Cross compilers were kept from
  auto-vectorizing unrelated loops where the documented big-endian GCC issue
  would otherwise introduce a false failure.

## Corrected findings

| ID | Severity | Finding and resolution |
| --- | --- | --- |
| CTL-2026-01 | High | `ctr_drbg_no_df` was implicitly copyable. A copy cloned the key and counter and could emit the same bytes as the source, which is especially dangerous when the output becomes keys or nonces. Copying is now deleted. Moving transfers the state, erases the source and makes the source reject use until it is explicitly instantiated with a fresh seed. |
| CTL-2026-02 | High | Incremental GCM phase and writer objects were implicitly copyable, and moving from AAD to data copied the session. Retaining or copying a phase could fork one key/IV into two identical key streams. Phase transitions now consume and erase the source state, phase objects cannot be copied, moves are transfers, and `finish` consumes the invocation so it cannot be written or finished twice. |
| CTL-2026-03 | Medium | The Windows entropy path narrowed a `size_t` request to BCryptGenRandom's 32-bit `ULONG`. A request above 4 GiB could report success after filling only the truncated prefix. Requests are now split into representable runs before the call. The API signature and its `ULONG cbBuffer` are documented by [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom). |
| CTL-2026-04 | Medium | ECB, CBC, CTR and XTS promised exact in-place operation but did not reject shifted overlap. A forward transform could overwrite input a later block had not read. All public variable-length transforms now accept disjoint ranges or the exact same starting address and reject every other overlap before writing. |
| CTL-2026-05 | Medium | GCM allowed its tag buffer to overlap the data output. Encryption could overwrite ciphertext after authenticating it, and decryption could overwrite the supplied tag before checking it. Single-call GCM and held-output writers now require the tag to be disjoint from data already written while still allowing the usual appended layout. |
| CTL-2026-06 | Low | GHASH erased byte arrays with volatile writes but cleared its scalar copies of the hash subkey and accumulator with ordinary destructor assignments, which a compiler may discard. Some ARIA/LEA key-derived temporaries and staged key stream blocks also lacked explicit erasure. Those values now use the same non-elidable erasure path. |
| CTL-2026-07 | Low | `ghash` selected the x86 polynomial-multiply implementation after deciding which intrinsic header to include, and `ctr` used endian helpers without including their header. Both compiled only when another header happened to precede them. Selection now precedes the intrinsic include and every public header compiles independently. |
| CTL-2026-08 | Low | The structural fixed-hash trait checked operation names but not that digest storage and fixed views actually matched `digest_size`. Generic HMAC/KDF code could therefore accept a malformed external type and fail only when the incompatible buffer was used. The trait now requires nonzero `size_t` constants and exact array/view extents, with negative compile-time tests. |
| CTL-2026-09 | Low | BLAKE2 length preflight prevented a valid call from overflowing its counter, but the internal counter increment still relied on that invariant and did not itself reject a final carry past 64 or 128 bits. Every increment is now checked, including the buffered final block; an excessive message is rejected before update writes state. |
| CTL-2026-10 | Medium | HMAC_DRBG consumes additional input both before and after producing output. If that input shared the output buffer, the first output bytes could silently change the value consumed by the state update. Every DRBG and the RBG policy now require additional input to be disjoint from output and reject overlap before changing state. |
| CTL-2026-11 | Medium | The old templated CTR_DRBG accepted any 128-bit block cipher even though the current SP 800-90A approved profile is AES. Both CTR mechanisms now accept only CTL AES-128/192/256, and the SHA mechanisms likewise allow-list the approved CTL SHA-2 types instead of treating generic SHA-3/BLAKE2 compatibility as a validation profile. |
| CTL-2026-12 | Low | An invalid oversized `rbg::generate_fresh` request could obtain entropy and reseed before the underlying DRBG rejected its output length. RBG request length and overlap are now checked before entropy acquisition, with an injected-source test confirming that failure leaves the source count and DRBG request count unchanged. |
| CTL-2026-13 | Low | A shared big-endian increment helper stopped after the first non-`0xff` byte, making its trip count depend on secret DRBG state. CTR and Hash generator increments now traverse their complete fixed-width values and propagate carry arithmetically. |
| CTL-2026-14 | Medium | The first Hash_DRBG extension inferred `seedlen` from SHA-512's internal block family and therefore assigned 888 bits to SHA-512/224 and SHA-512/256. SP 800-90A Table 2 assigns both truncated functions 440 bits. The traits were corrected before release, compile-time assertions fix all six mappings, and a SHA-512/224 CAVP answer now exercises the non-obvious case. |

No unresolved source finding at any severity remained at the end of this
review. All low-severity findings above were corrected as well.

## SHA-2 and KDF extension review

- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256 use the FIPS
  initial values, padding and big-endian length encodings. The 64-bit family
  maintains the 128-bit message length as two portable 64-bit halves rather
  than relying on a compiler extension.
- Hash and HMAC contexts cannot be copied. Moves transfer and erase the source;
  finish consumes the current message. HMAC comparison is content-independent,
  and only complete tags cross the generic interface.
- HKDF checks its `255 * HashLen` limit before writing. PBKDF2 rejects zero
  iterations, zero-length output and output beyond `(2^32 - 1) * HashLen`
  before writing. Both reject input/output overlap before derivation starts.
- Key-derived stack buffers have RAII erasure, including exception unwinding.
  KDF output is erased if an unexpected exception occurs after writing begins.
  Hash state, HMAC pads, PRKs and PBKDF2 intermediate values are also erased at
  their explicit lifecycle boundaries.

## Hash and XOF extension review

SHA-3, SHAKE and BLAKE2 were source-reviewed against FIPS 202 and RFC 7693,
compiled as independent public headers with Clang and GCC warning sets and with
MSVC under C++17, and included in both sanitizer builds and all thirteen target
configurations. Empty, exact-block and multi-block answers, every streaming
split point, and move/finish/reset lifecycle are covered. The fixed hashes are
also covered through generic HMAC/KDF composition; SHAKE remains outside those
fixed-output templates. The SHA-3 tests include NIST's byte-aligned 1,600-bit
sample for all four output sizes as well as empty and `abc` answers.

- SHA3-224, SHA3-256, SHA3-384 and SHA3-512 use Keccak-f[1600], their FIPS 202
  rates and the SHA-3 `01` domain suffix followed by multi-rate padding. SHAKE
  shares that reviewed permutation and sponge plumbing but is not exposed
  through the fixed-output interface.
- BLAKE2s and BLAKE2b retain the last input block until `finish`, apply the RFC
  final-block flag there, and maintain their 64-bit and 128-bit byte counters
  as portable word pairs with checked overflow. Digest size is fixed in the
  type, and every byte length accepted by RFC 7693 was differentially tested.
  The RFC's native keyed mode remains outside the unkeyed hash interface.

## SHAKE XOF extension review

- SHAKE128 and SHAKE256 use the FIPS 202 rates of 1,344 and 1,088 bits, the
  SHAKE `1111` domain suffix and multi-rate padding. The public byte interface
  materializes that suffix as `0x1f`, matching NIST's intermediate examples.
- The XOF lifecycle is a state machine: input is accepted only while absorbing,
  `finish` makes a one-way transition, and `squeeze` is accepted only after
  that transition. Repeated squeezes retain the exact byte position across
  permutation boundaries. Reset begins a new invocation; copying is forbidden,
  and moving transfers and erases either an absorbing or squeezing state.
- The structural XOF contract has no digest storage or digest size and does not
  satisfy the fixed-hash contract used by HMAC and the KDF templates. Output
  length remains protocol policy, and the byte-oriented API deliberately omits
  non-byte-aligned FIPS 202 inputs and outputs.

## DRBG and RBG extension review

- CTR_DRBG implements both section 10.2.1 branches as distinct types. The
  no-DF type requires exactly the key-plus-counter seed length of full entropy;
  the DF type implements `Block_Cipher_df`, including its BCC stage and encoded
  byte lengths, and enforces the entropy and nonce minima for each AES size.
- HMAC_DRBG follows section 10.1.2's two-stage Update, including the mandatory
  post-generation update. Hash_DRBG follows section 10.1.1's `Hash_df`,
  `Hashgen`, modular additions and the separate 440/888-bit seed lengths.
- Every mechanism enforces the 2^19-bit per-request and 2^48-request reseed
  limits, minimum entropy and nonce byte counts, input length bounds, move-only
  ownership and non-elidable state erasure. Counter and modular-addition loops
  have fixed trip counts rather than terminating on secret carry values. Length
  checks can establish buffer size, not entropy quality.
- `rbg` obtains separate entropy and nonce inputs on construction, obtains new
  entropy for scheduled, explicit and fresh-request reseeds, and checks the
  process ID before generation where the platform exposes one. Entropy-source
  failure leaves the DRBG state unchanged. It does not claim that an opaque OS
  API is a separately validated SP 800-90B source or that the wrapper alone is
  an SP 800-90C/FIPS validated module.

## Residual risks and caller obligations

- AES and ARIA use secret-indexed tables on their default software paths. Use
  processor instructions or the AES table-free build where cache timing is in
  the threat model. CTR_DRBG inherits the AES choice; HMAC_DRBG and Hash_DRBG
  do not use secret-indexed tables. ARIA has no table-free scalar path.
- ECB, CBC, CTR and XTS do not authenticate data. Their successful decryption
  says nothing about integrity. Prefer an authenticated construction such as
  GCM where its nonce requirements can be met.
- CBC IV unpredictability, CTR counter-block uniqueness, GCM IV uniqueness,
  and XTS data-unit/tweak allocation are system-wide properties. A local C++
  type cannot enforce them across threads, processes, restarts or devices.
- GCM piece order is semantically significant. The scatter writer cannot know
  that an output from an earlier call covers input that will be supplied later,
  and it cannot recover all plaintext on an incremental authentication failure.
- A byte view does not own storage. The caller must keep its backing object
  alive and, when using the explicit pointer-and-length escape hatch, must
  describe a real range of that length.
- Sensitive values can still exist in caller buffers, object copies outside
  this library, registers, crash dumps, swap and allocator remnants. The
  library erases the state it owns but does not lock pages or manage the
  caller's key storage.
- An unkeyed hash alone is not a MAC. HKDF is not a password-stretching
  function, and its `info` value has to provide the application-specific domain
  separation the protocol needs. PBKDF2 salt generation, password encoding and
  work-factor
  policy remain caller obligations; the RFC 7914 test iteration count is not a
  safe default.
- Generic HMAC-BLAKE2 is not RFC 7693's native keyed BLAKE2 mode. BLAKE2 is
  not a NIST-approved hash algorithm, and generic SHA-3/BLAKE2 HMAC or KDF
  instantiation does not create protocol identifiers or a deployment profile.
- SHAKE output length is not domain separation. Outputs of different lengths
  for the same input share a prefix, so a protocol must encode distinct
  purposes in the absorbed input when independent outputs are required.
- A live DRBG, RBG or incremental writer is mutable state and is not safe for
  concurrent calls without external synchronization. Direct DRBG users must
  reseed a child after `fork`; `rbg` performs a process-ID check on supported
  platforms, but an unsupported platform cannot provide that protection.
- Functional tests do not prove constant-time execution on every compiler and
  processor. The MIPS/MSA results under QEMU establish results and path
  selection only; physical equipment is still needed for timing and throughput
  claims.

## Release recommendation

Keep the warning, sanitizer, differential and cross-target checks as release
gates. Before using this library as a production trust boundary, commission an
independent review against the intended protocol and deployment, test on the
actual MIPS hardware where that path matters, and document how keys and unique
IV/counter/tweak values are allocated for the lifetime of the system.

---

[Back to status and limits](limits.md)
