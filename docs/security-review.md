# Internal security review

Review completed 2026-08-18. This is a source-assisted internal review, not an
independent third-party audit, a FIPS validation, or a certification of fitness
for a particular protocol. It records what was examined, what was corrected,
and what a caller still has to provide.

## Scope

The review covered the byte-view boundary, AES, ARIA, LEA, ECB, CBC, CTR, XTS,
GCM and GHASH, operating-system entropy, CTR_DRBG, run-time instruction
dispatch, endian conversion, secret-state erasure, and the native and cross
target tests.

The `ext` result type, operating-system RNG implementations themselves,
application protocols, key storage, process isolation, compiler correctness,
and physical side-channel behaviour were outside the source-review boundary.
QEMU was used to establish cross-target functional correctness and dispatch,
not physical-hardware timing.

The normative references used for the security properties were
[FIPS 197](https://csrc.nist.gov/pubs/fips/197/final),
[SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final),
[SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
[SP 800-38E](https://csrc.nist.gov/pubs/sp/800/38/e/final),
[SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final), and
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
- Ran coverage-guided structural fuzzing with ASan and UBSan over AES, ARIA,
  LEA, CTR, GCM and XTS: 50,000 inputs with normal dispatch and 50,000 with
  hardware acceleration disabled.
- Ran the complete cross-target matrix after the corrections, including both
  MIPS byte orders and the MSA paths. Cross compilers were kept from
  auto-vectorizing unrelated loops where the documented big-endian GCC issue
  would otherwise introduce a false failure.

## Corrected findings

| ID | Severity | Finding and resolution |
| --- | --- | --- |
| CTL-2026-01 | High | `ctr_drbg` was implicitly copyable. A copy cloned the key and counter and could emit the same bytes as the source, which is especially dangerous when the output becomes keys or nonces. Copying is now deleted. Moving transfers the state, erases the source and makes the source reject use until it is explicitly instantiated with a fresh seed. |
| CTL-2026-02 | High | Incremental GCM phase and writer objects were implicitly copyable, and moving from AAD to data copied the session. Retaining or copying a phase could fork one key/IV into two identical key streams. Phase transitions now consume and erase the source state, phase objects cannot be copied, moves are transfers, and `finish` consumes the invocation so it cannot be written or finished twice. |
| CTL-2026-03 | Medium | The Windows entropy path narrowed a `size_t` request to BCryptGenRandom's 32-bit `ULONG`. A request above 4 GiB could report success after filling only the truncated prefix. Requests are now split into representable runs before the call. The API signature and its `ULONG cbBuffer` are documented by [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom). |
| CTL-2026-04 | Medium | ECB, CBC, CTR and XTS promised exact in-place operation but did not reject shifted overlap. A forward transform could overwrite input a later block had not read. All public variable-length transforms now accept disjoint ranges or the exact same starting address and reject every other overlap before writing. |
| CTL-2026-05 | Medium | GCM allowed its tag buffer to overlap the data output. Encryption could overwrite ciphertext after authenticating it, and decryption could overwrite the supplied tag before checking it. Single-call GCM and held-output writers now require the tag to be disjoint from data already written while still allowing the usual appended layout. |
| CTL-2026-06 | Low | GHASH erased byte arrays with volatile writes but cleared its scalar copies of the hash subkey and accumulator with ordinary destructor assignments, which a compiler may discard. Some ARIA/LEA key-derived temporaries and staged key stream blocks also lacked explicit erasure. Those values now use the same non-elidable erasure path. |
| CTL-2026-07 | Low | `ghash` selected the x86 polynomial-multiply implementation after deciding which intrinsic header to include, and `ctr` used endian helpers without including their header. Both compiled only when another header happened to precede them. Selection now precedes the intrinsic include and every public header compiles independently. |

No unresolved source finding at any severity remained at the end of this
review. The two low-severity findings above were corrected as well.

## Residual risks and caller obligations

- AES and ARIA use secret-indexed tables on their default software paths. Use
  processor instructions or the AES table-free build where cache timing is in
  the threat model. ARIA has no table-free scalar path.
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
- A live DRBG or incremental writer is mutable state and is not safe for
  concurrent calls without external synchronization. A process fork still
  requires reseeding the child before it generates output.
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
