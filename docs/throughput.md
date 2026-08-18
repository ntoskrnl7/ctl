# Measured throughput

Numbers from one machine, all of them taken in one sitting. The last section
says what they are worth against numbers from anywhere else.

AES-128 over a 4096 byte buffer, Intel Core Ultra 7 265K, MSVC `/O2`. These are
only comparable to one another because the machine was in the same state for
all of them; a figure carried over from another session has looked like a code
change here more than once, so none are.

| Mode | Software | Accelerated |
| --- | --- | --- |
| ECB | 565 MB/s | 11,505 MB/s |
| CTR | 490 | 4,600 |
| XTS | 482 | 6,403 |
| GCM | 271 | 1,971 |
| CBC, which chains and cannot be parallelized | 436 | 1,623 |

No operation performs a heap allocation.

The other two ciphers, over the same buffer.

| | ECB | CTR | XTS | GCM |
| --- | --- | --- | --- | --- |
| LEA-128, eight blocks at a time, AVX2 | 3,545 MB/s | 2,259 | 2,749 | 1,366 |
| LEA-128, four blocks at a time, SSE2 | 1,873 | 1,520 | 1,589 | 1,130 |
| LEA-128, one block at a time | 823 | 541 | 453 | 227 |
| ARIA-128, vector path | 247 | 226 | 204 | 199 |
| ARIA-128, one block at a time | 117 | 112 | 105 | 86 |

The row that matters is the third one against the software column of the first
table: with
no instruction to help either cipher, LEA is about half again the throughput of
AES and gets there with no table at all. Where both have their instructions AES
is three times LEA in ECB, since AES-NI has no equal here, and the gap narrows
in GCM where the tag is a share of the work.

The measured ARIA row is the x86 vector path. It processes one block at a time,
so there a mode asks whether handing over a batch is worthwhile and ARIA answers
no. The MSA path is different: it bitslices eight independent blocks and asks
parallel modes for a full batch, while a single block and a partial batch use
the scalar path.

There is deliberately no MIPS MSA throughput row. That path has been cross
built and run under QEMU in both byte orders, which verifies its results and
dispatch but not its speed. QEMU translates individual MSA instructions in
software and its relative cost for operations such as `vshf.b` need not match a
physical processor. A throughput claim therefore waits for one-session
measurements on real MSA hardware.

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

## Where random bytes come from

Two things, and they are not the same.

Entropy cannot be computed. It has to be observed from the machine, so
`ctl::random_bytes` asks the system for it: `BCryptGenRandom` on Windows,
`getrandom` on Linux, `getentropy` on Apple and BSD. Nothing is implemented
there because there is nothing there to implement.

The deterministic generators are algorithms and therefore live here:
CTR_DRBG with and without `Block_Cipher_df`, HMAC_DRBG and Hash_DRBG. The AES
and SHA-2 profiles are checked against NIST CAVP vectors covering optional
personalization, additional input and reseeding as well as the simple path.
The distinction matters in a validated deployment: a named mechanism with
known answers can be assessed, while an opaque host facility cannot be claimed
as that mechanism merely because it returns random-looking bytes.

```cpp
using drbg_t = ctl::hmac_drbg<ctl::hash::sha256>;
ctl::rbg<drbg_t> random;
mode::gcm<cipher::aes<256>>::tag_t tag;
uint8_t iv[12];
random.generate(iv);
```

The high-level `rbg` owns a system entropy provider and one DRBG. It seeds on
construction, automatically reseeds before its configured request limit and
reseeds after a detectable process fork. Direct mechanism types remain
available where deterministic inputs or an externally validated entropy source
are required. The no-derivation CTR form still deliberately requires exactly
`seed_size` full-entropy bytes; its name is `ctr_drbg_no_df` so that constraint
cannot be missed.

These are correctness and lifecycle claims, not throughput claims. No random
generator number is published because system-call cost, reseed policy, AES/SHA
acceleration and request size would have to be measured and reported together.

---

[Back to the README](../README.md)
