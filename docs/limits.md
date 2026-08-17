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

The ARIA MSA path also has no secret-indexed memory lookup. It evaluates the
S-boxes as a bitwise tower-field circuit over eight blocks and uses `vshf.b`
only for fixed diffusion permutations; this statement is about its
memory-access pattern, not a physical-hardware throughput result.

GHASH never uses a table either, for the same reason and a sharper one: a
GHASH table is built from the hash subkey itself and indexed by data derived
from it. What it uses instead is in [what runs on what](acceleration.md).

---

[Back to the README](../README.md)
