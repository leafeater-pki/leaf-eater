# Leaf Eater Rule Catalog

This document describes every lint rule in `leaf-eater` v0.1.0-d02. Each rule
cites `draft-ietf-plants-merkle-tree-certs-02` by section and line number.

## Severity levels

| Severity | Meaning |
|----------|---------|
| NA       | Rule does not apply to this cert |
| NE       | Not evaluated (rule execution failed) |
| Pass     | Rule checked and passed |
| Notice   | Informational, not a draft violation |
| Warn     | Soft violation (draft SHOULD) |
| Error    | Draft MUST violation |
| Fatal    | Rule engine panic (parser crashed or invariant violated) |

## Rules

### MTC_R001_d02: Signature Algorithm OID

**Draft:** §6.1 lines 1977-1987
**Severity on failure:** Error
**Applies when:** The cert parsed as X.509. In default mode, also requires
`Proof != nil` (an MTC-shaped cert). `-strict` forces R001 to run on every
cert.

**Check:** The TBSCertificate's `signatureAlgorithm` OID must equal
`id-alg-mtcProof`. Draft-02 assigns the experimental OID
`1.3.6.1.4.1.44363.47.0`; the production OID is not yet allocated. When the
experimental OID matches, R001 emits a Notice to remind the user the OID is
experimental.

Draft text (lines 1977-1987):

> The TBSCertificate's signature and the Certificate's
> signatureAlgorithm MUST contain an AlgorithmIdentifier whose
> algorithm is id-alg-mtcProof, defined below, and whose parameters is
> omitted.
>
> id-alg-mtcProof OBJECT IDENTIFIER ::= {
>     iso(1) identified-organization(3) dod(6) internet(1) security(5)
>     mechanisms(5) pkix(7) algorithms(6) TBD }
>
> For initial experimentation, early implementations of this design
> will use the OID 1.3.6.1.4.1.44363.47.0 instead of id-alg-mtcProof.

### MTC_R002_d02: Subtree Bounds

**Draft:** §4.1 line 646
**Severity on failure:** Error
**Applies when:** `Proof != nil`

**Check:** `MTCProof.start` must be strictly less than `MTCProof.end`.

Draft text (lines 644-646):

> A _subtree_ of this Merkle Tree is itself a Merkle Tree, defined by
> MTH(D[start:end]). start and end are integers such that:
>
> *  0 <= start < end <= n

Example violation: `start=5 end=5`.

### MTC_R003_d02: Subtree Alignment

**Draft:** §4.1 lines 648-650
**Severity on failure:** Error
**Applies when:** `Proof != nil && start < end` (NA when R002 would fail).

**Check:** `MTCProof.start` must be a multiple of `BIT_CEIL(end - start)`,
where `BIT_CEIL(n)` is the smallest power of 2 that is greater than or equal
to n.

Draft text (lines 648-650):

> *  start is a multiple of BIT_CEIL(end - start)
>
> Note that, if start is zero, the second condition is always true.

Vacuous pass: when `start == 0`, R003 always passes (per line 650).

Example violation: `start=2 end=5` (width=3, BIT_CEIL(3)=4, 2 % 4 = 2).

### MTC_R005_d02: Serial Number Positive

**Draft:** §6.1 lines 1965-1970
**Severity on failure:** Error
**Applies when:** `X509 != nil && SerialNumber != nil`. Applies to non-MTC
certs as well: the rule is a universal RFC5280 + MTC restatement.

**Check:** `TBSCertificate.serialNumber > 0` (strictly positive).

Draft text (lines 1965-1970):

> The TBSCertificate's serialNumber MUST contain the zero-based index
> of the TBSCertificateLogEntry in the log.  Section 4.1.2.2 of
> [RFC5280] forbids zero as a serial number, but Section 5.3 defines a
> null_entry type for use in entry zero, so the index will be positive.

Example violation: `serialNumber=0`.

## Rule numbering convention

Rule IDs follow the format `MTC_R<NNN>_d<DD>` where `<NNN>` is a
zero-padded sequence and `<DD>` is the draft version this rule was authored
against. This allows draft-02 rules and future draft-03 rules to coexist in
the same registry without ID collisions.
