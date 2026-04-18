# Leaf Eater Architecture

## Pipeline

```
input → loader → parser → engine → reporter → stdout
```

1. **Loader** (`internal/loader`): normalizes input modes (file, directory,
   stdin, PEM chain) into a channel of `Item{Source, Data, Err}` pairs.
2. **Parser** (`internal/mtc`): converts a single `[]byte` into a
   `*mtc.Certificate` holding both the `x509.Certificate` view and, for
   MTC-shaped certs, a decoded `*MTCProof`.
3. **Engine** (`internal/rules`): runs every registered `Rule` against the
   certificate and returns `[]Finding`. Rules are registered via `init()`
   in `internal/rules/core`.
4. **Reporter** (`internal/reporter`): formats findings as text or JSON.

## Parser strategy

The MTC wire format is a mix of DER ASN.1 (the outer `TBSCertificate`) and
TLS presentation language (the `MTCProof` in the signature field). We use
`encoding/asn1` and `golang.org/x/crypto/cryptobyte` rather than a hand-rolled
length-prefix parser for two reasons:

1. `cryptobyte` provides `ReadASN1`, `ReadUint8LengthPrefixed`, and
   `ReadUint16LengthPrefixed` primitives that match the draft's field types
   exactly.
2. Stdlib `crypto/x509` handles the outer X.509 structure for free,
   including experimental signature algorithm OIDs.

The parser is strict: any malformed input yields a typed `ParseError` with
a dotted field path (e.g., `MTCProof.inclusion_proof[3]`). No partial
results, no recovery.

## Engine and rule interface

Every rule implements:

```go
type Rule interface {
    ID() string
    Description() string
    Citation() string
    CheckApplies(cert *mtc.Certificate) bool
    Execute(cert *mtc.Certificate) Finding
}
```

`CheckApplies` returning false short-circuits to an NA finding without
calling `Execute`. Panics during `Execute` are caught by the registry and
converted to Fatal findings so one bad rule cannot crash the linter.

## Test corpus

Phase 1B ships six fixtures:

- `testdata/valid/mtc_minimal.pem`: passes all rules
- `testdata/invalid/ed25519_cert.pem`: non-MTC (R001 NA in default, Error in strict)
- `testdata/invalid/r002_start_ge_end.pem`: R002 violation
- `testdata/invalid/r003_misaligned_start.pem`: R003 violation
- `testdata/invalid/r005_zero_serial.pem`: R005 violation
- `testdata/invalid/malformed_proof.pem`: MTC-shaped cert with truncated signatureValue (ParseCertificate parseMTCProof failure path)

All fixtures are generated deterministically by `cmd/genfixture` so the
test corpus is checked in but reproducible.

## Certlint_go lineage

The rule engine design borrows directly from `certlint_go`: a `Registry`
struct, `init()`-based rule registration, severity-per-finding rather than
per-rule. This keeps the port story simple: MTC rules are certlint_go rules
with a different input type (`*mtc.Certificate` instead of
`*x509.Certificate`).
