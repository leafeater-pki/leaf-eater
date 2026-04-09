# Leaf Eater

> First standalone, permissively-licensed, draft-02-targeting MTC linter.

A linter for Merkle Tree Certificates (MTC), the IETF post-quantum certificate
format under development by the PLANTS working group (PKI, Logs, And Tree
Signatures).

**Authors:** [Kevin Kusion](https://github.com/thekuuzzz) and [Peter McDade](https://github.com/pmcdade).

**Status:** work in progress. Phase 0 scaffold only; no rules wired up yet.

## Targeted Draft

`draft-ietf-plants-merkle-tree-certs-02`, published 2026-03-02.

See [`docs/spec-pin.md`](docs/spec-pin.md) for the SHA-256 of the local draft
copy and the procedure for bumping to newer revisions.

## Prior Art

DigiCert's [`mtc-conformance`](https://github.com/digicert/ca-extension-mtc-playground)
(AGPLv3, targets draft-01) predates this project. Leaf Eater is an independent,
permissively-licensed effort targeting draft-02.

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Status

Phase 0: scaffold complete, compiles, no rules.
Phase 1: parser + 4 core rules (R001, R002, R003, R005).
Phase 2: cosigner rules, inclusion proof verification, landmark certs.

## Usage

### Single file

```
leafeater cert.pem
leafeater cert.der
```

### Directory walk

```
leafeater ./certs/
```

Recursively processes `.pem`, `.der`, `.crt`, `.cer` files (case-insensitive).

### Stdin

```
cat cert.pem | leafeater
leafeater -
```

### PEM chains

A single file or stdin blob containing multiple PEM blocks is split
automatically; each block is tagged `<source>#<index>`.

### Output formats

```
leafeater -format text cert.pem    # default
leafeater -format json cert.pem    # JSON array of findings
```

### Severity filter

Suppress findings below a threshold:

```
leafeater -severity error ./certs/   # only Error and Fatal
leafeater -severity warn cert.pem    # Warn, Error, Fatal
```

### Rule filter

Run only a subset of rules:

```
leafeater -rules MTC_R002_d02,MTC_R003_d02 cert.pem
```

### Strict mode

By default, non-MTC certificates cause R001 to return NA. Pass `-strict`
to force R001 to Error on non-MTC input:

```
leafeater -strict rsa_cert.pem   # R001 Error instead of NA
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All findings below Notice severity |
| 1 | At least one Notice or Warn |
| 2 | At least one Error or Fatal |
| 3 | IO error, parse error, or usage error |

See [`docs/rules.md`](docs/rules.md) for the rule catalog and
[`docs/architecture.md`](docs/architecture.md) for the linter internals.

### Regenerate fixtures

```
make fixtures
```

Fixtures are deterministic; regeneration produces byte-identical output.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full release history.
