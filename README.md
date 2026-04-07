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

### Lint a single MTC certificate

```
$ ./leafeater testdata/valid/mtc_minimal.pem
testdata/valid/mtc_minimal.pem: notice [MTC_R001_d02] draft-02 uses experimental OID; production OID id-alg-mtcProof not yet assigned (draft-ietf-plants-merkle-tree-certs-02 §6.1 line 1987)
$ echo $?
1
```

### Lint a non-MTC certificate

```
$ ./leafeater testdata/invalid/rsa_cert.pem
testdata/invalid/rsa_cert.pem: error [MTC_R001_d02] signature algorithm OID must be id-alg-mtcProof (draft-ietf-plants-merkle-tree-certs-02 §6.1 line 1987)
$ echo $?
2
```

### Regenerate fixtures

```
$ make fixtures
```

Fixtures are deterministic; regeneration produces byte-identical output.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full release history.
