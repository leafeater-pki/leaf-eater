# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-d02-phase1a] — 2026-04-06

First working linter slice. Parses X.509-wrapped MTC certificates, extracts the
raw signature algorithm OID, parses the inner `MTCProof` from `signatureValue`
when the OID matches, runs the rule registry, and emits text findings with
severity-based exit codes.

### Added
- `internal/mtc/parse.go`: `ParseCertificate(input []byte) (*Certificate, error)`,
  `extractRawSigOID(rawTBS []byte) (asn1.ObjectIdentifier, error)`, and
  `parseMTCProof(b []byte) (*MTCProof, error)`. PEM/DER input, strict mode,
  typed `ParseError` with field path and byte offset.
- `internal/rules/core/r001_signature_alg.go`: `MTC_R001_d02` rule. Notice
  when the signature algorithm OID matches the experimental MTC OID
  `1.3.6.1.4.1.44363.47.0`; Error otherwise.
- `internal/reporter/text.go`: text findings reporter with severity filtering
  and quiet mode (suppresses `NA`/`Pass`).
- `cmd/leafeater/main.go`: real loader → registry → reporter pipeline
  (replaces the Phase 0 stub). Single-file path argument; exit code derived
  from maximum finding severity.
- `cmd/genfixture/main.go`: deterministic fixture generator. Builds the valid
  MTC fixture from scratch via `cryptobyte`; builds the invalid RSA fixture
  via `crypto/x509.CreateCertificate` with a deterministic `io.Reader` based
  on `crypto/sha256` over a counter.
- `testdata/valid/mtc_minimal.pem`: hand-crafted MTC certificate carrying a
  20-byte minimal `MTCProof` (`start=0, end=1`, empty inclusion proof and
  signatures vectors).
- `testdata/invalid/rsa_cert.pem`: vanilla self-signed RSA certificate for the
  R001 Error path.
- `testdata/README.md`: fixture provenance and regeneration procedure.
- `Makefile`: `fixtures` target (`go run ./cmd/genfixture`).
- Integration test in `cmd/leafeater/main_test.go`.

### Changed
- `internal/mtc/types.go`: added `RawSigOID asn1.ObjectIdentifier` field to
  `Certificate`. Relaxed the `Proof` doc comment: `Proof` is now nil for
  non-MTC certs (where the signature algorithm OID does not match the
  experimental MTC OID). All future rules must nil-check `cert.Proof`.
- `cmd/leafeater/main.go` exit code 3 doc comment: broadened from
  `"usage error"` to `"usage error or unparseable input"` to match parent
  spec §8.

### Deferred to Phase 1B
- `MTC_R002_d02` (subtree bounds), `MTC_R003_d02` (subtree alignment),
  `MTC_R005_d02` (serial > 0)
- JSON reporter
- Directory walk, stdin (`-`), PEM chain handling
- Real `-severity` and `-rules` flag filtering
- `docs/rules.md`, `docs/architecture.md`
- `v0.1.0-d02` tag
- "Non-MTC certs return NA" behavior (parent spec §8); R001 currently always
  applies and fires Error on non-MTC certs
