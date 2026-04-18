// genfixture builds the Phase 1A test fixtures from scratch, deterministically.
// Outputs:
//
//	testdata/valid/mtc_minimal.pem       hand-crafted MTC cert (cryptobyte)
//	testdata/invalid/ed25519_cert.pem    self-signed Ed25519 cert (crypto/x509)
//
// Apache 2.0 clean. No external dependencies beyond golang.org/x/crypto.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// detReader is a stdlib-only deterministic io.Reader built from sha256
// over (seed || counter). Per Phase 1A spec §4 genfixture entry: this is
// the dep-free path; do not introduce chacha20 or x/exp/rand dependencies
// unless this proves insufficient.
type detReader struct {
	seed []byte
	ctr  uint64
}

func (r *detReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], r.ctr)
		r.ctr++
		h := sha256.Sum256(append(r.seed, buf[:]...))
		n += copy(p[n:], h[:])
	}
	return len(p), nil
}

var (
	fixedNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedNotAfter  = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

// minimalMTCProof is the 20-byte minimal MTCProof per Phase 1A spec §5:
//
//	start=0 (8 bytes BE) + end=1 (8 bytes BE) + 0x0000 + 0x0000 = 20 bytes
var minimalMTCProof = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // start = 0
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // end   = 1
	0x00, 0x00, // inclusion_proof length = 0
	0x00, 0x00, // signatures     length = 0
}

// buildMTCProofBytes encodes an empty-vector MTCProof with the given
// start and end values. inclusion_proof and signatures are both empty.
// Total length is always 20 bytes.
func buildMTCProofBytes(start, end uint64) []byte {
	out := make([]byte, 20)
	binary.BigEndian.PutUint64(out[0:8], start)
	binary.BigEndian.PutUint64(out[8:16], end)
	// out[16:18] = inclusion_proof length 0 (already zero)
	// out[18:20] = signatures     length 0 (already zero)
	return out
}

// buildEd25519Cert builds a self-signed Ed25519 cert using a deterministic
// seeded key. Used as the non-MTC invalid fixture: R001 should classify it
// as NA in default mode and Error in strict mode, because the signature
// algorithm OID is Ed25519 (1.3.101.112), not the experimental MTC OID.
//
// Rationale for Ed25519 over RSA: as of Go 1.26, crypto/rsa.GenerateKey
// applies FIPS 140-3 blinding that bypasses the caller-supplied io.Reader,
// so an RSA-based fixture is no longer deterministic across regenerations.
// crypto/ed25519 still respects its supplied reader, matching the pattern
// already used for mtc_minimal.pem.
func buildEd25519Cert() ([]byte, error) {
	rng := &detReader{seed: []byte("leafeater-ed25519-seed-v1")}
	_, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, fmt.Errorf("ed25519.GenerateKey: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example"},
		Issuer:       pkix.Name{CommonName: "Leaf Eater Test CA"},
		NotBefore:    fixedNotBefore,
		NotAfter:     fixedNotAfter,
	}
	// Ed25519 signing is deterministic and ignores the rand argument, but
	// x509.CreateCertificate may still read from it for other purposes, so
	// we pass the same deterministic reader for reproducibility.
	der, err := x509.CreateCertificate(rng, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}
	// Self-test: re-parse.
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("self-test parse: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// addMTCAlgorithmIdentifier writes:
//
//	SEQUENCE { OID 1.3.6.1.4.1.44363.47.0 }
//
// Parameters ABSENT per draft §6.1.
func addMTCAlgorithmIdentifier(b *cryptobyte.Builder) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(mtc.MTCProofOID)
	})
}

// addCommonNameRDN writes a single-RDN Name containing only a CommonName.
func addCommonNameRDN(b *cryptobyte.Builder, cn string) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 3})
				b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(cn))
				})
			})
		})
	})
}

// buildMTCCert builds a minimal MTC-shaped X.509 certificate from scratch
// using cryptobyte, per Phase 1A spec §5. The outer signatureAlgorithm is
// the experimental MTC OID; the signatureValue BIT STRING contains the
// 20-byte minimalMTCProof. Self-tests by round-tripping through
// crypto/x509.ParseCertificate.
//
// Delegates to buildMTCCertWith with serial=1 and the minimal proof so the
// byte output is identical to the original Phase 1A fixture.
func buildMTCCert() ([]byte, error) {
	return buildMTCCertWith(1, minimalMTCProof)
}

// buildMTCCertWith builds a minimal MTC-shaped X.509 cert with a caller-
// supplied serialNumber and signatureValue proof bytes. Used for Phase 1B
// invalid fixtures that exercise R002, R003, and R005.
//
// The TBSCertificate is constructed manually via cryptobyte: we never go
// through crypto/x509.CreateCertificate, which lets us emit
// serialNumber=0 for the R005 fixture even though RFC5280 / CreateCertificate
// would reject it. stdlib x509.ParseCertificate DOES currently accept
// serial=0 (it only warns), which is why the self-test round-trip still
// passes.
func buildMTCCertWith(serial int64, proofBytes []byte) ([]byte, error) {
	// Deterministic Ed25519 key per spec §5: fixed 32-byte seed.
	seed := bytes.Repeat([]byte{0x42}, 32)
	edKey := ed25519.NewKeyFromSeed(seed)
	edPub := edKey.Public().(ed25519.PublicKey)

	// Build tbsCertificate.
	var tbs cryptobyte.Builder
	tbs.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// version [0] EXPLICIT INTEGER 2 (v3)
		b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1Int64(2)
		})
		// serialNumber INTEGER (caller-supplied)
		b.AddASN1Int64(serial)
		// signature AlgorithmIdentifier: MTC OID
		addMTCAlgorithmIdentifier(b)
		// issuer Name
		addCommonNameRDN(b, "Leaf Eater Test CA")
		// validity SEQUENCE { UTCTime notBefore, UTCTime notAfter }
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1UTCTime(fixedNotBefore)
			b.AddASN1UTCTime(fixedNotAfter)
		})
		// subject Name
		addCommonNameRDN(b, "test.example")
		// subjectPublicKeyInfo SEQUENCE {
		//   AlgorithmIdentifier { OID 1.3.101.112 (Ed25519), params ABSENT }
		//   BIT STRING (0 unused bits) { ed25519 public key }
		// }
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 3, 101, 112})
			})
			b.AddASN1BitString(edPub)
		})
	})
	tbsBytes, err := tbs.Bytes()
	if err != nil {
		return nil, fmt.Errorf("build tbs: %w", err)
	}

	// Build outer Certificate SEQUENCE.
	var cert cryptobyte.Builder
	cert.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbsBytes)
		addMTCAlgorithmIdentifier(b)
		// signatureValue BIT STRING (0 unused bits) containing the MTCProof.
		b.AddASN1BitString(proofBytes)
	})
	der, err := cert.Bytes()
	if err != nil {
		return nil, fmt.Errorf("build cert: %w", err)
	}

	// Self-test: round-trip through crypto/x509.ParseCertificate.
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("self-test parse: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// buildR002Fixture: valid MTC cert but start == end == 5. Violates R002.
func buildR002Fixture() ([]byte, error) {
	return buildMTCCertWith(1, buildMTCProofBytes(5, 5))
}

// buildR003Fixture: start=2, end=5. Width=3, BIT_CEIL(3)=4, 2 % 4 = 2.
// R002 passes (2 < 5); R003 fails (misaligned).
func buildR003Fixture() ([]byte, error) {
	return buildMTCCertWith(1, buildMTCProofBytes(2, 5))
}

// buildR005Fixture: serialNumber=0. Violates R005 (serial > 0 required).
// start=0, end=1 so R002 passes and R003 is vacuously true (start==0).
// The TBS is built by hand so CreateCertificate's RFC5280 serial check is
// not on the code path; stdlib ParseCertificate accepts serial=0 (warns
// only), so the self-test round-trip still works.
func buildR005Fixture() ([]byte, error) {
	return buildMTCCertWith(0, buildMTCProofBytes(0, 1))
}

// buildMalformedProofFixture exercises the
// ParseCertificate -> parseMTCProof error path; signatureValue is shorter
// than the 20-byte minimum so parseMTCProof returns *ParseError with
// Field == "MTCProof". The proof blob is 19 zero bytes (one byte short of
// the fixed 20-byte MTCProof header), which trips the len(b) < 20 guard
// at the top of parseMTCProof. The outer x509.ParseCertificate self-test
// still succeeds because the truncated payload is wrapped in a valid BIT
// STRING.
func buildMalformedProofFixture() ([]byte, error) {
	return buildMTCCertWith(1, make([]byte, 19))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "genfixture:", err)
		os.Exit(1)
	}
}

func run() error {
	edPEM, err := buildEd25519Cert()
	if err != nil {
		return fmt.Errorf("ed25519: %w", err)
	}
	mtcPEM, err := buildMTCCert()
	if err != nil {
		return fmt.Errorf("mtc: %w", err)
	}
	if err := os.MkdirAll(filepath.Join("testdata", "valid"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join("testdata", "invalid"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("testdata", "valid", "mtc_minimal.pem"), mtcPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("testdata", "invalid", "ed25519_cert.pem"), edPEM, 0o644); err != nil {
		return err
	}

	// Phase 1B invalid fixtures: one per new rule.
	type invalid struct {
		name string
		fn   func() ([]byte, error)
	}
	invalids := []invalid{
		{"r002_start_ge_end.pem", buildR002Fixture},
		{"r003_misaligned_start.pem", buildR003Fixture},
		{"r005_zero_serial.pem", buildR005Fixture},
		{"malformed_proof.pem", buildMalformedProofFixture},
	}
	for _, iv := range invalids {
		pemBytes, err := iv.fn()
		if err != nil {
			return fmt.Errorf("%s: %w", iv.name, err)
		}
		if err := os.WriteFile(filepath.Join("testdata", "invalid", iv.name), pemBytes, 0o644); err != nil {
			return err
		}
	}

	fmt.Println("wrote 6 fixtures (1 valid, 5 invalid)")
	return nil
}
