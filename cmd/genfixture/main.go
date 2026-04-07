// genfixture builds the Phase 1A test fixtures from scratch, deterministically.
// Outputs:
//
//	testdata/valid/mtc_minimal.pem   — hand-crafted MTC cert (cryptobyte)
//	testdata/invalid/rsa_cert.pem    — self-signed RSA-SHA256 cert (crypto/x509)
//
// Apache 2.0 clean. No external dependencies beyond golang.org/x/crypto.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
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

// buildRSACert builds a self-signed sha256WithRSAEncryption cert using a
// deterministic random reader. Used as an invalid fixture: R001 should
// reject it because the signature algorithm OID is not MTCProofOID.
func buildRSACert() ([]byte, error) {
	rng := &detReader{seed: []byte("leafeater-rsa-seed-v1")}
	key, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		return nil, fmt.Errorf("rsa.GenerateKey: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example"},
		Issuer:       pkix.Name{CommonName: "Leaf Eater Test CA"},
		NotBefore:    fixedNotBefore,
		NotAfter:     fixedNotAfter,
	}
	der, err := x509.CreateCertificate(rng, tmpl, tmpl, &key.PublicKey, key)
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
func buildMTCCert() ([]byte, error) {
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
		// serialNumber INTEGER 1
		b.AddASN1Int64(1)
		// signature AlgorithmIdentifier — MTC OID
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
		// signatureValue BIT STRING (0 unused bits) containing the 20-byte MTCProof.
		b.AddASN1BitString(minimalMTCProof)
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "genfixture:", err)
		os.Exit(1)
	}
}

func run() error {
	rsaPEM, err := buildRSACert()
	if err != nil {
		return fmt.Errorf("rsa: %w", err)
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
	if err := os.WriteFile(filepath.Join("testdata", "invalid", "rsa_cert.pem"), rsaPEM, 0o644); err != nil {
		return err
	}
	fmt.Println("wrote testdata/valid/mtc_minimal.pem and testdata/invalid/rsa_cert.pem")
	return nil
}
