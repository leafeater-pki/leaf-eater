package mtc

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCertificate_ValidMTCFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "valid", "mtc_minimal.pem")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cert, err := ParseCertificate(data)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.X509 == nil {
		t.Fatal("X509 is nil")
	}
	if cert.Proof == nil {
		t.Fatal("Proof is nil for MTC-shaped cert")
	}
	if cert.Proof.Start != 0 || cert.Proof.End != 1 {
		t.Errorf("proof start/end: got %d/%d, want 0/1", cert.Proof.Start, cert.Proof.End)
	}
}

func TestParseCertificate_NonMTCFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "invalid", "ed25519_cert.pem")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cert, err := ParseCertificate(data)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Proof != nil {
		t.Error("Proof should be nil for non-MTC cert")
	}
	if cert.RawSigOID.String() != "1.3.101.112" {
		t.Errorf("RawSigOID: got %s, want 1.3.101.112", cert.RawSigOID)
	}
}

func TestExtractRawSigOID_V1NoVersionWrapper(t *testing.T) {
	// Synthetic minimal tbsCertificate (v1, no [0] wrapper):
	//   SEQUENCE {
	//     INTEGER 1                         -- serialNumber
	//     SEQUENCE {                        -- signature AlgorithmIdentifier
	//       OID 1.2.840.113549.1.1.11       -- sha256WithRSAEncryption
	//       NULL
	//     }
	//     ... (rest elided; extractRawSigOID only reads up to here)
	//   }
	// Byte count: outer SEQUENCE body = 3 (INTEGER) + 15 (inner SEQUENCE
	// header+body) = 18 bytes, so the outer length octet is 0x12, not 0x13.
	// 30 12                                 SEQUENCE, len 18
	//   02 01 01                             INTEGER 1
	//   30 0d                                SEQUENCE, len 13
	//     06 09 2a 86 48 86 f7 0d 01 01 0b   OID sha256WithRSAEncryption
	//     05 00                              NULL
	raw, _ := hex.DecodeString("3012020101300d06092a864886f70d01010b0500")
	oid, err := extractRawSigOID(raw)
	if err != nil {
		t.Fatalf("extractRawSigOID: %v", err)
	}
	want := "1.2.840.113549.1.1.11"
	if oid.String() != want {
		t.Errorf("oid = %s, want %s", oid, want)
	}
}

func TestParseMTCProof_Minimal(t *testing.T) {
	// Case (a): canonical 20-byte minimal proof per spec §5:
	//   start=0 (8 bytes BE) + end=1 (8 bytes BE) + 0x00 0x00 + 0x00 0x00 = 20 bytes
	raw, _ := hex.DecodeString("00000000000000000000000000000001" + "0000" + "0000")
	p, err := parseMTCProof(raw)
	if err != nil {
		t.Fatalf("parseMTCProof: %v", err)
	}
	if p.Start != 0 || p.End != 1 {
		t.Errorf("start/end: got %d/%d, want 0/1", p.Start, p.End)
	}
}

func TestParseMTCProof_Truncated(t *testing.T) {
	// Case (b): < 20 bytes.
	_, err := parseMTCProof(make([]byte, 19))
	if err == nil {
		t.Fatal("expected error on truncated input")
	}
}

func TestParseMTCProof_OverlongLengthPrefix(t *testing.T) {
	// Case (c): inclusion_proof length prefix claims more bytes than present.
	// start=0, end=1, ip_len=0xffff, body empty, then signatures_len=0.
	raw, _ := hex.DecodeString("00000000000000000000000000000001" + "ffff" + "0000")
	_, err := parseMTCProof(raw)
	if err == nil {
		t.Fatal("expected error on overlong length prefix")
	}
}

func TestParseMTCProof_TrailingGarbage(t *testing.T) {
	// Case (d): complete 20-byte proof followed by extra bytes.
	raw, _ := hex.DecodeString("00000000000000000000000000000001" + "0000" + "0000" + "deadbeef")
	_, err := parseMTCProof(raw)
	if err == nil {
		t.Fatal("expected error on trailing garbage")
	}
}

func TestParseMTCProof_Empty(t *testing.T) {
	// Case (e): zero-length input.
	_, err := parseMTCProof(nil)
	if err == nil {
		t.Fatal("expected error on empty input")
	}
}

func TestParseCertificate_MalformedPEM(t *testing.T) {
	// Case (f): bad base64 and missing END line.
	_, err := ParseCertificate([]byte("-----BEGIN CERTIFICATE-----\nnot_base64!!\n"))
	if err == nil {
		t.Fatal("expected error on malformed PEM")
	}
}

func TestParseCertificate_ZeroLengthDER(t *testing.T) {
	// Case (g): valid PEM armor with empty body.
	_, err := ParseCertificate([]byte("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"))
	if err == nil {
		t.Fatal("expected error on zero-length DER")
	}
}

func TestExtractRawSigOID_V3WithVersionWrapper(t *testing.T) {
	// Synthetic minimal v3 tbsCertificate with explicit [0] version wrapper:
	//   SEQUENCE {
	//     [0] EXPLICIT { INTEGER 2 }            -- version v3
	//     INTEGER 1                             -- serialNumber
	//     SEQUENCE {                            -- signature AlgorithmIdentifier
	//       OID 1.2.840.113549.1.1.11           -- sha256WithRSAEncryption
	//       NULL
	//     }
	//   }
	// Byte layout:
	// 30 17                                    -- outer SEQUENCE, len 23
	//   a0 03                                   -- [0] EXPLICIT (constructed), len 3
	//     02 01 02                              -- INTEGER 2 (v3)
	//   02 01 01                                -- INTEGER 1 (serial)
	//   30 0d                                   -- SEQUENCE, len 13
	//     06 09 2a 86 48 86 f7 0d 01 01 0b      -- OID sha256WithRSAEncryption
	//     05 00                                 -- NULL
	// outer body bytes: 2 + 3 + 3 + 2 + 13 = 23 (0x17)
	raw, _ := hex.DecodeString("3017a003020102020101300d06092a864886f70d01010b0500")
	oid, err := extractRawSigOID(raw)
	if err != nil {
		t.Fatalf("extractRawSigOID: %v", err)
	}
	want := "1.2.840.113549.1.1.11"
	if oid.String() != want {
		t.Errorf("oid = %s, want %s", oid, want)
	}
}

func TestExtractRawSigOID_OuterNotSequence(t *testing.T) {
	// First tag is INTEGER (0x02), not SEQUENCE (0x30).
	raw, _ := hex.DecodeString("020101")
	_, err := extractRawSigOID(raw)
	if err == nil {
		t.Fatal("expected error when outer tag is not SEQUENCE")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("err type: got %T, want *ParseError", err)
	}
	if pe.Field != "tbsCertificate" {
		t.Errorf("Field: got %q, want %q", pe.Field, "tbsCertificate")
	}
}

func TestExtractRawSigOID_MissingSerial(t *testing.T) {
	// Outer SEQUENCE containing a NULL (0x05 0x00) where the serialNumber
	// INTEGER is expected. SkipOptionalASN1 for the [0] version is a no-op
	// because the tag does not match; SkipASN1(INTEGER) then fails.
	// 30 02                                     -- SEQUENCE, len 2
	//   05 00                                   -- NULL
	raw, _ := hex.DecodeString("30020500")
	_, err := extractRawSigOID(raw)
	if err == nil {
		t.Fatal("expected error when serialNumber is missing")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("err type: got %T, want *ParseError", err)
	}
	if pe.Field != "tbsCertificate.serialNumber" {
		t.Errorf("Field: got %q, want %q", pe.Field, "tbsCertificate.serialNumber")
	}
}

func TestExtractRawSigOID_MissingSignatureSequence(t *testing.T) {
	// Outer SEQUENCE with INTEGER serial, then a NULL where the
	// AlgorithmIdentifier SEQUENCE is expected.
	// 30 05                                     -- SEQUENCE, len 5
	//   02 01 01                                -- INTEGER 1
	//   05 00                                   -- NULL
	raw, _ := hex.DecodeString("30050201010500")
	_, err := extractRawSigOID(raw)
	if err == nil {
		t.Fatal("expected error when AlgorithmIdentifier SEQUENCE is missing")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("err type: got %T, want *ParseError", err)
	}
	if pe.Field != "tbsCertificate.signature" {
		t.Errorf("Field: got %q, want %q", pe.Field, "tbsCertificate.signature")
	}
}

func TestExtractRawSigOID_AlgIDFirstElementNotOID(t *testing.T) {
	// Outer SEQUENCE, INTEGER serial, then SEQUENCE whose first element is
	// NULL (not OID).
	// 30 09                                     -- SEQUENCE, len 9
	//   02 01 01                                -- INTEGER 1
	//   30 04                                   -- SEQUENCE, len 4
	//     05 00                                 -- NULL
	//     05 00                                 -- NULL
	raw, _ := hex.DecodeString("3009020101300405000500")
	_, err := extractRawSigOID(raw)
	if err == nil {
		t.Fatal("expected error when AlgorithmIdentifier first element is not OID")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("err type: got %T, want *ParseError", err)
	}
	if pe.Field != "tbsCertificate.signature.algorithm" {
		t.Errorf("Field: got %q, want %q", pe.Field, "tbsCertificate.signature.algorithm")
	}
}

func TestParseMTCProof_NonEmptyInclusionProof(t *testing.T) {
	// start=0, end=2, ip_len=32 (one SHA-256-sized hash), 32 bytes body,
	// then sig_len=0.
	body := strings.Repeat("ab", 32) // 32 bytes hex-encoded
	raw, _ := hex.DecodeString("00000000000000000000000000000002" + "0020" + body + "0000")
	p, err := parseMTCProof(raw)
	if err != nil {
		t.Fatalf("parseMTCProof: %v", err)
	}
	if p.Start != 0 || p.End != 2 {
		t.Errorf("start/end: got %d/%d, want 0/2", p.Start, p.End)
	}
}

func TestParseMTCProof_NonEmptySignatures(t *testing.T) {
	// start=0, end=1, ip_len=0, sig_len=4, 4 bytes body.
	raw, _ := hex.DecodeString("00000000000000000000000000000001" + "0000" + "0004" + "deadbeef")
	p, err := parseMTCProof(raw)
	if err != nil {
		t.Fatalf("parseMTCProof: %v", err)
	}
	if p.Start != 0 || p.End != 1 {
		t.Errorf("start/end: got %d/%d, want 0/1", p.Start, p.End)
	}
}

func TestParseMTCProof_TruncatedSigLengthPrefix(t *testing.T) {
	// To reach the "MTCProof.signatures.length" branch we must pass the
	// initial >= 20 byte guard, then have the cursor land exactly at len(b)
	// after consuming the inclusion_proof body, leaving fewer than 2 bytes
	// for the sig length uint16 prefix.
	//
	// Layout: start(8) + end(8) + ip_len=0x0002 (2) + ip body (2 bytes) = 20.
	// After consuming ip body, off == 20 == len(b), so b[20:22] read fails.
	raw, _ := hex.DecodeString("00000000000000000000000000000001" + "0002" + "abcd")
	if len(raw) != 20 {
		t.Fatalf("setup: expected length 20, got %d", len(raw))
	}
	_, err := parseMTCProof(raw)
	if err == nil {
		t.Fatal("expected error on truncated sig length prefix")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("err type: got %T, want *ParseError", err)
	}
	if pe.Field != "MTCProof.signatures.length" {
		t.Errorf("Field: got %q, want %q", pe.Field, "MTCProof.signatures.length")
	}
}

func TestParseMTCProof_BothBodiesPopulated(t *testing.T) {
	// start=10 (0x0a), end=12 (0x0c), ip_len=4 (deadbeef), sig_len=2 (cafe).
	raw, _ := hex.DecodeString("000000000000000a" + "000000000000000c" + "0004" + "deadbeef" + "0002" + "cafe")
	p, err := parseMTCProof(raw)
	if err != nil {
		t.Fatalf("parseMTCProof: %v", err)
	}
	if p.Start != 10 || p.End != 12 {
		t.Errorf("start/end: got %d/%d, want 10/12", p.Start, p.End)
	}
}

func TestParseCertificate_MalformedProofFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "invalid", "malformed_proof.pem")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	_, err = ParseCertificate(data)
	if err == nil {
		t.Fatal("expected error from malformed MTCProof signatureValue")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("err type: got %T, want *ParseError", err)
	}
	if !strings.HasPrefix(pe.Field, "MTCProof") {
		t.Errorf("Field: got %q, want prefix %q", pe.Field, "MTCProof")
	}
}

func TestParseCertificate_PEMNonCertificateBlock(t *testing.T) {
	// Valid PEM whose body decodes (base64 ok) but is not a parseable
	// X.509 certificate. pem.Decode succeeds; x509.ParseCertificate fails.
	body := base64.StdEncoding.EncodeToString([]byte("not a real cert"))
	armor := "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"
	// Sanity: ensure pem.Decode actually succeeds on this input.
	if blk, _ := pem.Decode([]byte(armor)); blk == nil {
		t.Fatalf("setup: pem.Decode returned nil block")
	}
	_, err := ParseCertificate([]byte(armor))
	if err == nil {
		t.Fatal("expected error parsing a non-certificate PEM block")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("err type: got %T, want *ParseError", err)
	}
	if pe.Field != "X509" {
		t.Errorf("Field: got %q, want %q", pe.Field, "X509")
	}
}
