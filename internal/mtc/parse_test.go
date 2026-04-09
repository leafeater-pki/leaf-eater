package mtc

import (
	"encoding/hex"
	"os"
	"path/filepath"
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
