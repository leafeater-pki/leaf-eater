package mtc

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// MTCProofOID is the experimental signature algorithm OID used by
// draft-ietf-plants-merkle-tree-certs-02 line 1987 for id-alg-mtcProof.
var MTCProofOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}

// ParseCertificate parses a single PEM- or DER-encoded X.509 certificate
// and, if it carries the experimental MTC signature OID, also parses the
// MTCProof from its signatureValue.
//
// PEM input is detected by leading "-----BEGIN". DER input is passed
// through to x509.ParseCertificate directly. Returns a *ParseError on any
// structural failure.
func ParseCertificate(input []byte) (*Certificate, error) {
	der := input
	if len(input) > 0 && input[0] == '-' {
		block, _ := pem.Decode(input)
		if block == nil {
			return nil, &ParseError{Field: "PEM", Cause: errBadPEM}
		}
		der = block.Bytes
	}
	x509Cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &ParseError{Field: "X509", Cause: err}
	}
	oid, err := extractRawSigOID(x509Cert.RawTBSCertificate)
	if err != nil {
		return nil, err
	}
	c := &Certificate{X509: x509Cert, RawSigOID: oid}
	if oid.Equal(MTCProofOID) {
		proof, err := parseMTCProof(x509Cert.Signature)
		if err != nil {
			return nil, err
		}
		c.Proof = proof
	}
	return c, nil
}

var errBadPEM = &pemError{"failed to decode PEM block"}

type pemError struct{ msg string }

func (e *pemError) Error() string { return e.msg }

// extractRawSigOID reads the raw signature AlgorithmIdentifier OID from a
// DER-encoded tbsCertificate blob (as stored in x509.Certificate.RawTBSCertificate).
//
// Per Phase 1A spec §3.1, the 5-step algorithm handles both v1 (no version
// wrapper) and v3 (explicit [0] wrapper) tbsCertificate layouts.
func extractRawSigOID(rawTBS []byte) (asn1.ObjectIdentifier, error) {
	// Step 1: unwrap the outer SEQUENCE. cert.RawTBSCertificate is the FULL
	// DER tbsCertificate including the outer tag + length.
	input := cryptobyte.String(rawTBS)
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) {
		return nil, &ParseError{Field: "tbsCertificate", Cause: errMalformed("unwrap outer SEQUENCE")}
	}
	// Step 2: skip the optional [0] EXPLICIT version wrapper if present.
	// SkipOptionalASN1 is a no-op if the next element does not match.
	if !inner.SkipOptionalASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, &ParseError{Field: "tbsCertificate.version", Cause: errMalformed("skip optional version")}
	}
	// Step 3: skip serialNumber INTEGER.
	if !inner.SkipASN1(cryptobyte_asn1.INTEGER) {
		return nil, &ParseError{Field: "tbsCertificate.serialNumber", Cause: errMalformed("skip serialNumber")}
	}
	// Step 4: read signature AlgorithmIdentifier as a SEQUENCE.
	var aiSeq cryptobyte.String
	if !inner.ReadASN1(&aiSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, &ParseError{Field: "tbsCertificate.signature", Cause: errMalformed("read AlgorithmIdentifier SEQUENCE")}
	}
	// Step 5: read the first element as an OBJECT IDENTIFIER.
	var oid asn1.ObjectIdentifier
	if !aiSeq.ReadASN1ObjectIdentifier(&oid) {
		return nil, &ParseError{Field: "tbsCertificate.signature.algorithm", Cause: errMalformed("read OID")}
	}
	return oid, nil
}

type errMalformed string

func (e errMalformed) Error() string { return "malformed: " + string(e) }

// parseMTCProof decodes an MTCProof from its TLS presentation language
// wire format. Strict mode: trailing garbage after a complete proof is a
// ParseError.
//
// Wire format (per draft-ietf-plants-merkle-tree-certs-02 §6.1 lines 1999-2004):
//
//	struct {
//	    uint64 start;
//	    uint64 end;
//	    HashValue inclusion_proof<0..2^16-1>;
//	    MTCSignature signatures<0..2^16-1>;
//	} MTCProof;
//
// Phase 1A: we do not parse individual HashValues or MTCSignatures; we
// record the raw length-prefixed blobs so R001 can run. R002/R003/R005
// in Phase 1B will read Start/End directly. Deeper parsing of the
// inclusion_proof and signatures vectors is deferred.
func parseMTCProof(b []byte) (*MTCProof, error) {
	if len(b) < 20 {
		return nil, &ParseError{Field: "MTCProof", Offset: 0, Cause: fmt.Errorf("need >= 20 bytes, got %d", len(b))}
	}
	p := &MTCProof{}
	p.Start = binary.BigEndian.Uint64(b[0:8])
	p.End = binary.BigEndian.Uint64(b[8:16])
	off := 16
	ipLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+ipLen > len(b) {
		return nil, &ParseError{Field: "MTCProof.inclusion_proof", Offset: off, Cause: fmt.Errorf("length %d exceeds remaining %d", ipLen, len(b)-off)}
	}
	// Skip inclusion_proof body (deeper parse deferred to Phase 1B).
	off += ipLen
	if off+2 > len(b) {
		return nil, &ParseError{Field: "MTCProof.signatures.length", Offset: off, Cause: fmt.Errorf("truncated length prefix")}
	}
	sigLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+sigLen > len(b) {
		return nil, &ParseError{Field: "MTCProof.signatures", Offset: off, Cause: fmt.Errorf("length %d exceeds remaining %d", sigLen, len(b)-off)}
	}
	off += sigLen
	if off != len(b) {
		return nil, &ParseError{Field: "MTCProof", Offset: off, Cause: fmt.Errorf("trailing garbage: %d bytes after end", len(b)-off)}
	}
	return p, nil
}
