package mtc

import (
	"crypto/x509"
	"encoding/asn1"
)

// Empty is the TLS presentation language placeholder for the null_entry
// case of MerkleTreeCertEntry.
//
// Derived verbatim from draft-ietf-plants-merkle-tree-certs-02, line 1461:
//
//	struct {} Empty;
type Empty struct{}

// MerkleTreeCertEntryType is the discriminator for MerkleTreeCertEntry.
//
// Derived verbatim from draft-ietf-plants-merkle-tree-certs-02, lines 1463-1465:
//
//	enum {
//	    null_entry(0), tbs_cert_entry(1), (2^16-1)
//	} MerkleTreeCertEntryType;
//
// The (2^16-1) maximum makes this a uint16 in the Go representation.
type MerkleTreeCertEntryType uint16

const (
	// NullEntry is reserved for the entry at index zero of every issuance log.
	// Per draft §5.3 lines 1476-1480, the entry at index 0 MUST be null_entry,
	// and other entries MUST NOT use null_entry. This exists to avoid zero
	// serial numbers in the wrapping X.509 certificate (§6.1).
	// Derived from draft line 1464.
	NullEntry MerkleTreeCertEntryType = 0
	// TBSCertEntry is the standard entry type carrying a DER-encoded
	// TBSCertificateLogEntry payload.
	// Derived from draft line 1464.
	TBSCertEntry MerkleTreeCertEntryType = 1
)

// MerkleTreeCertEntry is a single entry in a Merkle Tree Certificate
// issuance log, encoded in TLS presentation language.
//
// Derived verbatim from draft-ietf-plants-merkle-tree-certs-02, lines 1467-1474:
//
//	struct {
//	    MerkleTreeCertEntryType type;
//	    select (type) {
//	       case null_entry: Empty;
//	       case tbs_cert_entry: opaque tbs_cert_entry_data[N];
//	       /* May be extended with future types. */
//	    }
//	} MerkleTreeCertEntry;
//
// Per draft §5.3 lines 1482-1491, when type is tbs_cert_entry, N is "the
// number of bytes needed to consume the rest of the input"; the bytes
// contain the contents octets of the DER encoding of a TBSCertificateLogEntry.
// MerkleTreeCertEntry is expected to be decoded in contexts where the
// total length of the entry is known.
type MerkleTreeCertEntry struct {
	// Type is the entry discriminator. Derived from draft line 1468.
	Type MerkleTreeCertEntryType
	// TBSCertEntryData is the raw DER-encoded TBSCertificateLogEntry payload
	// (contents octets only, per draft line 1486-1488). Populated only when
	// Type == TBSCertEntry; nil when Type == NullEntry.
	// Derived from draft line 1471.
	TBSCertEntryData []byte
}

// TBSCertificateLogEntry is the log-side view of a Merkle Tree Certificate
// entry, encoded as a DER ASN.1 SEQUENCE.
//
// Derived verbatim from draft-ietf-plants-merkle-tree-certs-02, lines 1493-1505:
//
//	TBSCertificateLogEntry ::= SEQUENCE {
//	    version                   [0] EXPLICIT Version DEFAULT v1,
//	    issuer                        Name,
//	    validity                      Validity,
//	    subject                       Name,
//	    subjectPublicKeyAlgorithm     AlgorithmIdentifier{PUBLIC-KEY,
//	                                      {PublicKeyAlgorithms}},
//	    subjectPublicKeyInfoHash      OCTET STRING,
//	    issuerUniqueID            [1] IMPLICIT UniqueIdentifier OPTIONAL,
//	    subjectUniqueID           [2] IMPLICIT UniqueIdentifier OPTIONAL,
//	    extensions                [3] EXPLICIT Extensions{{CertExtensions}}
//	                                                       OPTIONAL
//	}
//
// IMPORTANT: TBSCertificateLogEntry has NO serialNumber and NO outer
// signature AlgorithmIdentifier. The serial number lives only in the
// wrapping X.509 certificate per §6.1 lines 1965-1970, and the outer
// signatureAlgorithm on the wrapping cert is id-alg-mtcProof. The
// subjectPublicKeyAlgorithm field describes the SUBJECT's public key
// algorithm, not an issuer signature.
//
// Per draft §6.1 lines 1947-1956, the TBSCertificate fields in the
// wrapping X.509 certificate MUST equal the corresponding
// TBSCertificateLogEntry fields, so in Phase 1+ this type is built lazily
// as a derived view of the x509 certificate via Certificate.LogEntryView();
// there is no separately-parsed instance on the Certificate struct in
// Phase 0. The struct is defined here for use by future code paths.
type TBSCertificateLogEntry struct {
	// Version of the TBS entry; defaults to v1. Derived from draft line 1494.
	Version int
	// IssuerDER is the DER-encoded issuer Name (PKIX). Derived from draft line 1495.
	IssuerDER []byte
	// NotBefore is the validity period start as a unix timestamp.
	// Derived from draft line 1496.
	NotBefore int64
	// NotAfter is the validity period end as a unix timestamp.
	// Derived from draft line 1496.
	NotAfter int64
	// SubjectDER is the DER-encoded subject Name (PKIX). Derived from draft line 1497.
	SubjectDER []byte
	// SubjectPublicKeyAlgorithm describes the subject public key algorithm.
	// This is NOT the issuer's signature algorithm; the wrapping cert uses
	// id-alg-mtcProof for that. Stored as an opaque RawValue in Phase 0.
	// Derived from draft lines 1498-1499.
	SubjectPublicKeyAlgorithm asn1.RawValue
	// SubjectPublicKeyInfoHash is the hash of the SPKI. Length equals the
	// log's HASH_SIZE per §5.1; only present in the log-side entry, not in
	// the wrapping x509 cert. Derived from draft line 1500.
	SubjectPublicKeyInfoHash HashValue
	// IssuerUniqueID is optional. Derived from draft line 1501.
	IssuerUniqueID []byte
	// SubjectUniqueID is optional. Derived from draft line 1502.
	SubjectUniqueID []byte
	// ExtensionsDER holds the raw DER-encoded extensions SEQUENCE.
	// Derived from draft line 1503.
	ExtensionsDER []byte
}

// HashValue is a fixed-length opaque hash value in TLS presentation language.
// The length is HASH_SIZE, a per-log parameter (per draft §5.1 lines
// 1393-1395), supplied to the parser out-of-band via the -hash CLI flag.
//
// Derived verbatim from draft-ietf-plants-merkle-tree-certs-02, line 1992:
//
//	opaque HashValue[HASH_SIZE];
type HashValue []byte

// MTCSignature is a single cosigner signature in an MTCProof, encoded in
// TLS presentation language.
//
// Derived verbatim from draft-ietf-plants-merkle-tree-certs-02, lines 1994-1997:
//
//	struct {
//	    TrustAnchorID cosigner_id;
//	    opaque signature<0..2^16-1>;
//	} MTCSignature;
//
// CosignerID is typed as TrustAnchorID per draft-ietf-tls-trust-anchor-ids;
// Phase 0 stores it as raw opaque bytes and defers TrustAnchorID parsing to
// a future phase.
type MTCSignature struct {
	// CosignerID is the binary representation of the cosigner's TrustAnchorID
	// per draft-ietf-tls-trust-anchor-ids §3. Stored as raw bytes in Phase 0.
	// Derived from draft line 1995.
	CosignerID []byte
	// Signature is the opaque cosigner signature value, formatted per draft
	// §5.4.1. Length-prefixed by uint16 on the wire (max 2^16-1 bytes).
	// Derived from draft line 1996.
	Signature []byte
}

// MTCProof is the proof structure carried in the wrapping X.509 certificate's
// signatureValue, encoded in TLS presentation language.
//
// Derived verbatim from draft-ietf-plants-merkle-tree-certs-02, lines 1999-2004:
//
//	struct {
//	    uint64 start;
//	    uint64 end;
//	    HashValue inclusion_proof<0..2^16-1>;
//	    MTCSignature signatures<0..2^16-1>;
//	} MTCProof;
//
// Per draft §6.1 lines 2006-2012: start and end are the chosen subtree's
// parameters; inclusion_proof is the subtree inclusion proof for the log
// entry; signatures contains the chosen subtree signatures (NOTE: the
// wire format uses the plural; this is a vector, not a single signature).
type MTCProof struct {
	// Start is the subtree start index (inclusive). Derived from draft line 2000.
	// Constraint (R002): start < end (strict).
	// Constraint (R003): start is a multiple of BIT_CEIL(end - start);
	// vacuously true when start == 0 per §4.1 line 650.
	Start uint64
	// End is the subtree end index (exclusive). Derived from draft line 2001.
	End uint64
	// InclusionProof is the subtree inclusion proof as a vector of HashValues
	// with a 16-bit length prefix on the wire. Each HashValue is HASH_SIZE
	// bytes per §5.1. Derived from draft line 2002.
	InclusionProof []HashValue
	// Signatures is the vector of cosigner signatures over the subtree head,
	// with a 16-bit length prefix on the wire. The wire format uses the
	// plural; this is a vector, not a single signature.
	// Derived from draft line 2003.
	Signatures []MTCSignature
}

// Certificate is the top-level MTC certificate. It wraps an X.509 certificate
// and the parsed MTC proof extracted from its signatureValue.
//
// Per draft §6.1 lines 1947-1990, an MTC certificate IS a standard X.509
// certificate whose signatureAlgorithm is id-alg-mtcProof (experimental OID
// 1.3.6.1.4.1.44363.47.0 in draft-02 per line 1987) and whose signatureValue
// contains an MTCProof encoded in TLS presentation language with no
// additional ASN.1 wrapping (per lines 2021-2025).
type Certificate struct {
	// X509 is the parsed wrapping X.509 certificate. Never nil in a
	// successfully-parsed Certificate. Used for structure only; do NOT call
	// CheckSignature on it; the experimental MTC OID has no registered
	// verifier in crypto/x509.
	X509 *x509.Certificate
	// Proof is the parsed MTCProof extracted from X509.Signature.
	// Nil if RawSigOID is not the experimental MTC OID (i.e., the cert is
	// not MTC-shaped); otherwise the parsed MTCProof from X509.Signature.
	// Every rule beyond R001 MUST nil-check Proof before dereferencing.
	Proof *MTCProof
	// RawSigOID is the signature algorithm OID extracted directly from the
	// DER-encoded tbsCertificate.signature field via cryptobyte. Populated
	// for every successfully-parsed Certificate regardless of whether the
	// cert is MTC-shaped. R001 uses this to discriminate MTC vs non-MTC.
	RawSigOID asn1.ObjectIdentifier
}
