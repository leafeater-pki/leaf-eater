// Package core contains the built-in leaf-eater lint rules.
package core

import (
	"fmt"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

// strictR001 controls R001's CheckApplies semantics:
//   - false (default): R001 only runs on certs that parsed as MTC (Proof != nil)
//   - true: R001 runs on every cert; non-MTC certs get Error severity
var strictR001 bool

// SetStrictR001 toggles whether R001 runs on non-MTC certs. main.go calls this
// when the -strict flag is passed.
func SetStrictR001(v bool) { strictR001 = v }

// r001 checks that the wrapping X.509 certificate's signatureAlgorithm is
// the experimental MTC OID (1.3.6.1.4.1.44363.47.0) per
// draft-ietf-plants-merkle-tree-certs-02 line 1987.
//
// Phase 1B: CheckApplies returns NA on non-MTC certs by default. The -strict
// flag (via SetStrictR001) restores Phase 1A behavior where R001 runs on every
// cert and non-MTC certs get Error severity.
type r001 struct{}

func (r *r001) ID() string          { return "MTC_R001_d02" }
func (r *r001) Description() string { return "signature algorithm OID must be id-alg-mtcProof" }
func (r *r001) Citation() string {
	return "draft-ietf-plants-merkle-tree-certs-02 §6.1 line 1987"
}

func (r *r001) CheckApplies(cert *mtc.Certificate) bool {
	if cert == nil || cert.X509 == nil {
		return false
	}
	if strictR001 {
		return true
	}
	return cert.Proof != nil
}

func (r *r001) Execute(cert *mtc.Certificate) rules.Finding {
	if cert.RawSigOID.Equal(mtc.MTCProofOID) {
		return rules.Finding{
			RuleID:      r.ID(),
			Severity:    rules.Notice,
			Description: "draft-02 uses experimental OID; production OID id-alg-mtcProof not yet assigned",
			Citation:    r.Citation(),
			Evidence:    cert.RawSigOID.String(),
		}
	}
	return rules.Finding{
		RuleID:      r.ID(),
		Severity:    rules.Error,
		Description: r.Description(),
		Citation:    r.Citation(),
		Evidence:    fmt.Sprintf("got OID %s, want %s", cert.RawSigOID, mtc.MTCProofOID),
	}
}

func init() {
	rules.DefaultRegistry.Register(&r001{})
}
