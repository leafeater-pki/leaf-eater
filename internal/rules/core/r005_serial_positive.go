package core

import (
	"fmt"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

// r005 enforces that the wrapping X.509 certificate's serialNumber is
// strictly positive.
//
// Draft §6.1 "Certificate Format" (draft-ietf-plants-merkle-tree-certs-02
// lines 1965-1970):
//
//	The TBSCertificate's serialNumber MUST contain the zero-based index
//	of the TBSCertificateLogEntry in the log.  Section 4.1.2.2 of
//	[RFC5280] forbids zero as a serial number, but Section 5.3 defines a
//	null_entry type for use in entry zero, so the index will be positive.
//	This encoding is intended to avoid implementation errors by having
//	the serial numbers and indices off by one.
//
// R005 is universal: the rationale (RFC5280 forbids zero, §5.3 reserves
// zero for null_entry) is a baseline X.509 constraint that MTC restates,
// so this rule applies to non-MTC certs as well.
type r005 struct{}

func (r *r005) ID() string { return "MTC_R005_d02" }

func (r *r005) Description() string {
	return "X.509 serialNumber must be strictly positive"
}

func (r *r005) Citation() string {
	return "draft-ietf-plants-merkle-tree-certs-02 §6.1 lines 1965-1970"
}

func (r *r005) CheckApplies(cert *mtc.Certificate) bool {
	return cert != nil && cert.X509 != nil && cert.X509.SerialNumber != nil
}

func (r *r005) Execute(cert *mtc.Certificate) rules.Finding {
	sn := cert.X509.SerialNumber
	if sn.Sign() > 0 {
		return rules.Finding{
			RuleID:      r.ID(),
			Severity:    rules.Pass,
			Description: "serialNumber is positive",
			Citation:    r.Citation(),
			Evidence:    fmt.Sprintf("serialNumber=%s", sn.String()),
		}
	}
	return rules.Finding{
		RuleID:      r.ID(),
		Severity:    rules.Error,
		Description: r.Description(),
		Citation:    r.Citation(),
		Evidence:    fmt.Sprintf("serialNumber=%s (sign=%d)", sn.String(), sn.Sign()),
	}
}

func init() {
	rules.DefaultRegistry.Register(&r005{})
}
