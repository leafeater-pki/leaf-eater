package core

import (
	"fmt"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

// r002 enforces the strict inequality start < end on MTCProof.
//
// Draft §4.1 "Definition of a Subtree" (draft-ietf-plants-merkle-tree-certs-02
// lines 644-650):
//
//	A _subtree_ of this Merkle Tree is itself a Merkle Tree, defined by
//	MTH(D[start:end]). start and end are integers such that:
//
//	*  0 <= start < end <= n
//
//	*  start is a multiple of BIT_CEIL(end - start)
//
//	Note that, if start is zero, the second condition is always true.
type r002 struct{}

func (r *r002) ID() string { return "MTC_R002_d02" }

func (r *r002) Description() string {
	return "MTCProof.start must be strictly less than MTCProof.end"
}

func (r *r002) Citation() string {
	return "draft-ietf-plants-merkle-tree-certs-02 §4.1 line 646"
}

func (r *r002) CheckApplies(cert *mtc.Certificate) bool {
	return cert != nil && cert.Proof != nil
}

func (r *r002) Execute(cert *mtc.Certificate) rules.Finding {
	p := cert.Proof
	if p.Start < p.End {
		return rules.Finding{
			RuleID:      r.ID(),
			Severity:    rules.Pass,
			Description: "subtree bounds valid (start < end)",
			Citation:    r.Citation(),
		}
	}
	return rules.Finding{
		RuleID:      r.ID(),
		Severity:    rules.Error,
		Description: r.Description(),
		Citation:    r.Citation(),
		Evidence:    fmt.Sprintf("start=%d end=%d", p.Start, p.End),
	}
}

func init() {
	rules.DefaultRegistry.Register(&r002{})
}
