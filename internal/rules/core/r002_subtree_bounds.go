// Package core implements the built-in rule set for leaf-eater.
//
// R002 (Subtree bounds): MTCProof.start MUST be strictly less than
// MTCProof.end.
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
package core

import (
	"fmt"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

// R002SubtreeBounds enforces the strict inequality start < end on MTCProof.
type R002SubtreeBounds struct{}

func (R002SubtreeBounds) ID() string { return "MTC_R002_d02" }

func (R002SubtreeBounds) Description() string {
	return "MTCProof.start must be strictly less than MTCProof.end"
}

func (R002SubtreeBounds) Citation() string {
	return "draft-ietf-plants-merkle-tree-certs-02 §4.1 line 646"
}

func (R002SubtreeBounds) CheckApplies(cert *mtc.Certificate) bool {
	return cert != nil && cert.Proof != nil
}

func (R002SubtreeBounds) Execute(cert *mtc.Certificate) rules.Finding {
	p := cert.Proof
	if p.Start < p.End {
		return rules.Finding{
			RuleID:      "MTC_R002_d02",
			Severity:    rules.Pass,
			Description: "subtree bounds valid (start < end)",
			Citation:    "draft-ietf-plants-merkle-tree-certs-02 §4.1 line 646",
		}
	}
	return rules.Finding{
		RuleID:      "MTC_R002_d02",
		Severity:    rules.Error,
		Description: "MTCProof.start must be strictly less than MTCProof.end",
		Citation:    "draft-ietf-plants-merkle-tree-certs-02 §4.1 line 646",
		Evidence:    fmt.Sprintf("start=%d end=%d", p.Start, p.End),
	}
}

func init() {
	rules.DefaultRegistry.Register(R002SubtreeBounds{})
}
