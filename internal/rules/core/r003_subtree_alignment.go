package core

import (
	"fmt"
	"math/bits"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

// r003 enforces that MTCProof.start is a multiple of BIT_CEIL(end - start).
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
type r003 struct{}

func (r *r003) ID() string { return "MTC_R003_d02" }

func (r *r003) Description() string {
	return "MTCProof.start must be a multiple of BIT_CEIL(end - start)"
}

func (r *r003) Citation() string {
	return "draft-ietf-plants-merkle-tree-certs-02 §4.1 line 648"
}

func (r *r003) CheckApplies(cert *mtc.Certificate) bool {
	return cert != nil && cert.Proof != nil && cert.Proof.Start < cert.Proof.End
}

func (r *r003) Execute(cert *mtc.Certificate) rules.Finding {
	p := cert.Proof
	if p.Start == 0 {
		// Vacuous pass per §4.1 line 650. This branch cites line 650 rather
		// than the rule's canonical line 648 citation, so the citation string
		// is hardcoded instead of calling r.Citation().
		return rules.Finding{
			RuleID:      r.ID(),
			Severity:    rules.Pass,
			Description: "vacuous pass: start == 0 per §4.1 line 650",
			Citation:    "draft-ietf-plants-merkle-tree-certs-02 §4.1 line 650",
		}
	}
	width := p.End - p.Start
	bc := bitCeil(width)
	if p.Start%bc == 0 {
		return rules.Finding{
			RuleID:      r.ID(),
			Severity:    rules.Pass,
			Description: "subtree alignment valid (start is a multiple of BIT_CEIL(width))",
			Citation:    r.Citation(),
		}
	}
	return rules.Finding{
		RuleID:      r.ID(),
		Severity:    rules.Error,
		Description: r.Description(),
		Citation:    r.Citation(),
		Evidence:    fmt.Sprintf("start=%d width=%d bit_ceil=%d (start %% bit_ceil = %d)", p.Start, width, bc, p.Start%bc),
	}
}

// bitCeil returns the smallest power of 2 that is >= w. Defined for w >= 1;
// returns 1 when w <= 1 (R002 catches w == 0 before R003 runs).
func bitCeil(w uint64) uint64 {
	if w <= 1 {
		return 1
	}
	return 1 << uint(bits.Len64(w-1))
}

func init() {
	rules.DefaultRegistry.Register(&r003{})
}
