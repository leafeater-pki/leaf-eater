// Package rules defines the core linting types: Severity, Finding, Rule,
// Registry, and Runner. Pattern mirrored from certlint_go/internal/rules,
// with the target type swapped from *x509.Certificate to *mtc.Certificate.
package rules

import "github.com/leafeater-pki/leaf-eater/internal/mtc"

// Severity mirrors zlint's LintStatus ordering.
type Severity int

const (
	NA     Severity = iota // rule does not apply to this certificate
	NE                     // not evaluated (check produced an error)
	Pass                   // certificate passes this rule
	Notice                 // informational finding
	Warn                   // warning finding
	Error                  // error finding
	Fatal                  // fatal finding
)

// String returns the human-readable name of the severity.
func (s Severity) String() string {
	switch s {
	case NA:
		return "NA"
	case NE:
		return "NE"
	case Pass:
		return "pass"
	case Notice:
		return "notice"
	case Warn:
		return "warn"
	case Error:
		return "error"
	case Fatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// Finding is the result of a single rule execution against an MTC certificate.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Citation    string   `json:"citation,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
}

// Rule is the interface all MTC lint rules implement.
type Rule interface {
	// ID returns the rule identifier (e.g. "MTC_R001_d02").
	ID() string
	// Description returns a human-readable description of what the rule checks.
	Description() string
	// Citation returns the normative reference for the rule
	// (e.g. "draft-ietf-plants-merkle-tree-certs-02 §6.1").
	Citation() string
	// CheckApplies returns true if this rule applies to the given certificate.
	// Rules that don't apply return NA without calling Execute.
	CheckApplies(cert *mtc.Certificate) bool
	// Execute runs the check and returns the finding.
	Execute(cert *mtc.Certificate) Finding
}
