package rules

import (
	"fmt"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
)

// Registry holds all registered lint rules.
type Registry struct {
	rules []Rule
}

// DefaultRegistry is the global registry that rules register into via init().
var DefaultRegistry Registry

// Register adds a rule to the registry.
func (r *Registry) Register(rule Rule) {
	r.rules = append(r.rules, rule)
}

// Rules returns the registered rules slice. Callers must not append to the
// returned slice.
func (r *Registry) Rules() []Rule {
	return r.rules
}

// Run executes all registered rules against an MTC certificate.
// For rules that do not apply, a Finding with Severity NA is recorded.
// If a rule panics, a Fatal finding is recorded and execution continues with
// the next rule.
func (r *Registry) Run(cert *mtc.Certificate) []Finding {
	findings := make([]Finding, 0, len(r.rules))
	for _, rule := range r.rules {
		if !rule.CheckApplies(cert) {
			findings = append(findings, Finding{
				RuleID:      rule.ID(),
				Severity:    NA,
				Description: rule.Description(),
				Citation:    rule.Citation(),
			})
			continue
		}
		findings = append(findings, safeExecute(rule, cert))
	}
	return findings
}

// safeExecute calls rule.Execute and recovers from any panic, converting it to
// a Fatal finding so that one broken rule does not crash the entire linter.
func safeExecute(rule Rule, cert *mtc.Certificate) (f Finding) {
	defer func() {
		if r := recover(); r != nil {
			f = Finding{
				RuleID:      rule.ID(),
				Severity:    Fatal,
				Description: "rule panicked during execution",
				Citation:    rule.Citation(),
				Evidence:    fmt.Sprintf("panic: %v", r),
			}
		}
	}()
	return rule.Execute(cert)
}

// CertResult groups an MTC certificate with its findings.
type CertResult struct {
	// Source is the file path or identifier the cert was loaded from.
	Source string
	// Cert is the parsed certificate.
	Cert *mtc.Certificate
	// Findings is the ordered list of rule findings.
	Findings []Finding
}

// LoadedCert pairs a parsed MTC certificate with its source path.
type LoadedCert struct {
	Source string
	Cert   *mtc.Certificate
}

// RunAll runs all registered rules in reg against each cert, returning one
// CertResult per cert.
func RunAll(reg *Registry, certs []*LoadedCert) []CertResult {
	results := make([]CertResult, 0, len(certs))
	for _, lc := range certs {
		findings := reg.Run(lc.Cert)
		results = append(results, CertResult{
			Source:   lc.Source,
			Cert:     lc.Cert,
			Findings: findings,
		})
	}
	return results
}
