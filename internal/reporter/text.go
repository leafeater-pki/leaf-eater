// Package reporter renders rule findings to human- and machine-readable
// output formats. Phase 1A ships the text reporter only; JSON lands in
// Phase 1B.
package reporter

import (
	"fmt"
	"io"

	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

// Render writes findings in text format to w. Format per Phase 1A spec §4:
//
//	<source>: <severity> [<rule_id>] <description> (<citation>)
//
// Findings below minSeverity are suppressed. If quiet is true, NA and
// Pass findings are suppressed regardless of minSeverity.
func Render(findings []rules.Finding, w io.Writer, source string, minSeverity rules.Severity, quiet bool) error {
	for _, f := range findings {
		if quiet && (f.Severity == rules.NA || f.Severity == rules.Pass) {
			continue
		}
		if f.Severity < minSeverity {
			continue
		}
		line := fmt.Sprintf("%s: %s [%s] %s", source, f.Severity, f.RuleID, f.Description)
		if f.Citation != "" {
			line += fmt.Sprintf(" (%s)", f.Citation)
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
