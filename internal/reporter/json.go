package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

// jsonFinding is the on-wire shape of a finding in JSON output. Severity is
// encoded as a string for readability; Citation and Evidence are optional.
type jsonFinding struct {
	Source      string `json:"source"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Citation    string `json:"citation,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

// severityString maps the Severity enum to its canonical JSON string form.
// Note: this differs from Severity.String(), which lowercases most values for
// text output. The JSON reporter uses title-case names for machine readers.
func severityString(s rules.Severity) string {
	switch s {
	case rules.NA:
		return "NA"
	case rules.NE:
		return "NE"
	case rules.Pass:
		return "Pass"
	case rules.Notice:
		return "Notice"
	case rules.Warn:
		return "Warn"
	case rules.Error:
		return "Error"
	case rules.Fatal:
		return "Fatal"
	default:
		return "Unknown"
	}
}

// shouldEmit applies the quiet and minSeverity filters. Returns true if the
// finding should be emitted.
func shouldEmit(f rules.Finding, minSeverity rules.Severity, quiet bool) bool {
	if quiet && (f.Severity == rules.NA || f.Severity == rules.Pass) {
		return false
	}
	if f.Severity < minSeverity {
		return false
	}
	return true
}

// toJSONFinding converts a rules.Finding into the wire shape, tagged with the
// given source.
func toJSONFinding(f rules.Finding, source string) jsonFinding {
	return jsonFinding{
		Source:      source,
		RuleID:      f.RuleID,
		Severity:    severityString(f.Severity),
		Description: f.Description,
		Citation:    f.Citation,
		Evidence:    f.Evidence,
	}
}

// RenderJSON writes findings as a JSON array to w. Filtering semantics match
// the text reporter: quiet suppresses NA and Pass; findings below minSeverity
// are dropped. Always emits valid JSON, including "[]" when no findings pass
// the filters.
func RenderJSON(findings []rules.Finding, w io.Writer, source string, minSeverity rules.Severity, quiet bool) error {
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	first := true
	for _, f := range findings {
		if !shouldEmit(f, minSeverity, quiet) {
			continue
		}
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		b, err := json.Marshal(toJSONFinding(f, source))
		if err != nil {
			return fmt.Errorf("marshal finding %s: %w", f.RuleID, err)
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		first = false
	}
	if _, err := io.WriteString(w, "]"); err != nil {
		return err
	}
	return nil
}

// JSONStreamer emits a single JSON array incrementally across multiple Write
// calls, one per source. Use this for directory walks where accumulating all
// findings in memory is not feasible.
type JSONStreamer struct {
	w           io.Writer
	minSeverity rules.Severity
	quiet       bool
	started     bool
	closed      bool
	first       bool
}

// NewJSONStreamer constructs a streamer that writes to w. Filtering semantics
// match RenderJSON.
func NewJSONStreamer(w io.Writer, minSeverity rules.Severity, quiet bool) *JSONStreamer {
	return &JSONStreamer{
		w:           w,
		minSeverity: minSeverity,
		quiet:       quiet,
		first:       true,
	}
}

// Write emits the filtered findings for one source. Safe to call repeatedly;
// the array framing is managed by the streamer.
func (s *JSONStreamer) Write(findings []rules.Finding, source string) error {
	if s.closed {
		return fmt.Errorf("JSONStreamer: Write after Close")
	}
	for _, f := range findings {
		if !shouldEmit(f, s.minSeverity, s.quiet) {
			continue
		}
		if !s.started {
			if _, err := io.WriteString(s.w, "["); err != nil {
				return err
			}
			s.started = true
		}
		if !s.first {
			if _, err := io.WriteString(s.w, ","); err != nil {
				return err
			}
		}
		b, err := json.Marshal(toJSONFinding(f, source))
		if err != nil {
			return fmt.Errorf("marshal finding %s: %w", f.RuleID, err)
		}
		if _, err := s.w.Write(b); err != nil {
			return err
		}
		s.first = false
	}
	return nil
}

// Close finalizes the JSON array. If no findings were ever written, emits the
// empty array "[]". Idempotent: calling Close more than once is a no-op.
func (s *JSONStreamer) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if !s.started {
		if _, err := io.WriteString(s.w, "[]"); err != nil {
			return err
		}
		return nil
	}
	if _, err := io.WriteString(s.w, "]"); err != nil {
		return err
	}
	return nil
}
