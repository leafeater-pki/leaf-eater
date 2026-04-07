package rules

import (
	"strings"
	"testing"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
)

// fakeRule is a test-only Rule implementation with configurable behavior.
type fakeRule struct {
	id       string
	applies  bool
	finding  Finding
	panicMsg string
}

func (f *fakeRule) ID() string          { return f.id }
func (f *fakeRule) Description() string { return "fake rule for tests: " + f.id }
func (f *fakeRule) Citation() string    { return "test://" + f.id }

func (f *fakeRule) CheckApplies(_ *mtc.Certificate) bool {
	return f.applies
}

func (f *fakeRule) Execute(_ *mtc.Certificate) Finding {
	if f.panicMsg != "" {
		panic(f.panicMsg)
	}
	return f.finding
}

// testCert is a minimal *mtc.Certificate for use in engine tests. The engine
// doesn't inspect fields; it just hands the pointer to each rule.
func testCert() *mtc.Certificate {
	return &mtc.Certificate{}
}

func TestRegistry_Run_PassingRule(t *testing.T) {
	reg := &Registry{}
	reg.Register(&fakeRule{
		id:      "FAKE_001",
		applies: true,
		finding: Finding{RuleID: "FAKE_001", Severity: Pass, Description: "ok"},
	})

	findings := reg.Run(testCert())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != Pass {
		t.Errorf("expected Pass, got %v", findings[0].Severity)
	}
	if findings[0].RuleID != "FAKE_001" {
		t.Errorf("expected rule id FAKE_001, got %q", findings[0].RuleID)
	}
}

func TestRegistry_Run_NotApplicable(t *testing.T) {
	reg := &Registry{}
	reg.Register(&fakeRule{
		id:      "FAKE_002",
		applies: false,
	})

	findings := reg.Run(testCert())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != NA {
		t.Errorf("expected NA, got %v", findings[0].Severity)
	}
	if findings[0].RuleID != "FAKE_002" {
		t.Errorf("expected rule id FAKE_002, got %q", findings[0].RuleID)
	}
}

func TestRegistry_Run_PanicBecomesFatal(t *testing.T) {
	reg := &Registry{}
	reg.Register(&fakeRule{
		id:       "FAKE_003",
		applies:  true,
		panicMsg: "boom",
	})

	findings := reg.Run(testCert())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != Fatal {
		t.Errorf("expected Fatal, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence, "boom") {
		t.Errorf("expected evidence to contain panic value 'boom', got %q", findings[0].Evidence)
	}
}

func TestRegistry_Run_ContinuesAfterPanic(t *testing.T) {
	reg := &Registry{}
	reg.Register(&fakeRule{id: "FAKE_A", applies: true, panicMsg: "kaboom"})
	reg.Register(&fakeRule{
		id:      "FAKE_B",
		applies: true,
		finding: Finding{RuleID: "FAKE_B", Severity: Pass, Description: "ok"},
	})

	findings := reg.Run(testCert())
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Severity != Fatal {
		t.Errorf("expected first finding Fatal, got %v", findings[0].Severity)
	}
	if findings[1].Severity != Pass {
		t.Errorf("expected second finding Pass, got %v", findings[1].Severity)
	}
}
