package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

func TestRender_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(nil, &buf, "test.pem", rules.Notice, false); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

func TestRender_MultipleFindings(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "MTC_R001_d02", Severity: rules.Notice, Description: "d1", Citation: "c1"},
		{RuleID: "MTC_R002_d02", Severity: rules.Error, Description: "d2", Citation: "c2"},
	}
	var buf bytes.Buffer
	if err := Render(findings, &buf, "test.pem", rules.Notice, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "MTC_R001_d02") || !strings.Contains(out, "MTC_R002_d02") {
		t.Errorf("missing rule IDs in %q", out)
	}
	if !strings.Contains(out, "notice") || !strings.Contains(out, "error") {
		t.Errorf("missing severities in %q", out)
	}
}

func TestRender_QuietSuppressesNAAndPass(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "MTC_R001_d02", Severity: rules.NA, Description: "d1"},
		{RuleID: "MTC_R002_d02", Severity: rules.Pass, Description: "d2"},
		{RuleID: "MTC_R003_d02", Severity: rules.Error, Description: "d3"},
	}
	var buf bytes.Buffer
	if err := Render(findings, &buf, "test.pem", rules.NA, true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "MTC_R001_d02") || strings.Contains(out, "MTC_R002_d02") {
		t.Errorf("quiet mode should suppress NA and Pass; got %q", out)
	}
	if !strings.Contains(out, "MTC_R003_d02") {
		t.Errorf("quiet mode should keep Error findings; got %q", out)
	}
}

func TestRender_SeverityFilter(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "MTC_R001_d02", Severity: rules.Notice, Description: "d1"},
		{RuleID: "MTC_R002_d02", Severity: rules.Error, Description: "d2"},
	}
	var buf bytes.Buffer
	if err := Render(findings, &buf, "test.pem", rules.Error, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "MTC_R001_d02") {
		t.Errorf("Notice should be filtered out when minSeverity=Error; got %q", out)
	}
	if !strings.Contains(out, "MTC_R002_d02") {
		t.Errorf("Error should not be filtered; got %q", out)
	}
}
