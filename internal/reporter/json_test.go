package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

func TestJSONRender_SingleFinding(t *testing.T) {
	var buf bytes.Buffer
	findings := []rules.Finding{
		{
			RuleID:      "MTC_R002_d02",
			Severity:    rules.Error,
			Description: "bounds violation",
			Citation:    "draft §4.1 line 646",
			Evidence:    "start=5 end=5",
		},
	}
	if err := RenderJSON(findings, &buf, "test.pem", rules.NA, false); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	if out[0]["rule_id"] != "MTC_R002_d02" {
		t.Errorf("rule_id mismatch: %v", out[0]["rule_id"])
	}
	if out[0]["severity"] != "Error" {
		t.Errorf("severity should be string 'Error', got %v", out[0]["severity"])
	}
	if out[0]["source"] != "test.pem" {
		t.Errorf("source mismatch: %v", out[0]["source"])
	}
}

func TestJSONRender_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(nil, &buf, "x.pem", rules.NA, false); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("want empty array, got %q", buf.String())
	}
}

func TestJSONRender_QuietSuppressesNA(t *testing.T) {
	var buf bytes.Buffer
	findings := []rules.Finding{
		{RuleID: "R001", Severity: rules.NA, Description: "skipped"},
		{RuleID: "R002", Severity: rules.Error, Description: "bad"},
	}
	if err := RenderJSON(findings, &buf, "x.pem", rules.NA, true); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0]["rule_id"] != "R002" {
		t.Errorf("quiet did not suppress NA: %v", out)
	}
}

func TestJSONRender_MinSeverityFilter(t *testing.T) {
	var buf bytes.Buffer
	findings := []rules.Finding{
		{RuleID: "R001", Severity: rules.Notice, Description: "info"},
		{RuleID: "R002", Severity: rules.Error, Description: "bad"},
	}
	if err := RenderJSON(findings, &buf, "x.pem", rules.Error, false); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0]["rule_id"] != "R002" {
		t.Errorf("minSeverity filter failed: %v", out)
	}
}

func TestJSONStreamer_MultipleSources(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONStreamer(&buf, rules.NA, false)
	_ = s.Write([]rules.Finding{{RuleID: "R001", Severity: rules.Pass, Description: "ok"}}, "a.pem")
	_ = s.Write([]rules.Finding{{RuleID: "R002", Severity: rules.Error, Description: "bad"}}, "b.pem")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(out) != 2 {
		t.Fatalf("want 2 findings from 2 sources, got %d", len(out))
	}
	if out[0]["source"] != "a.pem" || out[1]["source"] != "b.pem" {
		t.Errorf("source tagging wrong: %v", out)
	}
}
