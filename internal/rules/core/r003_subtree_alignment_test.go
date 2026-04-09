package core

import (
	"testing"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

func TestR003_Alignment_VacuousStartZero(t *testing.T) {
	// Line 650: "if start is zero, the second condition is always true."
	rule := &r003{}
	cert := &mtc.Certificate{Proof: &mtc.MTCProof{Start: 0, End: 7}}
	f := rule.Execute(cert)
	if f.Severity != rules.Pass {
		t.Errorf("want Pass for start=0, got %v", f.Severity)
	}
}

func TestR003_Alignment_WidthOne(t *testing.T) {
	// BIT_CEIL(1) == 1, so any start is a multiple of 1
	rule := &r003{}
	cert := &mtc.Certificate{Proof: &mtc.MTCProof{Start: 13, End: 14}}
	f := rule.Execute(cert)
	if f.Severity != rules.Pass {
		t.Errorf("want Pass for width=1, got %v", f.Severity)
	}
}

func TestR003_Alignment_Pass_Width4(t *testing.T) {
	// BIT_CEIL(4) == 4; start 8 is a multiple of 4
	rule := &r003{}
	cert := &mtc.Certificate{Proof: &mtc.MTCProof{Start: 8, End: 12}}
	f := rule.Execute(cert)
	if f.Severity != rules.Pass {
		t.Errorf("want Pass, got %v", f.Severity)
	}
}

func TestR003_Alignment_Fail_Width3(t *testing.T) {
	// BIT_CEIL(3) == 4; start 2 is NOT a multiple of 4
	rule := &r003{}
	cert := &mtc.Certificate{Proof: &mtc.MTCProof{Start: 2, End: 5}}
	f := rule.Execute(cert)
	if f.Severity != rules.Error {
		t.Errorf("want Error, got %v", f.Severity)
	}
	if f.Evidence == "" {
		t.Error("Evidence should be populated on failure")
	}
}

func TestR003_Alignment_NA_NonMTC(t *testing.T) {
	rule := &r003{}
	cert := &mtc.Certificate{Proof: nil}
	if rule.CheckApplies(cert) {
		t.Error("CheckApplies should be false when Proof is nil")
	}
}

func TestR003_Alignment_NA_NilCert(t *testing.T) {
	rule := &r003{}
	if rule.CheckApplies(nil) {
		t.Error("CheckApplies should be false when cert is nil")
	}
}

func TestR003_Alignment_NA_StartGEEnd(t *testing.T) {
	// When R002 would fail, R003 is undefined, so NA
	rule := &r003{}
	cert := &mtc.Certificate{Proof: &mtc.MTCProof{Start: 5, End: 5}}
	if rule.CheckApplies(cert) {
		t.Error("CheckApplies should be false when start >= end (R002 territory)")
	}
}
