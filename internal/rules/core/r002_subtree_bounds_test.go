package core

import (
	"testing"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

func TestR002_SubtreeBounds_Pass(t *testing.T) {
	rule := &r002{}
	cert := &mtc.Certificate{Proof: &mtc.MTCProof{Start: 0, End: 1}}
	if !rule.CheckApplies(cert) {
		t.Fatal("CheckApplies should be true when Proof is set")
	}
	f := rule.Execute(cert)
	if f.Severity != rules.Pass {
		t.Errorf("want Pass, got %v: %s", f.Severity, f.Description)
	}
}

func TestR002_SubtreeBounds_FailEqual(t *testing.T) {
	rule := &r002{}
	cert := &mtc.Certificate{Proof: &mtc.MTCProof{Start: 5, End: 5}}
	f := rule.Execute(cert)
	if f.Severity != rules.Error {
		t.Errorf("want Error, got %v", f.Severity)
	}
	if f.Evidence == "" {
		t.Error("Evidence should contain start/end values")
	}
}

func TestR002_SubtreeBounds_FailReversed(t *testing.T) {
	rule := &r002{}
	cert := &mtc.Certificate{Proof: &mtc.MTCProof{Start: 10, End: 5}}
	f := rule.Execute(cert)
	if f.Severity != rules.Error {
		t.Errorf("want Error, got %v", f.Severity)
	}
	if f.Evidence == "" {
		t.Error("Evidence should contain start/end values")
	}
}

func TestR002_SubtreeBounds_NA_NonMTC(t *testing.T) {
	rule := &r002{}
	cert := &mtc.Certificate{Proof: nil}
	if rule.CheckApplies(cert) {
		t.Error("CheckApplies should be false when Proof is nil")
	}
}

func TestR002_SubtreeBounds_NA_NilCert(t *testing.T) {
	rule := &r002{}
	if rule.CheckApplies(nil) {
		t.Error("CheckApplies should be false when cert is nil")
	}
}
