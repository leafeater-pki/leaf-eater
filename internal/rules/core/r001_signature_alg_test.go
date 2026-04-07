package core

import (
	"encoding/asn1"
	"testing"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

func TestR001_MTCOIDIsNotice(t *testing.T) {
	r := &r001{}
	cert := &mtc.Certificate{RawSigOID: mtc.MTCProofOID}
	f := r.Execute(cert)
	if f.Severity != rules.Notice {
		t.Errorf("severity = %v, want Notice", f.Severity)
	}
	if f.RuleID != "MTC_R001_d02" {
		t.Errorf("rule id = %q", f.RuleID)
	}
}

func TestR001_RSAOIDIsError(t *testing.T) {
	r := &r001{}
	cert := &mtc.Certificate{RawSigOID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}}
	f := r.Execute(cert)
	if f.Severity != rules.Error {
		t.Errorf("severity = %v, want Error", f.Severity)
	}
	if f.Evidence == "" {
		t.Error("evidence should include the actual OID")
	}
}

func TestR001_AlwaysApplies(t *testing.T) {
	r := &r001{}
	if !r.CheckApplies(&mtc.Certificate{}) {
		t.Error("CheckApplies should always return true in Phase 1A")
	}
}
