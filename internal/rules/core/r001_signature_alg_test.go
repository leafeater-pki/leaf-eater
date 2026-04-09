package core

import (
	"crypto/x509"
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

func TestR001_NonMTC_Default_NA(t *testing.T) {
	SetStrictR001(false)
	rule := &r001{}
	cert := &mtc.Certificate{X509: &x509.Certificate{}, Proof: nil}
	if rule.CheckApplies(cert) {
		t.Error("default should NA on non-MTC")
	}
}

func TestR001_NonMTC_Strict_Applies(t *testing.T) {
	SetStrictR001(true)
	defer SetStrictR001(false)
	rule := &r001{}
	cert := &mtc.Certificate{X509: &x509.Certificate{}, Proof: nil}
	if !rule.CheckApplies(cert) {
		t.Error("strict should apply R001 on non-MTC")
	}
}

func TestR001_NilCert_NA(t *testing.T) {
	SetStrictR001(false)
	rule := &r001{}
	if rule.CheckApplies(nil) {
		t.Error("CheckApplies should be false when cert is nil")
	}
}
