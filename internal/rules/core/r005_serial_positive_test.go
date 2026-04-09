package core

import (
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/rules"
)

func TestR005_SerialPositive_Pass(t *testing.T) {
	rule := &r005{}
	cert := &mtc.Certificate{
		X509: &x509.Certificate{SerialNumber: big.NewInt(1)},
	}
	f := rule.Execute(cert)
	if f.Severity != rules.Pass {
		t.Errorf("want Pass, got %v: %s", f.Severity, f.Description)
	}
}

func TestR005_SerialPositive_FailZero(t *testing.T) {
	rule := &r005{}
	cert := &mtc.Certificate{
		X509: &x509.Certificate{SerialNumber: big.NewInt(0)},
	}
	f := rule.Execute(cert)
	if f.Severity != rules.Error {
		t.Errorf("want Error, got %v", f.Severity)
	}
	if f.Evidence == "" {
		t.Error("Evidence should be populated on failure")
	}
}

func TestR005_SerialPositive_FailNegative(t *testing.T) {
	rule := &r005{}
	cert := &mtc.Certificate{
		X509: &x509.Certificate{SerialNumber: big.NewInt(-7)},
	}
	f := rule.Execute(cert)
	if f.Severity != rules.Error {
		t.Errorf("want Error, got %v", f.Severity)
	}
}

func TestR005_SerialPositive_NA_NoX509(t *testing.T) {
	rule := &r005{}
	cert := &mtc.Certificate{X509: nil}
	if rule.CheckApplies(cert) {
		t.Error("CheckApplies should be false when X509 is nil")
	}
}

func TestR005_SerialPositive_NA_NilCert(t *testing.T) {
	rule := &r005{}
	if rule.CheckApplies(nil) {
		t.Error("CheckApplies should be false when cert is nil")
	}
}

func TestR005_SerialPositive_NA_NilSerialNumber(t *testing.T) {
	rule := &r005{}
	cert := &mtc.Certificate{X509: &x509.Certificate{SerialNumber: nil}}
	if rule.CheckApplies(cert) {
		t.Error("CheckApplies should be false when SerialNumber is nil")
	}
}

func TestR005_SerialPositive_AppliesToNonMTC(t *testing.T) {
	// R005 is universal; applies even when MTCProof is nil
	rule := &r005{}
	cert := &mtc.Certificate{
		X509:  &x509.Certificate{SerialNumber: big.NewInt(42)},
		Proof: nil,
	}
	if !rule.CheckApplies(cert) {
		t.Error("R005 should apply to non-MTC certs too")
	}
}
