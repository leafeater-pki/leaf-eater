package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/leafeater-pki/leaf-eater/internal/rules/core"
)

func TestRun_ValidMTCFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "valid", "mtc_minimal.pem")
	var stdout, stderr bytes.Buffer
	code := runWith([]string{path}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (Notice finding)\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "MTC_R001_d02") || !strings.Contains(out, "notice") {
		t.Errorf("expected R001 Notice in output; got %q", out)
	}
}

// Phase 1B: R001 CheckApplies returns false on non-MTC certs by default
// (parent spec §8), so this case is now NA across the board (exit 0). The
// -strict companion below exercises the flipped semantics.
func TestRun_NonMTCFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "invalid", "ed25519_cert.pem")
	var stdout, stderr bytes.Buffer
	code := runWith([]string{path}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (default mode: R001 NA on non-MTC)\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
}

// Strict mode: R001 fires Error on non-MTC certs. Companion to the default
// test; guards the plumbing from -strict through core.SetStrictR001 to R001's
// CheckApplies.
func TestRun_NonMTCFixture_Strict(t *testing.T) {
	// Belt-and-suspenders: reset at the end in case run() leaves the package
	// state dirty (it shouldn't, but we own the state here).
	defer core.SetStrictR001(false)

	path := filepath.Join("..", "..", "testdata", "invalid", "ed25519_cert.pem")
	var stdout, stderr bytes.Buffer
	code := runWith([]string{"-strict", path}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (strict mode: R001 Error on non-MTC)\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "MTC_R001_d02") || !strings.Contains(out, "error") {
		t.Errorf("expected R001 Error in output; got %q", out)
	}
}

func TestRun_TooManyArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWith([]string{"a.pem", "b.pem"}, &stdout, &stderr)
	if code != 3 {
		t.Errorf("exit code = %d, want 3 (usage error)", code)
	}
}

func TestRun_VersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWith([]string{"-version"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "leaf-eater v0.1.0-d02") {
		t.Errorf("expected version string in stdout; got %q", stdout.String())
	}
}

// runWith invokes run() with a canned arg list and empty stdin, capturing
// stdout and stderr. Keeps flag parsing isolated per call.
func runWith(args []string, stdout, stderr *bytes.Buffer) int {
	return run(args, bytes.NewReader(nil), stdout, stderr)
}
