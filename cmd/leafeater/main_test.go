package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_ValidMTCFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "valid", "mtc_minimal.pem")
	var stdout, stderr bytes.Buffer
	code := runWith([]string{"leafeater", path}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (Notice finding)\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "MTC_R001_d02") || !strings.Contains(out, "notice") {
		t.Errorf("expected R001 Notice in output; got %q", out)
	}
}

// This assertion is expected to FLIP in Phase 1B: once R001.CheckApplies
// returns false on non-MTC certs by default, this case will become NA (exit 0)
// and the Error case will require the -strict flag. Update together.
// Expected to flip in Phase 1B when R001's CheckApplies returns false on
// non-MTC certs (parent spec §8) — this test will need to update to expect
// NA + exit 0 at that time.
func TestRun_InvalidRSAFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "invalid", "rsa_cert.pem")
	var stdout, stderr bytes.Buffer
	code := runWith([]string{"leafeater", path}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (Error finding)\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "MTC_R001_d02") || !strings.Contains(out, "error") {
		t.Errorf("expected R001 Error in output; got %q", out)
	}
}

func TestRun_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWith([]string{"leafeater"}, &stdout, &stderr)
	if code != 3 {
		t.Errorf("exit code = %d, want 3 (usage error)", code)
	}
}

// runWith invokes run() with stdout/stderr captured. Helper used by the
// integration tests above; keeps flag.CommandLine isolated per call.
func runWith(args []string, stdout, stderr *bytes.Buffer) int {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = args
	return run(stdout, stderr)
}
