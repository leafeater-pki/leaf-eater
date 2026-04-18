package mtc

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestParseError_ErrorString_WithCause(t *testing.T) {
	pe := &ParseError{Field: "X", Offset: 5, Cause: errors.New("boom")}
	got := pe.Error()
	if !strings.Contains(got, "X") {
		t.Errorf("Error() = %q, want it to contain field name %q", got, "X")
	}
	if !strings.Contains(got, "5") {
		t.Errorf("Error() = %q, want it to contain offset %q", got, "5")
	}
	if !strings.Contains(got, "boom") {
		t.Errorf("Error() = %q, want it to contain cause %q", got, "boom")
	}
}

func TestParseError_ErrorString_NoCause(t *testing.T) {
	pe := &ParseError{Field: "Y", Offset: 7}
	got := pe.Error()
	if !strings.Contains(got, "Y") {
		t.Errorf("Error() = %q, want it to contain field name %q", got, "Y")
	}
	if !strings.Contains(got, "7") {
		t.Errorf("Error() = %q, want it to contain offset %q", got, "7")
	}
	// The no-cause branch in errors.go ends with the closing parenthesis on the
	// "(offset N)" segment; it must not have a trailing ": <cause>" suffix.
	if strings.HasSuffix(got, ":") || strings.Contains(got, "): ") {
		t.Errorf("Error() = %q, should not contain a trailing cause separator", got)
	}
}

func TestParseError_Unwrap(t *testing.T) {
	pe := &ParseError{Field: "Z", Offset: 0, Cause: io.EOF}
	if !errors.Is(pe, io.EOF) {
		t.Errorf("errors.Is(pe, io.EOF) = false, want true")
	}
}

func TestPemError_ErrorString(t *testing.T) {
	e := &pemError{"bar"}
	if got := e.Error(); got != "bar" {
		t.Errorf("Error() = %q, want %q", got, "bar")
	}
}

func TestErrMalformed_ErrorString(t *testing.T) {
	e := errMalformed("foo")
	if got := e.Error(); got != "malformed: foo" {
		t.Errorf("Error() = %q, want %q", got, "malformed: foo")
	}
}
